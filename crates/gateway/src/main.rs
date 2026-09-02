use std::path::PathBuf;

use clap::Parser;
use gateway::Gateway;
use time::UtcOffset;
use tracing_subscriber::fmt::time::OffsetTime;
use tracing_subscriber::EnvFilter;

/// 命令行仅保留：指定配置文件路径。
#[derive(Parser)]
#[command(
    version,
    about = "cloud-gateway: 家庭 LLM 远程访问网关（公网入口 + QUIC 隧道服务端）"
)]
struct Args {
    /// 配置文件路径（YAML），所有参数都在其中配置
    #[arg(long, default_value = "gateway-config.yml")]
    config: PathBuf,
}

/// 启动网关主循环（独立函数，便于单元测试覆盖启动路径）。
async fn run(args: Args) -> anyhow::Result<()> {
    // 日志时间戳固定东八区（UTC+8）：China Standard Time，无夏令时。
    let timer = OffsetTime::new(
        UtcOffset::from_hms(8, 0, 0).expect("UTC+8 is a valid fixed offset"),
        time::format_description::well_known::Rfc3339,
    );
    let _ = tracing_subscriber::fmt()
        .with_timer(timer)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .try_init();

    let cfg = gateway::config::from_path(&args.config)?;

    let gw = Gateway::start(cfg).await?;
    tracing::info!(http = %gw.http_addr, quic = %gw.quic_addr, "Gateway ready");
    shutdown_signal().await;
    tracing::info!("graceful shutdown: stopping gateway");
    gw.shutdown().await;
    Ok(())
}

/// 等待 SIGINT / SIGTERM，收到后干净退出（覆盖 systemd stop / Ctrl+C / job kill）。
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install SIGINT handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => tracing::info!("received SIGINT"),
        _ = terminate => tracing::info!("received SIGTERM"),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run(Args::parse()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, IsCa, KeyPair, SanType};

    /// 在临时目录生成 (ca, server.crt, server.key) 并返回路径。
    fn gen_cert_files(dir: &std::path::Path) -> (PathBuf, PathBuf, PathBuf) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::default();
        ca.distinguished_name.push(DnType::CommonName, "test ca");
        ca.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca_cert = ca.self_signed(&ca_key).unwrap();

        let srv_key = KeyPair::generate().unwrap();
        let mut srv = CertificateParams::default();
        srv.distinguished_name.push(DnType::CommonName, "gw");
        srv.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
        let srv_cert = srv.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();

        let write = |name: &str, content: &str| {
            let p = dir.join(name);
            std::fs::write(&p, content).unwrap();
            p
        };
        (
            write("ca.crt", &ca_cert.pem()),
            write("server.crt", &srv_cert.pem()),
            write("server.key", &srv_key.serialize_pem()),
        )
    }

    #[tokio::test]
    async fn run_starts_gateway() {
        // 写一份完整配置到临时目录，用随机端口启动网关
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let config_path = dir.path().join("config.yml");
        let yaml = format!(
            r#"
listen_addr: "127.0.0.1:0"
quic_addr: "127.0.0.1:0"
cert: {}
key: {}
ca: {}
keys_file: {}
"#,
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            ca.to_str().unwrap(),
            dir.path().join("keys.db").to_str().unwrap(),
        );
        std::fs::write(&config_path, &yaml).unwrap();
        let task = tokio::spawn(run(Args {
            config: config_path,
        }));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(!task.is_finished(), "gateway loop should stay running");
        task.abort();
    }
}
