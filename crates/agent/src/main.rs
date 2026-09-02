use std::path::PathBuf;

use agent::Agent;
use clap::Parser;
use time::UtcOffset;
use tracing_subscriber::fmt::time::OffsetTime;
use tracing_subscriber::EnvFilter;

/// 命令行仅保留：指定配置文件路径。
#[derive(Parser)]
#[command(
    version,
    about = "home-agent: 常驻 LLM 所在机器，通过 QUIC 隧道接入云端网关"
)]
struct Args {
    /// 配置文件路径（YAML），所有参数都在其中配置
    #[arg(long, default_value = "agent-config.yml")]
    config: PathBuf,
}

/// 启动 agent 主循环（独立函数，便于单元测试覆盖启动路径）。
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

    let cfg = agent::config::from_path(&args.config)?;

    let agent = Agent::start(cfg)?;
    shutdown_signal().await;
    tracing::info!("graceful shutdown: stopping agent");
    agent.shutdown().await;
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

    /// 在临时目录生成 (ca, client.crt, client.key) 并返回路径。
    fn gen_cert_files(dir: &std::path::Path) -> (PathBuf, PathBuf, PathBuf) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::default();
        ca.distinguished_name.push(DnType::CommonName, "test ca");
        ca.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca_cert = ca.self_signed(&ca_key).unwrap();

        let cli_key = KeyPair::generate().unwrap();
        let mut cli = CertificateParams::default();
        cli.distinguished_name.push(DnType::CommonName, "agent");
        cli.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
        let cli_cert = cli.signed_by(&cli_key, &ca_cert, &ca_key).unwrap();

        let write = |name: &str, content: &str| {
            let p = dir.join(name);
            std::fs::write(&p, content).unwrap();
            p
        };
        (
            write("ca.crt", &ca_cert.pem()),
            write("client.crt", &cli_cert.pem()),
            write("client.key", &cli_key.serialize_pem()),
        )
    }

    #[tokio::test]
    async fn run_starts_agent_loop() {
        // 写一份完整配置到临时目录；云端地址不可达 → 后台重试，主循环挂起在 pending
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let config_path = dir.path().join("config.yml");
        let yaml = format!(
            r#"
cloud_addr: "127.0.0.1:1"
ca: {}
cert: {}
key: {}
heartbeat_secs: 1
"#,
            ca.to_str().unwrap(),
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
        );
        std::fs::write(&config_path, &yaml).unwrap();
        let task = tokio::spawn(run(Args {
            config: config_path,
        }));
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!task.is_finished(), "agent loop should stay running");
        task.abort();
    }
}
