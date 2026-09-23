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
    about = "edge-agent: 常驻 LLM 所在机器（edge 节点），通过 QUIC 隧道接入云端网关"
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

/// 等待 SIGINT / SIGTERM / SIGHUP，收到后干净退出（覆盖 systemd stop / Ctrl+C / job kill /
/// 终端挂断）。
///
/// SIGHUP 也算**关闭请求**（P3-9）：agent 没有配置热重载（`deploy/agent.service` 里也没有
/// `ExecReload`），保留默认动作只会让 `kill -HUP` 或终端挂断绕过 `agent.shutdown()` 直接
/// 杀进程。日志里点名这一点，免得有人以为 HUP 会重载配置。
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        // 三个信号流**先**建好、再打日志：`signal()` 就是注册 handler 的那一刻，所以这行
        // 日志可以承诺"从此刻起的 INT/TERM/HUP 都会被接住"。它同时是 e2e 的**确定性**就绪
        // 判据——真进程只能靠日志，而在这之前发 HUP 会按默认动作直接杀掉进程（测试随机红）。
        let mut interrupt =
            signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");
        let mut terminate =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        let mut hangup = signal(SignalKind::hangup()).expect("failed to install SIGHUP handler");
        tracing::info!("shutdown signals armed (SIGINT/SIGTERM/SIGHUP)");
        tokio::select! {
            _ = interrupt.recv() => tracing::info!("received SIGINT"),
            _ = terminate.recv() => tracing::info!("received SIGTERM"),
            _ = hangup.recv() => {
                tracing::info!("received SIGHUP (no config hot-reload; shutting down)")
            }
        }
    }
    #[cfg(not(unix))]
    {
        // 非 unix 上只有 Ctrl+C（Windows）。
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install SIGINT handler");
        tracing::info!("received SIGINT");
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
