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

    let mut agent = Agent::start(cfg)?;
    let abnormal: Option<agent::AgentExit> = tokio::select! {
        _ = shutdown_signal() => None,
        exit = agent.wait_for_abnormal_exit() => exit,
    };
    match abnormal {
        None => {
            tracing::info!("graceful shutdown: stopping agent");
            agent.shutdown().await;
        }
        Some(exit) => {
            // `run` 正常**永不返回**（无限重连循环）：走到这里说明它返回或 panic 了。若继续停在
            // 等信号上，进程就是一个"看起来活着、什么都不做"的僵尸，日志里也什么都没有——比一次
            // 崩溃难查得多。返回 Err ⇒ 退出码 1 ⇒ `deploy/agent.service` 的 `Restart=always`
            // 重新拉起。**退出决定在这里，不在库里**（P3-5）。
            anyhow::bail!(
                "agent run loop ended abnormally ({exit:?}); exiting so the supervisor restarts us"
            );
        }
    }
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

    /// 规格（复扫 F5）：`run` 起来之后**真的去连过云端**，不只是"任务没结束"。
    ///
    /// 单看 `!task.is_finished()` 是不够的：把 `run` 里"启动之后"的部分换成 `pending()`，
    /// 那条断言照样绿。所以这里绑一个 UDP socket 当云端地址——s2n-quic 的 Initial 包会打到
    /// 它上面（不需要有服务端应答），于是"发过包"就是一个不依赖日志、也不依赖服务端的判据。
    #[tokio::test]
    async fn run_starts_agent_loop() {
        let cloud = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cloud_addr = cloud.local_addr().unwrap();

        // 写一份完整配置到临时目录；云端地址指向上面那个 socket（不会有应答）→ 后台重试
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let config_path = dir.path().join("config.yml");
        let yaml = format!(
            r#"
cloud_addr: "{cloud_addr}"
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
        // 第二判据（复扫 F5）：真的发过 QUIC Initial 包（有界等待）
        let mut buf = [0u8; 1500];
        let got =
            tokio::time::timeout(std::time::Duration::from_secs(5), cloud.recv_from(&mut buf))
                .await;
        assert!(
            got.is_ok(),
            "agent 必须真的向 {cloud_addr} 发过包，而不是挂在一个 pending 上（复扫 F5）"
        );
        assert!(!task.is_finished(), "agent loop should stay running");
        task.abort();
    }
}
