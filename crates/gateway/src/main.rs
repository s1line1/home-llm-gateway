use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use gateway::Gateway;
use time::UtcOffset;
use tracing_subscriber::fmt::time::OffsetTime;
use tracing_subscriber::EnvFilter;

/// 命令行仅保留：指定配置文件路径。
#[derive(Parser)]
#[command(
    version,
    about = "cloud-gateway: Edge LLM 网关（公网入口 + QUIC 隧道服务端）"
)]
struct Args {
    /// 配置文件路径（YAML），所有参数都在其中配置
    #[arg(long, default_value = "gateway-config.yml")]
    config: PathBuf,
}

fn main() -> anyhow::Result<()> {
    // 手动建 runtime（而不是 `#[tokio::main]`）：退出时要能**有界地**等待阻塞池。
    // `Gateway::shutdown` 的强制落库跑在阻塞池上、有 `shutdown_flush_timeout` 超时；
    // 若它超时，默认的 runtime drop 会**无限**等那个阻塞任务跑完，systemd 到点照样 SIGKILL
    // ——超时就白设了。`shutdown` 已经等过它自己的超时，这里不再等。
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(run(Args::parse()));
    rt.shutdown_timeout(Duration::ZERO);
    result
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
    tracing::info!("shutting down gateway (draining in-flight requests, then flushing usage)");
    // `shutdown` 现在是四阶段：停 accept（在途继续）→ 排空（或在途带明确事件收尾）→
    // 有界强制落库 → abort。落库**排在最后**，所以排空期间结算的用量也在里面；以前这里要记得
    // 先调 flush_usage_on_shutdown —— 现在忘不了。
    gw.shutdown().await;
    Ok(())
}

/// 等待 SIGINT / SIGTERM / SIGHUP，收到后干净退出（覆盖 systemd stop / Ctrl+C / job kill /
/// 终端挂断）。
///
/// SIGHUP 也算**关闭请求**（P3-9）：本网关没有配置热重载（`OPTIMIZATION.md` A4，
/// `deploy/gateway.service` 里也没有 `ExecReload`），保留默认动作只会让 `kill -HUP` 或终端
/// 挂断绕过 `Gateway::shutdown` 直接杀进程——排空与强制落库都不会跑。日志里点名这一点，
/// 免得有人以为 HUP 会重载配置。
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
