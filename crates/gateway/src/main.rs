use std::ffi::OsStr;
use std::io::IsTerminal;
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
    let ansi = ansi_for_logs(
        std::io::stdout().is_terminal(),
        std::env::var_os("NO_COLOR").as_deref(),
    );
    let _ = tracing_subscriber::fmt()
        .with_timer(timer)
        // 显式给值（复扫 A6）：不写这一行时 tracing-subscriber 只看 `NO_COLOR`，不看 TTY。
        .with_ansi(ansi)
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

/// 是否给日志上色（复扫 A6）。
///
/// tracing-subscriber 的默认判据只有两条：编译期 `ansi` feature 与**非空**的 `NO_COLOR`
/// ——**不看 stdout 是不是终端**（vendored `fmt/fmt_layer.rs`：`cfg!(feature = "ansi") &&
/// env::var("NO_COLOR").map_or(true, |v| v.is_empty())`）。于是 `StandardOutput=append:` 的
/// systemd 单元、`> log` 重定向、没设 `NO_COLOR` 的容器，都会把 `ESC[2m`/`ESC[32m` 一路写进
/// 日志文件——`docker-compose.yml` 那条路径是靠 `NO_COLOR=1` 兜住的，systemd 单元漏了
/// （照着 compose 补一份环境变量只是补了一个部署；凡是"忘了设环境变量"的落盘路径都会再犯）。
///
/// 所以判据改成"**只有交互终端才上色**"，同时保持 `NO_COLOR` 的既有语义不变（设成非空即关闭；
/// 空串按未设置处理，与 tracing-subscriber 一致）。这样任何非交互落盘自动干净，不需要每一份
/// 部署配置都记得加一个环境变量。
fn ansi_for_logs(stdout_is_terminal: bool, no_color: Option<&OsStr>) -> bool {
    stdout_is_terminal && !no_color.is_some_and(|v| !v.is_empty())
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

    /// 规格（复扫 A6）：**非终端一律不上色**，且 `NO_COLOR` 的语义保持不变。
    ///
    /// 这条判据没法在进程内用真日志验证（tracing 的全局订阅者只能装一次，而测试进程的 stdout
    /// 恰好是 libtest 的管道），所以这里钉纯函数表；"日志真的落盘时干净"由真进程 e2e
    /// `signals::e2e_logs_written_to_a_file_are_not_colored` 覆盖（它把子进程 stdout 指向文件，
    /// 并**显式清掉继承来的 `NO_COLOR`**，否则测的就不是 TTY 判据了）。
    #[test]
    fn logs_are_only_colored_on_a_terminal() {
        let empty = OsStr::new("");
        let set = OsStr::new("1");
        assert!(ansi_for_logs(true, None), "终端 + 未设 NO_COLOR：上色");
        assert!(
            !ansi_for_logs(false, None),
            "**不是终端就不上色**——复扫 A6 的全部要点（旧行为只认 NO_COLOR，文件里全是 ESC）"
        );
        assert!(
            !ansi_for_logs(true, Some(set)),
            "NO_COLOR 非空：即使是终端也不上色"
        );
        assert!(
            ansi_for_logs(true, Some(empty)),
            "NO_COLOR 空串按未设置处理（与 tracing-subscriber 同口径）"
        );
        assert!(!ansi_for_logs(false, Some(set)));
    }

    /// 规格（复扫 F5）：`run` 起来之后**真的在提供服务**，不只是"任务没结束"。
    ///
    /// 单看 `!task.is_finished()` 是不够的：把 `run` 里"启动之后"的部分换成 `pending()`，
    /// 那条断言照样绿——它只证明了这个 future 没有立刻返回。所以这里加第二条判据：
    /// **公网入口真的在接受 TCP 连接**。
    #[tokio::test]
    async fn run_starts_gateway() {
        // 端口不能写 0：`listen_addr: 127.0.0.1:0` 让内核挑端口，测试就无从验证"真的在听"。
        // 先占一个再放掉（取空闲端口的常规办法），把端口号留在手里。
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        // 写一份完整配置到临时目录
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let config_path = dir.path().join("config.yml");
        let yaml = format!(
            r#"
listen_addr: "127.0.0.1:{port}"
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

        // 第二判据（复扫 F5）：真的能在那个端口上建立连接。有界轮询——listen 是启动期做的，
        // 但任务调度可能还没跑到。
        let mut connected = false;
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                connected = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            connected,
            "网关必须真的在 127.0.0.1:{port} 上接受连接，而不是挂在一个 pending 上（复扫 F5）"
        );

        task.abort();
    }
}
