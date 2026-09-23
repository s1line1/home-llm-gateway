//! 信号场景 e2e：**真进程**收 SIGHUP，必须走优雅关闭（排空 + 强制落库），
//! 而不是沿用默认动作被直接终止。
//!
//! 为什么用真进程而不是库 API：这条缺陷就在 `main.rs` 的**信号选择**里——`Gateway::shutdown`
//! 自己是好的（库内 e2e 已经覆盖）。只有把二进制拉起来、真的发一个 SIGHUP，才能把"信号压根
//! 没被接住"这件事测出来：被信号打死时 `ExitStatus::code()` 是 `None`，且日志里不会有
//! 落库那一行。

use super::common::*;
use std::{
    fs::File,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

/// 子进程守卫：断言失败 / 提前 panic 也要收尸，别把网关留在后台占着端口。
struct ChildGuard(Child);

impl ChildGuard {
    fn pid(&self) -> u32 {
        self.0.id()
    }

    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.0.try_wait()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// 内核分配一个空闲端口后立刻放掉：真进程的配置里写不了 `:0`（拿不回实际端口，
/// 而 `gw.http_addr` 那种回读只在库内可用）。
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    p
}

/// 给进程发信号。用系统 `kill` 而不是 libc/nix：不想为一个测试加依赖。
fn send_signal(pid: u32, sig: &str) {
    let out = Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "kill -{sig} {pid} 失败: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// 轮询子进程日志，等某一行出现（真进程唯一的确定性就绪判据）。
async fn wait_for_log_line(path: &Path, needle: &str, limit: Duration) -> String {
    let deadline = Instant::now() + limit;
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if text.contains(needle) {
            return text;
        }
        assert!(
            Instant::now() < deadline,
            "日志里没等到 {needle:?}：\n{text}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_exit(child: &mut ChildGuard, limit: Duration) -> ExitStatus {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "进程在 {limit:?} 内没有退出");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// 规格（P3-9 / SUPPORT_LAYER P3-19）：SIGHUP 不是"默认终止"，而是**优雅关闭**的另一种触发
/// ——与 SIGTERM/SIGINT 同一条路径（排空在途 → 有界强制落库）。
///
/// 之前 `shutdown_signal()` 只 select 了 SIGINT/SIGTERM，SIGHUP 保留默认动作：`kill -HUP`、
/// 终端挂断、`systemctl stop` 之外的任何 HUP 都会**立刻杀进程**，于是 `Gateway::shutdown` 的
/// `flush_usage_blocking` 不跑，最多丢掉一个 flush 周期（≤1s）的用量；在途流式请求也被硬断。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_sighup_goes_through_the_graceful_shutdown_path() {
    let dir = tempfile::tempdir().unwrap();
    let (ca_pem, srv_pem, srv_key_pem, _, _) = gen_certs_pem();
    let ca = write_file(dir.path(), "ca.crt", &ca_pem);
    let cert = write_file(dir.path(), "server.crt", &srv_pem);
    let key = write_file(dir.path(), "server.key", &srv_key_pem);

    let http_port = free_port();
    let quic_port = free_port();
    let cfg = write_file(
        dir.path(),
        "gateway.yml",
        &format!(
            "listen_addr: \"127.0.0.1:{http_port}\"\n\
             quic_addr: \"127.0.0.1:{quic_port}\"\n\
             cert: {}\nkey: {}\nca: {}\nkeys_file: {}\n",
            cert.display(),
            key.display(),
            ca.display(),
            dir.path().join("keys.db").display(),
        ),
    );

    let log_path = dir.path().join("gateway.log");
    let log = File::create(&log_path).unwrap();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_gateway"))
            .arg("--config")
            .arg(&cfg)
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );

    // 就绪判据必须是"信号 handler 已注册"这行日志，而不是探活：`/healthz` 在
    // `Gateway::start` 里就可用了，那时 `shutdown_signal()` 还没跑，抢在中间发 HUP 会按
    // 默认动作直接杀掉进程（随机红）。
    wait_for_log_line(&log_path, "shutdown signals armed", Duration::from_secs(15)).await;

    send_signal(child.pid(), "HUP");
    let status = wait_for_exit(&mut child, Duration::from_secs(15)).await;
    let text = std::fs::read_to_string(&log_path).unwrap();

    assert_eq!(
        status.code(),
        Some(0),
        "SIGHUP 应当走优雅关闭并以 0 退出；被信号打死时 code() 是 None。日志：\n{text}"
    );
    assert!(
        text.contains("received SIGHUP"),
        "日志里应当说明收到了 SIGHUP：\n{text}"
    );
    assert!(
        text.contains("usage flushed before shutdown"),
        "SIGHUP 也必须走到 shutdown 的强制落库那一步：\n{text}"
    );
}
