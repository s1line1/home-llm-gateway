//! 信号场景测试：**真进程**收 SIGHUP，必须走优雅关闭（`agent.shutdown()`），
//! 而不是沿用默认动作被直接终止。
//!
//! 用真进程而不是库 API：缺陷在 `main.rs` 的信号选择里，`Agent::shutdown` 自己没问题。

use std::{
    fs::File,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType};

/// 子进程守卫：断言失败 / 提前 panic 也要收尸，别把 agent 留在后台。
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

/// 生成 (ca, client.crt, client.key) 三个 PEM 文件。agent 需要一个能装载的客户端身份；
/// 本用例里它永远连不上（配置指向没人监听的端口），所以只需"装得进去"。
fn gen_cert_files(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::default();
    ca.distinguished_name.push(DnType::CommonName, "test ca");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
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

/// 规格（P3-9 / SUPPORT_LAYER P3-19，agent 侧同形）：SIGHUP 是**优雅关闭**的另一种触发，
/// 与 SIGTERM/SIGINT 同一条路径（`agent.shutdown()`）。
#[test]
fn sighup_goes_through_the_graceful_shutdown_path() {
    let dir = tempfile::tempdir().unwrap();
    let (ca, cert, key) = gen_cert_files(dir.path());
    let cfg_path = dir.path().join("agent.yml");
    std::fs::write(
        &cfg_path,
        format!(
            "cloud_addr: \"127.0.0.1:1\"\n\
             ca: {}\ncert: {}\nkey: {}\n\
             agent_id: sighup-test\n\
             upstream: \"http://127.0.0.1:1\"\n\
             heartbeat_secs: 1\n\
             max_concurrency: 1\n",
            ca.display(),
            cert.display(),
            key.display(),
        ),
    )
    .unwrap();

    let log_path = dir.path().join("agent.log");
    let log = File::create(&log_path).unwrap();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_agent"))
            .arg("--config")
            .arg(&cfg_path)
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );

    // 就绪判据是"信号 handler 已注册"那行日志：它连不上网关（端口 1 没人听），
    // 没有"connected"可等；而在这行之前发 HUP 会按默认动作直接杀掉进程（随机红）。
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let text = std::fs::read_to_string(&log_path).unwrap_or_default();
        if text.contains("shutdown signals armed") {
            break;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "agent 起动就退出了；日志：\n{text}"
        );
        assert!(Instant::now() < deadline, "没等到信号就绪日志：\n{text}");
        std::thread::sleep(Duration::from_millis(20));
    }

    send_signal(child.pid(), "HUP");
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < deadline, "agent 在 15s 内没有退出");
        std::thread::sleep(Duration::from_millis(20));
    };
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
        text.contains("graceful shutdown: stopping agent"),
        "SIGHUP 也必须走到 agent.shutdown() 那一步：\n{text}"
    );
}
