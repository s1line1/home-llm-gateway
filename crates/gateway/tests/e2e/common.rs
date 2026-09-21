//! e2e 公共辅助：证书生成、测试栈启动等（被各场景模块共享）。

// 公共导入以 pub use 暴露，子场景模块通过 `use super::common::*` 共享
pub use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

pub use agent::{Agent, AgentConfig};
pub use gateway::{Gateway, GatewayConfig, Options, TlsPem, TunnelTls};
pub use proto::{
    io::{read_frame, write_frame},
    Frame,
};
pub use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
pub use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
pub use serial_test::serial;

/// 生成 (CA, 服务端证书, 服务端私钥, 客户端证书, 客户端私钥) 的 DER 形态。
///
/// 与 [`gen_certs_pem`] 是**同一套**material，只是编码不同：这里转成 DER，
/// 以前它是一份独立的 60 行复制品（两份只差 CA 的 key_usages，见下）。
pub fn gen_certs() -> (
    CertificateDer<'static>,
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
) {
    let (ca, srv, srv_key, cli, cli_key) = gen_certs_pem();
    (
        parse_certs_pem(&ca).remove(0),
        parse_certs_pem(&srv).remove(0),
        parse_key_pem(&srv_key),
        parse_certs_pem(&cli).remove(0),
        parse_key_pem(&cli_key),
    )
}

/// 生成同一套证书的 PEM 文本（HTTPS 公网入口需要 PEM 字节）。
pub fn gen_certs_pem() -> (String, String, String, String, String) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "e2e CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    // CA 的用途取并集：DER 路径原先多一项 DigitalSignature，PEM 路径没有。
    // 合并成一份之后按**更宽**的那个来——给 CA 加用途不会让原本通过的握手失败。
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let server_key = KeyPair::generate().unwrap();
    let mut srv = CertificateParams::default();
    srv.distinguished_name.push(DnType::CommonName, "gateway");
    srv.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into().unwrap()),
        SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    ];
    srv.is_ca = IsCa::NoCa;
    srv.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    srv.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let server_cert = srv.signed_by(&server_key, &ca_cert, &ca_key).unwrap();

    let client_key = KeyPair::generate().unwrap();
    let mut cli = CertificateParams::default();
    cli.distinguished_name
        .push(DnType::CommonName, "test-agent");
    cli.is_ca = IsCa::NoCa;
    cli.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    cli.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let client_cert = cli.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

    (
        ca_cert.pem(),
        server_cert.pem(),
        server_key.serialize_pem(),
        client_cert.pem(),
        client_key.serialize_pem(),
    )
}

pub fn parse_certs_pem(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut std::io::Cursor::new(pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

pub fn parse_key_pem(pem: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut std::io::Cursor::new(pem.as_bytes()))
        .unwrap()
        .unwrap()
}

pub async fn start_mock_llm(name: &str) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let name = name.to_string();
    tokio::spawn(async move {
        let _ = axum::serve(listener, mock_llm::router(&name)).await;
    });
    addr
}

pub async fn wait_for_agents(gw: &Gateway, count: usize, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if gw.agent_count() >= count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("expected {count} agents, got {}", gw.agent_count());
}

/// 建一个临时 SQLite 库并种入一个测试 key，返回 (库路径, key)。
/// 临时目录被 forget 保活，避免网关持有连接时库文件被清理。
pub fn seed_keys_db() -> (PathBuf, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.db");
    let store = gateway::storage::KeyStore::new(Some(path.clone()));
    let created = store.create("e2e".into());
    std::mem::forget(dir);
    (path, created.plaintext)
}

/// 读 `/metrics` 里的某个 gauge 值（测试用它断言"槽位是否归还"）。
pub async fn metric_gauge(base: &str, name: &str) -> u64 {
    let text = reqwest::get(format!("{base}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    text.lines()
        .find_map(|l| {
            let (k, v) = l.split_once(' ')?;
            (k == name).then(|| v.trim().parse().ok())?
        })
        .unwrap_or_else(|| panic!("指标 {name} 不在 /metrics 输出里"))
}

/// 一套测试用证书材料：CA + 一份 agent 客户端身份 + 服务端身份的两种编码形态。
///
/// 由 [`start_gateway`] 产出。多 agent 场景复用它给每个 agent 签身份（客户端私钥用
/// `clone_key()`，每个 agent 各拿一份）。HTTPS 公网入口要的是 **PEM 字节**而隧道侧要 DER，
/// 所以两种形态都在这里——省得各用例自己再跑一遍 `gen_certs_pem()` 并手工 parse。
pub struct TestCerts {
    pub ca: Vec<CertificateDer<'static>>,
    pub client_cert: Vec<CertificateDer<'static>>,
    pub client_key: PrivateKeyDer<'static>,
    /// 服务端身份（DER）：隧道侧 `TunnelTls` 用。
    server_cert_der: Vec<CertificateDer<'static>>,
    server_key_der: PrivateKeyDer<'static>,
    /// 服务端身份（PEM 字节）：HTTPS 公网入口用。
    server_cert_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
}

impl TestCerts {
    /// 起一个 agent 接到 `gw`，上游是 `upstream` 上的 mock-llm。
    pub fn agent(
        &self,
        gw: &Gateway,
        agent_id: &str,
        models: &[&str],
        upstream: SocketAddr,
        max_concurrency: u32,
        request_log: bool,
    ) -> Agent {
        Agent::start(AgentConfig {
            cloud_addr: gw.quic_addr,
            server_name: "localhost".into(),
            ca_cert: self.ca.clone(),
            client_cert: self.client_cert.clone(),
            client_key: self.client_key.clone_key(),
            agent_id: agent_id.into(),
            models: models.iter().map(|m| (*m).to_string()).collect(),
            max_concurrency,
            upstream_base: format!("http://{upstream}"),
            heartbeat_interval: Duration::from_millis(200),
            request_log,
        })
        .unwrap()
    }

    /// 公网入口的 HTTPS 材料（PEM 字节，见 [`gateway::TlsPem`]）。
    ///
    /// 放进 `Options::https` 即可让入口走 TLS——但材料要**生成之后**才知道，所以那种用例得用
    /// [`start_gateway_with`]，它的 `tune` 能拿到 `&TestCerts`。
    pub fn https_pem(&self) -> TlsPem {
        TlsPem {
            cert: self.server_cert_pem.clone(),
            key: self.server_key_pem.clone(),
        }
    }
}

/// 裸网关 + 它周围的材料：证书、已种好的 api key、keys.db 路径、http base。
///
/// 多 agent / 异构模型 / 裸 QUIC 客户端 / 自定义上游这类要自己控制"网关之外那一半"的场景
/// 用它；只要一套标准栈（mock-llm + 一个 test-agent）就用 [`start_stack`]。
pub struct TestGateway {
    pub gw: Gateway,
    pub certs: TestCerts,
    pub key: String,
    /// 已种好的 keys.db 路径（少数用例要自己对它拿独占锁）。
    pub keys_path: PathBuf,
    /// `http://<真实端口>`。
    pub base: String,
}

/// 起一个**裸网关**（不接 agent）。`tune` 只改这个用例真正要动的旋钮。
///
/// 测试基线刻意与库默认（生产数值）不同：超时压到秒级——否则一条注定失败的用例会静默多挂
/// 十几秒（`request_timeout` 库默认 120s）。端口用库默认的 `127.0.0.1:0`（内核分配，靠
/// `gw.http_addr` 回读），UI 目录不配。
pub async fn start_gateway(tune: impl FnOnce(&mut Options)) -> TestGateway {
    start_gateway_with(move |o, _certs| tune(o)).await
}

/// 同 [`start_gateway`]，但 `tune` 还能拿到证书材料——HTTPS 入口的 PEM 只有生成之后才知道。
pub async fn start_gateway_with(tune: impl FnOnce(&mut Options, &TestCerts)) -> TestGateway {
    let (ca_pem, srv_pem, srv_key_pem, cli_pem, cli_key_pem) = gen_certs_pem();
    let certs = TestCerts {
        ca: parse_certs_pem(&ca_pem),
        client_cert: parse_certs_pem(&cli_pem),
        client_key: parse_key_pem(&cli_key_pem),
        server_cert_der: parse_certs_pem(&srv_pem),
        server_key_der: parse_key_pem(&srv_key_pem),
        server_cert_pem: srv_pem.into_bytes(),
        server_key_pem: srv_key_pem.into_bytes(),
    };

    let (keys_path, key) = seed_keys_db();
    let mut opts = Options {
        keys_file: Some(keys_path.clone()),
        request_timeout: Duration::from_secs(10),
        tunnel_op_timeout: Duration::from_secs(2),
        head_timeout: Duration::from_secs(5),
        agent_stale_after: Duration::from_secs(10),
        client_stall: Duration::from_secs(60),
        ..Options::default()
    };
    tune(&mut opts, &certs);

    let gw = Gateway::start(GatewayConfig {
        tunnel: TunnelTls::from_der(
            certs.ca.clone(),
            certs.server_cert_der.clone(),
            certs.server_key_der.clone_key(),
        )
        .expect("e2e certs are non-empty"),
        opts,
    })
    .await
    .unwrap();

    let base = format!("http://{}", gw.http_addr);
    TestGateway {
        gw,
        certs,
        key,
        keys_path,
        base,
    }
}

/// 拉起一整套栈（mock-llm + gateway + 一个 test-agent），返回 (gw, agent, http base, api key)。
///
/// `max_concurrency` 是 **agent 侧**的并发上限（准入控制的依据）；网关旋钮一律通过
/// `tune` 闭包表达。以前这里有 6 个近邻函数（`start_stack_with_verify_cache` /
/// `_with_tunnel_timeout` / `_full` / `_with_admission` / `_with_head_timeout` /
/// `start_stack` 自身），每加一种测试变体就得再写一个；现在变体是闭包，**不会再长**。
pub async fn start_stack(
    max_concurrency: u32,
    tune: impl FnOnce(&mut Options),
) -> (Gateway, Agent, String, String) {
    let t = start_gateway(tune).await;
    let mock_addr = start_mock_llm("mock-llm").await;
    let agent = t.certs.agent(
        &t.gw,
        "test-agent",
        &["mock-llm"],
        mock_addr,
        max_concurrency,
        true,
    );
    wait_for_agents(&t.gw, 1, Duration::from_secs(10)).await;
    let TestGateway { gw, key, base, .. } = t;
    (gw, agent, base, key)
}

/// 起一个**裸 QUIC agent**：注册成功后什么都不做——**不读请求流、不回帧、也不发心跳**。
///
/// 连接被移进一个永不结束的 keep-alive 任务：既保证它活到测试结束，也保证没有任何代码
/// 会去 accept/read 请求流。两个用途：
/// - 写背压：请求帧撑爆对端流控窗口 → `tunnel_write` 超时（见 `write_backpressure`）；
/// - 可路由性：注册后从不心跳 → `last_seen` 过期，`agent_count()` 仍计入它、
///   `healthy_agent_count()` 不计（见 `lifecycle`）。
pub async fn spawn_raw_agent(
    gw: &Gateway,
    certs: &TestCerts,
    agent_id: &str,
    max_concurrency: u32,
) {
    let client = s2n_quic::Client::builder()
        .with_tls(s2n_quic::provider::tls::rustls::Client::from(
            std::sync::Arc::new(
                agent::tls::rustls_client_tls(
                    &certs.ca,
                    certs.client_cert.clone(),
                    certs.client_key.clone_key(),
                )
                .unwrap(),
            ),
        ))
        .unwrap()
        .with_io("0.0.0.0:0")
        .unwrap()
        .start()
        .unwrap();
    let mut conn = client
        .connect(s2n_quic::client::Connect::new(gw.quic_addr).with_server_name("localhost"))
        .await
        .unwrap();
    let stream = conn.open_bidirectional_stream().await.unwrap();
    let (mut reg_recv, mut reg_send) = stream.split();
    write_frame(
        &mut reg_send,
        &Frame::Register {
            agent_id: agent_id.into(),
            models: vec!["mock-llm".into()],
            max_concurrency,
            version: "test".into(),
        },
    )
    .await
    .unwrap();
    reg_send.finish().unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut reg_recv)).await;
    wait_for_agents(gw, 1, Duration::from_secs(5)).await;

    tokio::spawn(async move {
        let _keep_alive = (client, conn, reg_recv);
        std::future::pending::<()>().await;
    });
}
