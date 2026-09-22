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

/// 单个 e2e 步骤的墙钟上限（见 [`bounded`]）。
///
/// **取值 30s 是被两边夹出来的**：下界要高于网关自己在测试基线下的所有合法上限
/// （`head_timeout` 5s + 转发空闲 `request_timeout` 10s，关闭路径最坏
/// `shutdown_grace` 15s + `shutdown_flush_timeout` 10s + 收尾窗口 1s ≈ 26s）；
/// 上界要低于 `.config/nextest.toml` 的 `slow-timeout` 周期（60s），否则失败会被
/// nextest 先报成 TIMEOUT，丢掉步骤名这一关键信息。
///
/// 为什么需要它：e2e 里绝大多数 await **没有**任何超时（PROJECT_SCAN P2-17）。网关侧
/// 每一步虽然都有界，但"客户端一步卡住"在两种 runner 下的表现完全不同——
/// nextest 会在 180s 后杀掉进程、只留一句 TIMEOUT；`cargo test`（`make test`）下
/// 整条 e2e 是 `#[serial]` 的，一处卡住 = 套件无限期挂起。有了它，卡住会变成一条
/// **带步骤名**的失败。
pub const STEP_TIMEOUT: Duration = Duration::from_secs(30);

/// 等 `fut` 完成，最多 [`STEP_TIMEOUT`]；超时则 panic 并点出是哪一步。
pub async fn bounded<F: std::future::Future>(step: &str, fut: F) -> F::Output {
    bounded_within(STEP_TIMEOUT, step, fut).await
}

/// 同 [`bounded`]，窗口可指定（守卫自身的哨兵测试要毫秒级窗口，见文件末尾的测试模块）。
pub async fn bounded_within<F: std::future::Future>(
    limit: Duration,
    step: &str,
    fut: F,
) -> F::Output {
    match tokio::time::timeout(limit, fut).await {
        Ok(v) => v,
        Err(_) => panic!(
            "e2e step {step:?} did not finish within {limit:?}; \
             the gateway or the mock upstream stalled at this step"
        ),
    }
}

/// 测试用 reqwest client：**整条请求（含读响应体）的总超时**为 [`STEP_TIMEOUT`]。
///
/// "这一步本该完成"的用例一律用它——一个裸 `Client::new()` 会一直等下去（见哨兵
/// `a_bare_client_waits_forever_while_a_bounded_one_gives_up`），而 e2e 是 `#[serial]`：
/// 一处卡住 = `cargo test` 下整个套件无限期挂起、nextest 下只有一句 TIMEOUT。
///
/// **三类必须继续用裸 client**（它们要的就是"卡住"）：
/// - `stalls.rs`（请求体/响应体停滞）、`write_backpressure.rs`（写背压）：
///   断言的前提就是客户端不被服务；
/// - `https.rs::e2e_proxy_protocol_edge_cases`：好几个断言期待"body 读到一半出错"，
///   加了总超时会让它们变成"超时才出错"，断言虽仍通过但验的不是同一件事。
pub fn test_client() -> reqwest::Client {
    test_client_within(STEP_TIMEOUT)
}

/// 同 [`test_client`]，窗口可指定（哨兵测试要毫秒级窗口）。
pub fn test_client_within(limit: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(limit)
        .build()
        .expect("reqwest client")
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
    let created = store.create("e2e".into()).unwrap();
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

#[cfg(test)]
mod step_guard_tests {
    use super::{bounded_within, test_client_within, STEP_TIMEOUT};
    use std::time::Duration;

    /// 守卫**不能吞掉结果**：正常完成的步骤原样返回。
    #[tokio::test]
    async fn a_step_that_finishes_returns_its_value() {
        let v = bounded_within(Duration::from_secs(5), "fast step", async { 7u8 }).await;
        assert_eq!(v, 7);
    }

    /// [`STEP_TIMEOUT`] 的取值不是随手挑的，两侧都是硬约束——把它钉住，免得日后有人
    /// 顺着"再宽松点免抖动"把它调到 nextest 周期之上，于是失败又被报成 TIMEOUT、
    /// 步骤名这个唯一有用的信息再次丢掉。
    #[test]
    fn the_step_window_sits_between_the_gateway_bound_and_the_nextest_period() {
        // 收尾窗口是 `gateway.rs` 的私有常量 END_EVENT_WINDOW（1s），按 1s 记。
        let worst_gateway_bound = gateway::Options::DEFAULT_SHUTDOWN_GRACE
            + gateway::Options::DEFAULT_SHUTDOWN_FLUSH_TIMEOUT
            + Duration::from_secs(1);
        assert!(
            STEP_TIMEOUT > worst_gateway_bound,
            "窗口 {STEP_TIMEOUT:?} 必须高于网关关闭路径的最坏上限 {worst_gateway_bound:?}"
        );
        assert!(
            STEP_TIMEOUT < Duration::from_secs(60),
            "窗口 {STEP_TIMEOUT:?} 必须低于 nextest 的 slow-timeout 周期(60s)，\
             否则失败会被 TIMEOUT 抢先、丢掉步骤名"
        );
    }

    /// 守卫自身的哨兵：卡住的步骤必须**带着步骤名**失败，而不是静静挂住。
    ///
    /// 用 `bounded_within` 传毫秒级窗口，生产值 [`STEP_TIMEOUT`] 只在被测代码里生效
    /// （30s 的窗口没法进单元测试）。
    #[tokio::test]
    #[should_panic(expected = "stalled step")]
    async fn a_stalled_step_fails_with_its_name_instead_of_hanging() {
        bounded_within(
            Duration::from_millis(20),
            "stalled step",
            std::future::pending::<()>(),
        )
        .await;
    }

    /// **复现被报告的那个症状**：对端 accept 了连接却永远不说话（TLS 握手永远等不到
    /// ServerHello），客户端一步卡死。这正是 `https::e2e_https_public_entry` 那次
    /// 180s TIMEOUT 的形状——`slow-timeout` 只能告诉你"有个测试卡了 180s"，
    /// 而带上守卫之后失败会点名是**哪一步**卡了。
    #[tokio::test]
    #[should_panic(expected = "GET /healthz over TLS")]
    async fn a_black_hole_listener_fails_the_step_that_talks_to_it() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // accept 之后把 socket **留着不放**：关闭会变成 EOF（客户端立刻报错），
        // 而这里要的是"连上了但永远没有响应"。
        tokio::spawn(async move {
            let _held = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        bounded_within(
            Duration::from_millis(300),
            "GET /healthz over TLS",
            client.get(format!("https://{addr}/healthz")).send(),
        )
        .await
        .unwrap();
    }

    /// 规格（`PROJECT_SCAN` P2-17 的剩余部分）：**裸 client 会一直等下去，
    /// 带总超时的 client 会自己放弃**。
    ///
    /// 前半句是这个缺陷本身（e2e 里绝大多数请求以前就是裸 client），后半句是
    /// [`test_client`] 的契约。窗口取毫秒级，所以这条哨兵本身是毫秒级的。
    #[tokio::test]
    async fn a_bare_client_waits_forever_while_a_bounded_one_gives_up() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // 黑洞：accept 之后既不读也不写，永远不回响应
        tokio::spawn(async move {
            let _held = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let url = format!("http://{addr}/healthz");

        // ① 裸 client：500ms 的外层窗口内不会返回（这就是缺陷）
        let bare = reqwest::Client::new();
        let hung = tokio::time::timeout(Duration::from_millis(500), bare.get(&url).send()).await;
        assert!(
            hung.is_err(),
            "前提：裸 client 对黑洞连接不会自己放弃（否则这条哨兵没测到东西）"
        );

        // ② 带窗口的 client：在窗口量级返回错误，而不是陪着一起卡住
        let t0 = std::time::Instant::now();
        let gave_up = test_client_within(Duration::from_millis(200))
            .get(&url)
            .send()
            .await;
        assert!(gave_up.is_err(), "总超时到点必须报错");
        assert!(
            t0.elapsed() < Duration::from_millis(400),
            "应在超时量级返回，实际 {:?}",
            t0.elapsed()
        );
    }
}
