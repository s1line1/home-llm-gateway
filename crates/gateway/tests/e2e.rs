//! 端到端集成测试：内存生成 CA/服务端/客户端证书，
//! 在单进程内拉起 mock-llm + gateway + agent，验证完整链路。
//! 无需真实 LLM 或真实服务器。

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use agent::{Agent, AgentConfig};
use gateway::{Gateway, GatewayConfig, TlsPem};
use proto::{io::{read_frame, write_frame}, Frame};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// 生成 (CA, 服务端证书, 服务端私钥, 客户端证书, 客户端私钥)。
fn gen_certs() -> (
    CertificateDer<'static>,
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "e2e CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
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
    let server_cert = srv
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap()
        .der()
        .clone();
    let server_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));

    let client_key = KeyPair::generate().unwrap();
    let mut cli = CertificateParams::default();
    cli.distinguished_name
        .push(DnType::CommonName, "test-agent");
    cli.is_ca = IsCa::NoCa;
    cli.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    cli.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let client_cert = cli
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap()
        .der()
        .clone();
    let client_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der()));

    (ca_cert.der().clone(), server_cert, server_key, client_cert, client_key)
}

/// 生成同一套证书的 PEM 文本（HTTPS 公网入口需要 PEM 字节）。
fn gen_certs_pem() -> (String, String, String, String, String) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "e2e CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
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

fn parse_certs_pem(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut std::io::Cursor::new(pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn parse_key_pem(pem: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut std::io::Cursor::new(pem.as_bytes()))
        .unwrap()
        .unwrap()
}

async fn start_mock_llm(name: &str) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let name = name.to_string();
    tokio::spawn(async move {
        let _ = axum::serve(listener, mock_llm::router(&name)).await;
    });
    addr
}

async fn wait_for_agents(gw: &Gateway, count: usize, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if gw.agent_count() >= count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("expected {count} agents, got {}", gw.agent_count());
}

/// 拉起一整套栈（mock-llm + gateway + agent），返回 (gw, agent, http base)。
#[allow(clippy::too_many_arguments)]
async fn start_stack(
    request_timeout: Duration,
    rate_limit_per_min: u32,
    max_concurrency: u32,
    admin_token: Option<&str>,
    keys_file: Option<PathBuf>,
) -> (Gateway, Agent, String) {
    let (ca, server_cert, server_key, client_cert, client_key) = gen_certs();
    let mock_addr = start_mock_llm("mock-llm").await;

    let gw = Gateway::start(GatewayConfig {
        http_bind: "127.0.0.1:0".parse().unwrap(),
        quic_bind: "127.0.0.1:0".parse().unwrap(),
        ca_cert: vec![ca.clone()],
        server_cert: vec![server_cert.clone()],
        server_key,
        api_keys: vec!["test-key".into()],
        admin_token: admin_token.map(|s| s.to_string()),
        keys_file,
        request_timeout,
        agent_stale_after: Duration::from_secs(10),
        rate_limit_per_min,
        tls: None,
    })
    .await
    .unwrap();

    let agent = Agent::start(AgentConfig {
        cloud_addr: gw.quic_addr,
        server_name: "localhost".into(),
        ca_cert: vec![ca.clone()],
        client_cert: vec![client_cert.clone()],
        client_key,
        agent_id: "test-agent".into(),
        models: vec!["mock-llm".into()],
        max_concurrency,
        upstream_base: format!("http://{mock_addr}"),
        heartbeat_interval: Duration::from_millis(200),
    })
    .unwrap();

    wait_for_agents(&gw, 1, Duration::from_secs(10)).await;
    let base = format!("http://{}", gw.http_addr);
    (gw, agent, base)
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_chain_with_mock_llm() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base) = start_stack(Duration::from_secs(10), 0, 4, None, None).await;
    let client = reqwest::Client::new();

    // 无认证 → 401
    let resp = client.get(format!("{base}/v1/models")).send().await.unwrap();
    assert_eq!(resp.status(), 401, "missing api key must be rejected");

    // healthz 无需认证
    let resp = client.get(format!("{base}/healthz")).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // 根路径返回管理页 HTML（含创建 API Key 的 UI）
    let resp = client.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let page = resp.text().await.unwrap();
    assert!(page.contains("Home LLM Gateway"), "root should serve the admin page");
    assert!(page.contains("创建 Key"), "admin page should expose key creation UI");
    assert!(page.starts_with("<!doctype html>"), "admin page should be HTML");

    // 认证后 /v1/models 穿透到 mock
    let resp = client
        .get(format!("{base}/v1/models"))
        .header("Authorization", "Bearer test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let models: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(models["data"][0]["id"], "mock-llm");

    // chat completions 全链路（非流式）
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", "Bearer test-key")
        .json(&serde_json::json!({
            "model": "mock-llm",
            "messages": [{"role": "user", "content": "hello from e2e"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let reply = body["choices"][0]["message"]["content"].as_str().unwrap();
    assert!(
        reply.contains("hello from e2e"),
        "mock reply should echo user content, got: {reply}"
    );

    // embeddings 也走通
    let resp = client
        .post(format!("{base}/v1/embeddings"))
        .header("Authorization", "Bearer test-key")
        .json(&serde_json::json!({"model": "mock-llm", "input": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let emb: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(emb["data"][0]["embedding"].as_array().unwrap().len(), 3);

    agent.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_sse_streaming_passthrough() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base) = start_stack(Duration::from_secs(10), 0, 4, None, None).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", "Bearer test-key")
        .json(&serde_json::json!({
            "model": "mock-llm",
            "stream": true,
            "messages": [{"role": "user", "content": "流式测试"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let ctype = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        ctype.starts_with("text/event-stream"),
        "expected SSE content-type, got: {ctype}"
    );

    let text = resp.text().await.unwrap();
    // 逐字事件 + finish_reason 事件 + [DONE]
    let data_lines = text.matches("data: ").count();
    assert!(data_lines >= 3, "expected multiple SSE events, got {data_lines}: {text}");
    assert!(text.contains("data: [DONE]"), "missing [DONE] terminator: {text}");
    assert!(
        text.contains(r#""content":"流""#) && text.contains(r#""content":"试""#),
        "SSE should stream the echoed content per char: {text}"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_gateway_timeout_cancels_upstream() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    // 网关空闲超时 150ms，而 mock 的 /v1/slow 要睡 800ms 才响应 → 应触发超时 + Cancel
    let (gw, agent, base) = start_stack(Duration::from_millis(150), 0, 4, None, None).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/v1/slow"))
        .header("Authorization", "Bearer test-key")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 504, "slow upstream should be cut off by idle timeout");

    // Cancel 不应影响 agent 连接本身，之后仍能正常服务
    let resp = client
        .get(format!("{base}/v1/models"))
        .header("Authorization", "Bearer test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    agent.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_rate_limit_per_key() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    // 每分钟 5 次：前 5 个请求放行，第 6 个 429
    let (gw, agent, base) = start_stack(Duration::from_secs(10), 5, 4, None, None).await;
    let client = reqwest::Client::new();

    for i in 0..5 {
        let resp = client
            .get(format!("{base}/v1/models"))
            .header("Authorization", "Bearer test-key")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "request {i} should pass the limit");
    }
    let resp = client
        .get(format!("{base}/v1/models"))
        .header("Authorization", "Bearer test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "6th request within the minute should be limited"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_admission_control() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    // agent max_concurrency=1：两个并发慢请求，一个 200、一个 429；完成后槽位释放
    let (gw, agent, base) = start_stack(Duration::from_secs(10), 0, 1, None, None).await;
    let client = reqwest::Client::new();
    let url = format!("{base}/v1/slow");
    let req = || {
        client
            .post(&url)
            .header("Authorization", "Bearer test-key")
            .json(&serde_json::json!({}))
    };

    let (a, b) = tokio::join!(req().send(), req().send());
    let (ra, rb) = (a.unwrap(), b.unwrap());
    let mut statuses = vec![ra.status(), rb.status()];
    statuses.sort();
    assert_eq!(
        statuses,
        vec![
            reqwest::StatusCode::OK,
            reqwest::StatusCode::TOO_MANY_REQUESTS
        ],
        "with max_concurrency=1, exactly one concurrent request should be admitted"
    );

    // 消费两个响应体，确保网关侧槽位已释放
    let _ = ra.bytes().await;
    let _ = rb.bytes().await;

    // 槽位释放后，新请求应成功
    let resp = req().send().await.unwrap();
    assert_eq!(resp.status(), 200, "slot should be released after completion");

    agent.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_multi_agent_least_loaded() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (ca, server_cert, server_key, client_cert, client_key) = gen_certs();
    let mock_a = start_mock_llm("mock-a").await;
    let mock_b = start_mock_llm("mock-b").await;

    let gw = Gateway::start(GatewayConfig {
        http_bind: "127.0.0.1:0".parse().unwrap(),
        quic_bind: "127.0.0.1:0".parse().unwrap(),
        ca_cert: vec![ca.clone()],
        server_cert: vec![server_cert.clone()],
        server_key,
        api_keys: vec!["test-key".into()],
        admin_token: None,
        keys_file: None,
        request_timeout: Duration::from_secs(10),
        agent_stale_after: Duration::from_secs(10),
        rate_limit_per_min: 0,
        tls: None,
    })
    .await
    .unwrap();

    let mk_agent = |agent_id: &str, upstream: SocketAddr| {
        Agent::start(AgentConfig {
            cloud_addr: gw.quic_addr,
            server_name: "localhost".into(),
            ca_cert: vec![ca.clone()],
            client_cert: vec![client_cert.clone()],
            client_key: client_key.clone_key(),
            agent_id: agent_id.into(),
            models: vec!["mock-llm".into()],
            max_concurrency: 1,
            upstream_base: format!("http://{upstream}"),
            heartbeat_interval: Duration::from_millis(200),
        })
        .unwrap()
    };
    let agent_a = mk_agent("agent-a", mock_a);
    let agent_b = mk_agent("agent-b", mock_b);
    wait_for_agents(&gw, 2, Duration::from_secs(10)).await;

    let client = reqwest::Client::new();
    let url = format!("http://{}/v1/slow", gw.http_addr);
    let req = || {
        client
            .post(&url)
            .header("Authorization", "Bearer test-key")
            .json(&serde_json::json!({}))
    };

    // 3 个并发慢请求：每个 agent 容量 1 → 应恰好占用两个不同 agent（2×200），第 3 个 429
    let (ra, rb, rc) = tokio::join!(req().send(), req().send(), req().send());
    let mut responses = vec![ra.unwrap(), rb.unwrap(), rc.unwrap()];
    let mut servers = Vec::new();
    for resp in responses.drain(..) {
        match resp.status() {
            reqwest::StatusCode::OK => {
                let body: serde_json::Value = resp.json().await.unwrap();
                servers.push(body["server"].as_str().unwrap().to_string());
            }
            reqwest::StatusCode::TOO_MANY_REQUESTS => {}
            other => panic!("unexpected status: {other}"),
        }
    }
    assert_eq!(servers.len(), 2, "two requests should be admitted");
    assert_ne!(servers[0], servers[1], "concurrent requests should be spread across agents");
    assert!(
        servers.iter().all(|s| s == "mock-a" || s == "mock-b"),
        "unexpected upstream: {servers:?}"
    );

    agent_a.shutdown().await;
    agent_b.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_metrics_endpoint() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base) = start_stack(Duration::from_secs(10), 0, 4, None, None).await;
    let client = reqwest::Client::new();

    // 先发两个请求（一个 401、一个 200），让计数器有值
    let _ = client.get(format!("{base}/v1/models")).send().await.unwrap();
    let _ = client
        .get(format!("{base}/v1/models"))
        .header("Authorization", "Bearer test-key")
        .send()
        .await
        .unwrap();

    let resp = client.get(format!("{base}/metrics")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert!(text.contains("hlmg_requests_total{status=\"401\"} 1"), "missing 401 counter: {text}");
    assert!(text.contains("hlmg_requests_total{status=\"200\"} 1"), "missing 200 counter: {text}");
    assert!(text.contains("hlmg_agents 1"), "missing agents gauge: {text}");
    assert!(text.contains("hlmg_bytes_out "), "missing bytes counter: {text}");

    agent.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_admin_api_keys() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base) = start_stack(Duration::from_secs(10), 0, 4, Some("admin-token"), None).await;
    let client = reqwest::Client::new();

    // 无 admin token → 401；普通 API key 也不行
    let resp = client
        .post(format!("{base}/admin/keys"))
        .json(&serde_json::json!({"name": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "admin endpoints require admin token");
    let resp = client
        .post(format!("{base}/admin/keys"))
        .header("Authorization", "Bearer test-key")
        .json(&serde_json::json!({"name": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "API keys must not unlock admin endpoints");

    // 创建 key
    let resp = client
        .post(format!("{base}/admin/keys"))
        .header("Authorization", "Bearer admin-token")
        .json(&serde_json::json!({"name": "dsh-client"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let created: serde_json::Value = resp.json().await.unwrap();
    let new_key = created["key"].as_str().unwrap().to_string();
    let new_id = created["id"].as_str().unwrap().to_string();
    assert!(new_key.starts_with("sk-"), "generated key should have sk- prefix");

    // 新 key 立即生效（运行时创建，无需重启）
    let resp = client
        .get(format!("{base}/v1/models"))
        .header("Authorization", format!("Bearer {new_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "runtime-created key should work immediately");

    // 列表包含刚创建的 key（且不暴露明文）
    let resp = client
        .get(format!("{base}/admin/keys"))
        .header("Authorization", "Bearer admin-token")
        .send()
        .await
        .unwrap();
    let list: serde_json::Value = resp.json().await.unwrap();
    assert!(
        list.as_array().unwrap().iter().any(|k| k["name"] == "dsh-client" && k["id"] == new_id),
        "list should contain the created key"
    );
    let list_text = serde_json::to_string(&list).unwrap();
    assert!(!list_text.contains(&new_key), "list must not leak full key secrets");

    // 吊销 → 204，之后该 key 立即失效
    let resp = client
        .delete(format!("{base}/admin/keys/{new_id}"))
        .header("Authorization", "Bearer admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let resp = client
        .get(format!("{base}/v1/models"))
        .header("Authorization", format!("Bearer {new_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "revoked key must be rejected");

    // 删除不存在的 key → 404
    let resp = client
        .delete(format!("{base}/admin/keys/{new_id}"))
        .header("Authorization", "Bearer admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    agent.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_https_public_entry() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (ca_pem, srv_pem, srv_key_pem, cli_pem, cli_key_pem) = gen_certs_pem();
    let mock_addr = start_mock_llm("mock-llm").await;

    let gw = Gateway::start(GatewayConfig {
        http_bind: "127.0.0.1:0".parse().unwrap(),
        quic_bind: "127.0.0.1:0".parse().unwrap(),
        ca_cert: parse_certs_pem(&ca_pem),
        server_cert: parse_certs_pem(&srv_pem),
        server_key: parse_key_pem(&srv_key_pem),
        api_keys: vec!["test-key".into()],
        admin_token: None,
        keys_file: None,
        request_timeout: Duration::from_secs(10),
        agent_stale_after: Duration::from_secs(10),
        rate_limit_per_min: 0,
        tls: Some(TlsPem {
            cert: srv_pem.clone().into_bytes(),
            key: srv_key_pem.clone().into_bytes(),
        }),
    })
    .await
    .unwrap();

    let agent = Agent::start(AgentConfig {
        cloud_addr: gw.quic_addr,
        server_name: "localhost".into(),
        ca_cert: parse_certs_pem(&ca_pem),
        client_cert: parse_certs_pem(&cli_pem),
        client_key: parse_key_pem(&cli_key_pem),
        agent_id: "test-agent".into(),
        models: vec!["mock-llm".into()],
        max_concurrency: 4,
        upstream_base: format!("http://{mock_addr}"),
        heartbeat_interval: Duration::from_millis(200),
    })
    .unwrap();
    wait_for_agents(&gw, 1, Duration::from_secs(10)).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let base = format!("https://{}", gw.http_addr);

    // healthz 与根路径（管理页）走 HTTPS
    let resp = client.get(format!("{base}/healthz")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // 无 key → 401
    let resp = client.get(format!("{base}/v1/models")).send().await.unwrap();
    assert_eq!(resp.status(), 401);

    // 认证请求穿透到 mock
    let resp = client
        .get(format!("{base}/v1/models"))
        .header("Authorization", "Bearer test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let models: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(models["data"][0]["id"], "mock-llm");

    // SSE 流式同样走 HTTPS
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", "Bearer test-key")
        .json(&serde_json::json!({
            "model": "mock-llm",
            "stream": true,
            "messages": [{"role": "user", "content": "https 流式"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert!(text.contains("data: [DONE]"), "missing [DONE]: {text}");

    agent.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_quic_control_stream_edge_frames() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (ca, server_cert, server_key, client_cert, client_key) = gen_certs();

    let gw = Gateway::start(GatewayConfig {
        http_bind: "127.0.0.1:0".parse().unwrap(),
        quic_bind: "127.0.0.1:0".parse().unwrap(),
        ca_cert: vec![ca.clone()],
        server_cert: vec![server_cert.clone()],
        server_key,
        api_keys: vec!["test-key".into()],
        admin_token: None,
        keys_file: None,
        request_timeout: Duration::from_secs(10),
        agent_stale_after: Duration::from_secs(10),
        rate_limit_per_min: 0,
        tls: None,
    })
    .await
    .unwrap();

    // 裸 quinn 客户端（复用 agent 的 mTLS 配置），不走 agent crate 逻辑
    let client_config =
        agent::tls::client_config(&[ca.clone()], vec![client_cert.clone()], client_key.clone_key())
            .unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    let conn = endpoint
        .connect(gw.quic_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // 控制流上发非预期帧（Cancel）→ 服务端走 "unexpected frame" 分支，连接不受影响
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    write_frame(&mut send, &Frame::Cancel { request_id: 1 })
        .await
        .unwrap();
    send.finish().unwrap();
    let _ = read_frame(&mut recv).await; // 等服务端 finish

    // 立即结束的空流 → 服务端走干净 EOF 分支
    let (mut send2, _recv2) = conn.open_bi().await.unwrap();
    send2.finish().unwrap();

    // 未注册 agent 的心跳 → registry 无害忽略
    let (mut send3, mut recv3) = conn.open_bi().await.unwrap();
    write_frame(
        &mut send3,
        &Frame::Heartbeat {
            agent_id: "ghost".into(),
            inflight: 0,
        },
    )
    .await
    .unwrap();
    send3.finish().unwrap();
    let _ = read_frame(&mut recv3).await;

    // 给服务端处理留时间；裸连接未发 Register，不应进入注册表
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(gw.agent_count(), 0, "unregistered connection must not register");
    gw.shutdown().await;
}
