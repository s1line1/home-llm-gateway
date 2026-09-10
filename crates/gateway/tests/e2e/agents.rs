//! agents 场景 e2e 测试。

use super::common::*;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_admission_control() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    // agent max_concurrency=1：两个并发慢请求，一个 200、一个 429；完成后槽位释放
    let (gw, agent, base, key) = start_stack(Duration::from_secs(10), 0, 1, None).await;
    let client = reqwest::Client::new();
    let url = format!("{base}/v1/slow");
    let req = || {
        client
            .post(&url)
            .header("Authorization", format!("Bearer {key}"))
            .json(&serde_json::json!({ "model": "mock-llm" }))
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
    assert_eq!(
        resp.status(),
        200,
        "slot should be released after completion"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_multi_agent_least_loaded() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (ca, server_cert, server_key, client_cert, client_key) = gen_certs();
    let mock_a = start_mock_llm("mock-a").await;
    let mock_b = start_mock_llm("mock-b").await;
    let (keys_path, key) = seed_keys_db();

    let gw = Gateway::start(GatewayConfig {
        http_bind: "127.0.0.1:0".parse().unwrap(),
        quic_bind: "127.0.0.1:0".parse().unwrap(),
        ca_cert: vec![ca.clone()],
        server_cert: vec![server_cert.clone()],
        server_key,
        admin_token: None,
        keys_file: Some(keys_path),
        request_timeout: Duration::from_secs(10),
        agent_stale_after: Duration::from_secs(10),
        rate_limit_per_min: 0,
        max_concurrent_requests: 0,
        tls: None,
        ui_dir: None,
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
            request_log: true,
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
            .header("Authorization", format!("Bearer {key}"))
            .json(&serde_json::json!({ "model": "mock-llm" }))
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
    assert_ne!(
        servers[0], servers[1],
        "concurrent requests should be spread across agents"
    );
    assert!(
        servers.iter().all(|s| s == "mock-a" || s == "mock-b"),
        "unexpected upstream: {servers:?}"
    );

    agent_a.shutdown().await;
    agent_b.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_rate_limit_per_key() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    // 每分钟 5 次：前 5 个请求放行，第 6 个 429
    let (gw, agent, base, key) = start_stack(Duration::from_secs(10), 5, 4, None).await;
    let client = reqwest::Client::new();

    for i in 0..5 {
        let resp = client
            .get(format!("{base}/v1/models"))
            .header("Authorization", format!("Bearer {key}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "request {i} should pass the limit");
    }
    let resp = client
        .get(format!("{base}/v1/models"))
        .header("Authorization", format!("Bearer {key}"))
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

/// 双 edge 异构模型：按请求 model 路由到能服务它的 agent（同模型内最少负载），
/// /v1/models 网关聚合（不含 "*"、不含失联 agent），模型均不可路由 → 404。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_model_routing_and_models_endpoint() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (ca, server_cert, server_key, client_cert, client_key) = gen_certs();
    let mock_qwen = start_mock_llm("mock-qwen").await;
    let mock_llama = start_mock_llm("mock-llama").await;
    let (keys_path, key) = seed_keys_db();

    let gw = Gateway::start(GatewayConfig {
        http_bind: "127.0.0.1:0".parse().unwrap(),
        quic_bind: "127.0.0.1:0".parse().unwrap(),
        ca_cert: vec![ca.clone()],
        server_cert: vec![server_cert.clone()],
        server_key,
        admin_token: None,
        keys_file: Some(keys_path),
        request_timeout: Duration::from_secs(10),
        agent_stale_after: Duration::from_secs(10),
        rate_limit_per_min: 0,
        max_concurrent_requests: 0,
        tls: None,
        ui_dir: None,
    })
    .await
    .unwrap();

    let mk_agent = |agent_id: &str, models: Vec<&str>, upstream: SocketAddr| {
        Agent::start(AgentConfig {
            cloud_addr: gw.quic_addr,
            server_name: "localhost".into(),
            ca_cert: vec![ca.clone()],
            client_cert: vec![client_cert.clone()],
            client_key: client_key.clone_key(),
            agent_id: agent_id.into(),
            models: models.into_iter().map(String::from).collect(),
            max_concurrency: 1,
            upstream_base: format!("http://{upstream}"),
            heartbeat_interval: Duration::from_millis(200),
            request_log: false,
        })
        .unwrap()
    };
    let agent_qwen = mk_agent("edge-qwen", vec!["qwen2.5-72b"], mock_qwen);
    let agent_llama = mk_agent("edge-llama", vec!["llama3-70b", "*"], mock_llama);
    wait_for_agents(&gw, 2, Duration::from_secs(10)).await;

    let client = reqwest::Client::new();
    let base = format!("http://{}", gw.http_addr);
    let post_model = |model: &str| {
        client
            .post(format!("{base}/v1/chat/completions"))
            .header("Authorization", format!("Bearer {key}"))
            .json(&serde_json::json!({ "model": model, "messages": [] }))
    };

    // qwen2.5-72b → 只命中 edge-qwen（edge-llama 虽健康但不声明该模型）
    let resp = post_model("qwen2.5-72b").send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["server"], "mock-qwen", "must route to qwen edge");

    // llama3-70b → edge-llama（含 "*" 的 agent 也能服务）
    let resp = post_model("llama3-70b").send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["server"], "mock-llama", "must route to llama edge");

    // 通配兜底：mistral-7b 无 edge 精确声明，但 edge-llama 含 "*" → 由它服务
    // （404 model-not-found 的纯逻辑已在 registry 单测覆盖：无通配且无精确时）
    let resp = post_model("mistral-7b").send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["server"], "mock-llama",
        "unclaimed model should fall back to wildcard edge"
    );

    // /v1/models 聚合：qwen2.5-72b 与 llama3-70b 都列出，但 "*" 不贡献条目
    let resp = client
        .get(format!("{base}/v1/models"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let models: serde_json::Value = resp.json().await.unwrap();
    let ids: Vec<String> = models["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap().to_string())
        .collect();
    assert!(
        ids.contains(&"qwen2.5-72b".to_string()) && ids.contains(&"llama3-70b".to_string()),
        "aggregated model list missing declared models: {ids:?}"
    );
    assert!(
        !ids.contains(&"*".to_string()),
        "wildcard must not be listed"
    );

    // 无 model 的请求 → 400 model is required
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({ "messages": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    agent_qwen.shutdown().await;
    agent_llama.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_admin_agents_lists_registry() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base, _key) =
        start_stack(Duration::from_secs(10), 0, 4, Some("admin-token")).await;
    let client = reqwest::Client::new();

    // 无 admin token → 401
    let resp = client
        .get(format!("{base}/admin/agents"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "agent list requires admin token");

    // 带 admin token → 明细（已注册 1 个 agent：test-agent, mock-llm, 容量 4）
    let resp = client
        .get(format!("{base}/admin/agents"))
        .header("Authorization", "Bearer admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let agents: serde_json::Value = resp.json().await.unwrap();
    let arr = agents.as_array().expect("should be an array");
    assert_eq!(arr.len(), 1, "one agent should be registered");
    assert_eq!(arr[0]["agent_id"], "test-agent");
    assert_eq!(arr[0]["models"][0], "mock-llm");
    assert_eq!(arr[0]["max_concurrency"], 4);
    assert_eq!(arr[0]["inflight"], 0);
    assert!(
        arr[0]["last_seen_secs_ago"].as_u64().unwrap() < 5,
        "agent just heartbeated"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}

/// 客户端取消在途请求（真实路径：连接断开 → 请求 future 被 drop）**不得**泄漏
/// 全局并发槽位。回归：释放原先只挂在中间件尾部，取消会让尾部永不执行 → 槽位永久
/// 占住，此后所有请求（含 /healthz）被 429，只能重启网关。
///
/// 用 `/v1/slow`（上游 800ms 才回响应头）保证取消必然落在 gateway parked 于
/// `read_head` 的窗口内——即"用户取消一个首 token 很慢的 LLM 请求"这一最常见形态。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_client_cancel_does_not_leak_concurrency_slot() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (ca, server_cert, server_key, client_cert, client_key) = gen_certs();
    let mock_addr = start_mock_llm("mock-llm").await;
    let (keys_path, key) = seed_keys_db();

    let gw = Gateway::start(GatewayConfig {
        http_bind: "127.0.0.1:0".parse().unwrap(),
        quic_bind: "127.0.0.1:0".parse().unwrap(),
        ca_cert: vec![ca.clone()],
        server_cert: vec![server_cert.clone()],
        server_key,
        admin_token: None,
        keys_file: Some(keys_path),
        request_timeout: Duration::from_secs(30),
        agent_stale_after: Duration::from_secs(10),
        rate_limit_per_min: 0,
        max_concurrent_requests: 1,
        tls: None,
        ui_dir: None,
    })
    .await
    .unwrap();

    let agent = Agent::start(AgentConfig {
        cloud_addr: gw.quic_addr,
        server_name: "localhost".into(),
        ca_cert: vec![ca.clone()],
        client_cert: vec![client_cert.clone()],
        client_key,
        agent_id: "cancel-agent".into(),
        models: vec!["mock-llm".into()],
        max_concurrency: 4,
        upstream_base: format!("http://{mock_addr}"),
        heartbeat_interval: Duration::from_millis(200),
        request_log: false,
    })
    .unwrap();
    wait_for_agents(&gw, 1, Duration::from_secs(10)).await;

    let base = format!("http://{}", gw.http_addr);
    let client = reqwest::Client::new();

    // 发起请求后 150ms 放弃 → 网关此刻仍 parked 在 read_head（上游 800ms 才回头）
    let cancelled = tokio::time::timeout(
        Duration::from_millis(150),
        client
            .post(format!("{base}/v1/slow"))
            .header("Authorization", format!("Bearer {key}"))
            .json(&serde_json::json!({ "model": "mock-llm" }))
            .send(),
    )
    .await;
    assert!(cancelled.is_err(), "client must give up before headers");

    // 等上游那 800ms 走完，确保不是"还没到点"造成的假绿
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // 用户可见契约：后续请求不得因取消而 429
    let resp = client.get(format!("{base}/healthz")).send().await.unwrap();
    assert_eq!(
        resp.status(),
        200,
        "cancel of an in-flight request leaked the global concurrency slot"
    );

    // 指标侧：在途数必须回到 0
    let text = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let active: u64 = text
        .lines()
        .find(|l| l.starts_with("hlmg_active_requests "))
        .expect("hlmg_active_requests present")
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        active, 0,
        "in-flight gauge must return to zero after cancel"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}

/// 流式回传期间全局并发槽位**必须仍被占用**：SSE 首字节返回后 body 还在流，
/// 此刻 `max_concurrent_requests` 超限的请求必须 429；流结束后槽位才释放。
///
/// 回归：准入原先在 handler 返回 Response 时就释放 → 闸门只覆盖到"首字节"，
/// 恰好在 LLM 长流这个主场景上失效（`hlmg_active_requests` 也系统性偏低）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_streaming_holds_concurrency_slot_until_body_ends() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (ca, server_cert, server_key, client_cert, client_key) = gen_certs();
    let mock_addr = start_mock_llm("mock-llm").await;
    let (keys_path, key) = seed_keys_db();

    let gw = Gateway::start(GatewayConfig {
        http_bind: "127.0.0.1:0".parse().unwrap(),
        quic_bind: "127.0.0.1:0".parse().unwrap(),
        ca_cert: vec![ca.clone()],
        server_cert: vec![server_cert.clone()],
        server_key,
        admin_token: None,
        keys_file: Some(keys_path),
        request_timeout: Duration::from_secs(30),
        agent_stale_after: Duration::from_secs(10),
        rate_limit_per_min: 0,
        max_concurrent_requests: 1,
        tls: None,
        ui_dir: None,
    })
    .await
    .unwrap();

    let agent = Agent::start(AgentConfig {
        cloud_addr: gw.quic_addr,
        server_name: "localhost".into(),
        ca_cert: vec![ca.clone()],
        client_cert: vec![client_cert.clone()],
        client_key,
        agent_id: "stream-agent".into(),
        models: vec!["mock-llm".into()],
        max_concurrency: 4,
        upstream_base: format!("http://{mock_addr}"),
        heartbeat_interval: Duration::from_millis(200),
        request_log: false,
    })
    .unwrap();
    wait_for_agents(&gw, 1, Duration::from_secs(10)).await;

    let base = format!("http://{}", gw.http_addr);
    let client = reqwest::Client::new();

    // mock 的 SSE 逐字输出（10ms/字）：200 字 ≈ 2s 流，足够在流中做断言
    let stream_resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({
            "model": "mock-llm",
            "stream": true,
            "messages": [{ "role": "user", "content": "x".repeat(200) }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(stream_resp.status(), 200, "streaming request admitted");

    // ★ 关键：此时 body 仍在流式回传（约 2s 中的前 300ms）
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 在途指标必须仍计入这个流式请求
    assert_eq!(
        fetch_active(&client, &base).await,
        1,
        "in-flight gauge must count a request whose body is still streaming"
    );

    // 闸门必须仍然生效：超限的第二个请求 429（"慢请求占住闸门"正是本特性目的）
    let second = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({
            "model": "mock-llm",
            "messages": [{ "role": "user", "content": "hi" }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        429,
        "limit=1 must reject while the first response body is still streaming"
    );

    // 排空流 → 槽位应随之释放（允许极短的传播延迟，故轮询而非即时断言）
    let _ = stream_resp.bytes().await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut active = fetch_active(&client, &base).await;
    while active != 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        active = fetch_active(&client, &base).await;
    }
    assert_eq!(active, 0, "slot must be released once the body has ended");

    // 且后续请求恢复正常
    let after = client.get(format!("{base}/healthz")).send().await.unwrap();
    assert_eq!(after.status(), 200, "slot released after stream end");

    agent.shutdown().await;
    gw.shutdown().await;
}

/// 流式中途放弃（用户看着打字机输出到一半点"停止"，最常见的取消形态）也必须归还槽位。
///
/// 与 parked 阶段取消（`e2e_client_cancel_...`）不同，这里请求已进入流式回传，
/// 槽位由 response body 持有——客户端断开时 body 被丢弃，槽位应随之释放。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_mid_stream_cancel_releases_concurrency_slot() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (ca, server_cert, server_key, client_cert, client_key) = gen_certs();
    let mock_addr = start_mock_llm("mock-llm").await;
    let (keys_path, key) = seed_keys_db();

    let gw = Gateway::start(GatewayConfig {
        http_bind: "127.0.0.1:0".parse().unwrap(),
        quic_bind: "127.0.0.1:0".parse().unwrap(),
        ca_cert: vec![ca.clone()],
        server_cert: vec![server_cert.clone()],
        server_key,
        admin_token: None,
        keys_file: Some(keys_path),
        request_timeout: Duration::from_secs(30),
        agent_stale_after: Duration::from_secs(10),
        rate_limit_per_min: 0,
        max_concurrent_requests: 1,
        tls: None,
        ui_dir: None,
    })
    .await
    .unwrap();

    let agent = Agent::start(AgentConfig {
        cloud_addr: gw.quic_addr,
        server_name: "localhost".into(),
        ca_cert: vec![ca.clone()],
        client_cert: vec![client_cert.clone()],
        client_key,
        agent_id: "midstream-agent".into(),
        models: vec!["mock-llm".into()],
        max_concurrency: 4,
        upstream_base: format!("http://{mock_addr}"),
        heartbeat_interval: Duration::from_millis(200),
        request_log: false,
    })
    .unwrap();
    wait_for_agents(&gw, 1, Duration::from_secs(10)).await;

    let base = format!("http://{}", gw.http_addr);
    let client = reqwest::Client::new();

    // 拿到响应头即开始流式回传（200 字 ≈ 2s）
    let stream_resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({
            "model": "mock-llm",
            "stream": true,
            "messages": [{ "role": "user", "content": "x".repeat(200) }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(stream_resp.status(), 200);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        fetch_active(&client, &base).await,
        1,
        "slot held while streaming"
    );

    // 中途放弃：只读一小段就丢掉响应体（模拟用户点"停止"）
    let mut partial = stream_resp;
    let _ = partial.chunk().await;
    drop(partial);

    // 槽位应随 body 丢弃而释放（轮询容忍传播延迟）
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut active = fetch_active(&client, &base).await;
    while active != 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        active = fetch_active(&client, &base).await;
    }
    assert_eq!(active, 0, "mid-stream cancel must release the slot");

    let resp = client.get(format!("{base}/healthz")).send().await.unwrap();
    assert_eq!(resp.status(), 200, "gateway usable after mid-stream cancel");

    agent.shutdown().await;
    gw.shutdown().await;
}

/// 读 `/metrics` 的 `hlmg_active_requests` 当前值。
async fn fetch_active(client: &reqwest::Client, base: &str) -> u64 {
    let text = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    text.lines()
        .find(|l| l.starts_with("hlmg_active_requests "))
        .expect("hlmg_active_requests present")
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

/// HTTP 全局并发上限（max_concurrent_requests=1）：并发两个慢请求 → 一个 200、
/// 一个 429（防多 key 总和压垮单实例，见 TODO P1 B 档）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_http_concurrent_request_limit() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (ca, server_cert, server_key, client_cert, client_key) = gen_certs();
    let mock_addr = start_mock_llm("mock-llm").await;
    let (keys_path, key) = seed_keys_db();

    let gw = Gateway::start(GatewayConfig {
        http_bind: "127.0.0.1:0".parse().unwrap(),
        quic_bind: "127.0.0.1:0".parse().unwrap(),
        ca_cert: vec![ca.clone()],
        server_cert: vec![server_cert.clone()],
        server_key,
        admin_token: None,
        keys_file: Some(keys_path),
        request_timeout: Duration::from_secs(10),
        agent_stale_after: Duration::from_secs(10),
        rate_limit_per_min: 0,
        max_concurrent_requests: 1,
        tls: None,
        ui_dir: None,
    })
    .await
    .unwrap();

    let agent = Agent::start(AgentConfig {
        cloud_addr: gw.quic_addr,
        server_name: "localhost".into(),
        ca_cert: vec![ca.clone()],
        client_cert: vec![client_cert.clone()],
        client_key: client_key.clone_key(),
        agent_id: "limit-agent".into(),
        models: vec!["mock-llm".into()],
        max_concurrency: 4,
        upstream_base: format!("http://{mock_addr}"),
        heartbeat_interval: Duration::from_millis(200),
        request_log: false,
    })
    .unwrap();
    wait_for_agents(&gw, 1, Duration::from_secs(10)).await;

    let client = reqwest::Client::new();
    let url = format!("http://{}/v1/slow", gw.http_addr); // mock 睡 800ms → 并发窗口大
    let req = || {
        client
            .post(&url)
            .header("Authorization", format!("Bearer {key}"))
            .json(&serde_json::json!({ "model": "mock-llm" }))
    };

    // 两个并发慢请求：limit=1 → 恰一个 200、一个 429
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
        "global concurrent limit=1 should admit exactly one in-flight request"
    );
    let _ = ra.bytes().await;
    let _ = rb.bytes().await;

    agent.shutdown().await;
    gw.shutdown().await;
}
