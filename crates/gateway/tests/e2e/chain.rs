//! chain 场景 e2e 测试。

use super::common::*;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_chain_with_mock_llm() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base, key) = start_stack(Duration::from_secs(10), 0, 4, None).await;
    let client = reqwest::Client::new();

    // 无认证 → 401
    let resp = client
        .get(format!("{base}/v1/models"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "missing api key must be rejected");

    // healthz 无需认证
    let resp = client.get(format!("{base}/healthz")).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // 根路径：未配置 ui_dir 时返回 UI 构建提示页（HTML，不再内嵌管理页）
    let resp = client.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let page = resp.text().await.unwrap();
    assert!(
        page.contains("Home LLM Gateway"),
        "root should serve the UI placeholder"
    );
    assert!(
        page.contains("尚未构建"),
        "placeholder should mention building the UI"
    );
    assert!(
        page.starts_with("<!doctype html>"),
        "placeholder should be HTML"
    );

    // 认证后 /v1/models 穿透到 mock
    let resp = client
        .get(format!("{base}/v1/models"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let models: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(models["data"][0]["id"], "mock-llm");

    // chat completions 全链路（非流式）
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
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
        .header("Authorization", format!("Bearer {key}"))
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
#[serial]
async fn e2e_sse_streaming_passthrough() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base, key) = start_stack(Duration::from_secs(10), 0, 4, None).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
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
    assert!(
        data_lines >= 3,
        "expected multiple SSE events, got {data_lines}: {text}"
    );
    assert!(
        text.contains("data: [DONE]"),
        "missing [DONE] terminator: {text}"
    );
    assert!(
        text.contains(r#""content":"流""#) && text.contains(r#""content":"试""#),
        "SSE should stream the echoed content per char: {text}"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_gateway_timeout_cancels_upstream() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    // 网关空闲超时 150ms，而 mock 的 /v1/slow 要睡 800ms 才响应 → 应触发超时 + Cancel
    let (gw, agent, base, key) = start_stack(Duration::from_millis(150), 0, 4, None).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/v1/slow"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({ "model": "mock-llm" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        504,
        "slow upstream should be cut off by idle timeout"
    );

    // Cancel 不应影响 agent 连接本身，之后仍能正常服务（/v1/models 由网关聚合回答）
    let resp = client
        .get(format!("{base}/v1/models"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["object"], "list");
    assert_eq!(
        body["data"][0]["id"], "mock-llm",
        "healthy agent's declared model should be listed"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_client_disconnect_cancels_upstream() {
    use futures_util::StreamExt;

    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base, key) = start_stack(Duration::from_secs(10), 0, 4, None).await;
    let client = reqwest::Client::new();

    // 发起 SSE 流式请求，读到一个 chunk 后直接丢弃响应（模拟客户端断开）
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({
            "model": "mock-llm",
            "stream": true,
            "messages": [{"role": "user", "content": "断开测试"}]
        }))
        .send()
        .await
        .unwrap();
    let mut stream = resp.bytes_stream();
    let _first = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("first SSE chunk within 5s")
        .unwrap()
        .unwrap();
    drop(stream); // 客户端断开 → 网关通道接收端被丢弃 → 发 Cancel

    // 给网关发 Cancel、agent 取消上游留时间
    tokio::time::sleep(Duration::from_millis(600)).await;

    // 网关仍可用
    let r = client
        .get(format!("{base}/v1/models"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    agent.shutdown().await;
    gw.shutdown().await;
}

/// 规格：调用方的凭据**不得**出现在上游收到的请求里。
///
/// 在**上游侧**观察，因此覆盖 网关 → 隧道帧 → agent → 上游 整条链路（而不只是网关
/// 自己的过滤函数）。客户端持有的是网关签发的 API key（对全部模型有效、能打公网网关），
/// 而 edge / 上游属于另一个信任域、三种上游（Ollama/vLLM/llama.cpp）都不认证——透传
/// 零收益纯风险：edge 一旦被攻破，攻击者白得一把可用的公网凭据，且 edge / 上游日志里
/// 会留下吊销不掉的副本。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_upstream_never_receives_client_credentials() {
    use std::sync::{Arc, Mutex};

    /// 记录收到的头名的假上游（只需要能应答一个 OpenAI 形状的响应）。
    #[derive(Clone)]
    struct Capture {
        seen: Arc<Mutex<Vec<String>>>,
    }
    async fn capture_chat(
        axum::extract::State(st): axum::extract::State<Capture>,
        headers: axum::http::HeaderMap,
    ) -> axum::Json<serde_json::Value> {
        let mut names: Vec<String> = headers.keys().map(|k| k.as_str().to_string()).collect();
        names.sort();
        st.seen.lock().unwrap().extend(names);
        axum::Json(serde_json::json!({
            "id": "chatcmpl-capture",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": "ok" },
                "finish_reason": "stop"
            }],
            "usage": { "prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2 }
        }))
    }

    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (ca, server_cert, server_key, client_cert, client_key) = gen_certs();
    let (keys_path, key) = seed_keys_db();

    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let app = axum::Router::new()
        .route("/v1/chat/completions", axum::routing::post(capture_chat))
        .with_state(Capture {
            seen: Arc::clone(&seen),
        });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

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

    let agent = Agent::start(AgentConfig {
        cloud_addr: gw.quic_addr,
        server_name: "localhost".into(),
        ca_cert: vec![ca.clone()],
        client_cert: vec![client_cert.clone()],
        client_key,
        agent_id: "cred-agent".into(),
        models: vec!["mock-llm".into()],
        max_concurrency: 4,
        upstream_base: format!("http://{upstream_addr}"),
        heartbeat_interval: Duration::from_millis(200),
        request_log: false,
    })
    .unwrap();
    wait_for_agents(&gw, 1, Duration::from_secs(10)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", gw.http_addr))
        .header("Authorization", format!("Bearer {key}"))
        .header("Cookie", "session=topsecret")
        .header("X-Custom-Trace", "keep-me")
        .json(&serde_json::json!({
            "model": "mock-llm",
            "messages": [{ "role": "user", "content": "hi" }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "整条链路应当正常");

    let names = seen.lock().unwrap().clone();
    println!("PROBE: 上游收到的头名 = {names:?}");
    assert!(
        names.contains(&"x-custom-trace".to_string()),
        "普通业务头应当照旧转发到上游: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n == "authorization"),
        "上游不得收到调用方的 Authorization（网关自己的 API key）: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n == "cookie"),
        "上游不得收到调用方的 Cookie: {names:?}"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}
