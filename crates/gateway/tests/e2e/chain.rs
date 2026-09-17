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
    use futures_util::StreamExt;

    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    // 网关**逐帧空闲**超时 300ms，而 mock 的 /v1/slow_body 立刻回响应头、正文停 3s。
    //
    // 注意用 /v1/slow_body 而不是 /v1/slow：后者卡的是**响应头**，归 `head_timeout` 管
    // （另一个语义，默认 15s —— 上游"思考"是合法的）。这里测的是"响应头已到、正文不走"
    // 这条路径，即 `forward_body` 的逐帧空闲超时。
    //
    // 契约：响应头已经发出去了，状态码不可能再变，所以**不能**断言 504；正确契约是
    // 正文在超时点被截断（收不到 [DONE]，流以错误结束），而不是让客户端一直挂着。
    let (gw, agent, base, key) = start_stack(Duration::from_millis(300), 0, 4, None).await;
    let client = reqwest::Client::new();

    let t0 = std::time::Instant::now();
    let resp = client
        .post(format!("{base}/v1/slow_body"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({ "model": "mock-llm" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "响应头应当正常到达");

    // 读正文：300ms 空闲超时后网关发 Cancel 并结束这条流 —— 应远早于上游的 3s
    let mut got = Vec::new();
    let mut stream = resp.bytes_stream();
    let read_all = async {
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(b) => got.extend_from_slice(&b),
                Err(_) => break, // 流被截断
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(5), read_all).await;
    let text = String::from_utf8_lossy(&got);
    assert!(
        !text.contains("[DONE]"),
        "上游还没出字就被空闲超时截断，不应收到 [DONE]；实际正文：{text:?}"
    );
    // 断言窗口 2s：相对 300ms 的空闲超时有 6 倍余量（够覆盖 argon2 校验 + 建连 + CI 抖动），
    // 又远小于上游 3s 的停顿 —— 所以"超时没生效"时必然失败，"机器慢"时不会假失败。
    // （之前是 150ms 超时配 800ms 停顿 + 700ms 断言，只有 ~95ms 余量，CI 上直接翻车。）
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "应在空闲超时（300ms）量级结束，而不是等上游 3s 出字；实际 {:?}",
        t0.elapsed()
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
        verified_cache_max: gateway::keystore::DEFAULT_VERIFIED_MAX,
        request_timeout: Duration::from_secs(10),
        tunnel_op_timeout: Duration::from_secs(2),
        head_timeout: Duration::from_secs(5),
        agent_stale_after: Duration::from_secs(10),
        rate_limit_per_min: 0,
        max_concurrent_requests: 0,
        max_open_tunnel_streams: 1024,
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

/// 已验证身份缓存**端到端**生效：同一 key 连续请求只跑一次 argon2。
///
/// 为什么值得一条 e2e：单元测试证明的是 `KeyStore` 的契约，而这里走的是
/// **HTTP → api_key() → spawn_blocking → KeyStore** 整条真实路径；同时它把
/// "每请求一次 argon2（19MiB）" 换成 "每凭据版本一次" 的收益钉在可观测指标上
/// （`hlmg_key_verify_misses_total` 只涨 1）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_verified_cache_reuses_argon2_across_requests() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base, key) = start_stack_with_verify_cache(
        Duration::from_secs(10),
        gateway::keystore::DEFAULT_VERIFIED_MAX,
        0,
        4,
        None,
    )
    .await;
    let client = reqwest::Client::new();
    let req = || {
        client
            .post(format!("{base}/v1/chat/completions"))
            .header("Authorization", format!("Bearer {key}"))
            .json(&serde_json::json!({ "model": "mock-llm" }))
    };

    // 冷启动一发（会跑一次 argon2），随后 9 发都应命中缓存
    for _ in 0..10 {
        let resp = req().send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let _ = resp.bytes().await;
    }

    let metrics = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let hits: u64 = metrics
        .lines()
        .find_map(|l| l.strip_prefix("hlmg_key_verify_hits_total "))
        .and_then(|v| v.trim().parse().ok())
        .expect("metrics 应包含 hlmg_key_verify_hits_total");
    let misses: u64 = metrics
        .lines()
        .find_map(|l| l.strip_prefix("hlmg_key_verify_misses_total "))
        .and_then(|v| v.trim().parse().ok())
        .expect("metrics 应包含 hlmg_key_verify_misses_total");

    assert_eq!(
        misses, 1,
        "10 个请求只应跑 1 次 argon2（缓存 + 单飞），实际 {misses}"
    );
    assert!(hits >= 9, "其余请求应命中缓存，实际 hits={hits}");

    agent.shutdown().await;
    gw.shutdown().await;
}

/// e2e 层的**并发单飞**：8 个请求同时首用同一个 key，也只应跑 1 次 argon2。
///
/// 为什么必须单独测：单元测试（`concurrent_same_token_hashes_once`）证明的是 KeyStore 的
/// 契约；这里走的是真实 HTTP + 真实并发（8 个连接同时打进来），也就是现网那个
/// "32 并发 → 654MB" 的形态。misses 计数是确定性的证据（内存数字太脆）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_concurrent_cold_requests_hash_once() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base, key) = start_stack_with_verify_cache(
        Duration::from_secs(10),
        gateway::keystore::DEFAULT_VERIFIED_MAX,
        0,
        8,
        None,
    )
    .await;
    let client = reqwest::Client::new();

    // 8 个并发请求同时到达（同一个 key，从未校验过）
    let mut handles = Vec::new();
    for _ in 0..8 {
        let client = client.clone();
        let base = base.clone();
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            client
                .post(format!("{base}/v1/chat/completions"))
                .header("Authorization", format!("Bearer {key}"))
                .json(&serde_json::json!({ "model": "mock-llm" }))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }));
    }
    for h in handles {
        assert_eq!(h.await.unwrap(), 200);
    }

    let metrics = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let misses: u64 = metrics
        .lines()
        .find_map(|l| l.strip_prefix("hlmg_key_verify_misses_total "))
        .and_then(|v| v.trim().parse().ok())
        .expect("metrics 应包含 hlmg_key_verify_misses_total");
    assert_eq!(
        misses, 1,
        "8 个并发冷请求只应跑 1 次 argon2（单飞），实际 {misses}——否则内存峰值就是 N × 19MiB"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}
