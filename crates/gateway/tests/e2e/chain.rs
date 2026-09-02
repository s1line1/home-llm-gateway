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
