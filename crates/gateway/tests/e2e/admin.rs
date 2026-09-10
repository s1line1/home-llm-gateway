//! admin 场景 e2e 测试。

use super::common::*;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_admin_api_keys() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base, key) =
        start_stack(Duration::from_secs(10), 0, 4, Some("admin-token")).await;
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
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({"name": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "API keys must not unlock admin endpoints"
    );

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
    assert!(
        new_key.starts_with("sk-"),
        "generated key should have sk- prefix"
    );

    // 新 key 立即生效（运行时创建，无需重启）
    let resp = client
        .get(format!("{base}/v1/models"))
        .header("Authorization", format!("Bearer {new_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "runtime-created key should work immediately"
    );

    // 列表包含刚创建的 key（且不暴露明文）
    let resp = client
        .get(format!("{base}/admin/keys"))
        .header("Authorization", "Bearer admin-token")
        .send()
        .await
        .unwrap();
    let list: serde_json::Value = resp.json().await.unwrap();
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .any(|k| k["name"] == "dsh-client" && k["id"] == new_id),
        "list should contain the created key"
    );
    let list_text = serde_json::to_string(&list).unwrap();
    assert!(
        !list_text.contains(&new_key),
        "list must not leak full key secrets"
    );

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

/// 打真实 chat 请求 → mock 返回 usage {prompt:1, completion:1} → /admin/usage
/// 一致累计；/admin/keys 内嵌 usage；吊销 key 后用量记录仍保留（可审计）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_usage_metering() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base, key) =
        start_stack(Duration::from_secs(10), 0, 4, Some("admin-token")).await;
    let client = reqwest::Client::new();

    // 非流式 chat ×2（mock 每次返回 usage prompt 1 / completion 1）
    for _ in 0..2 {
        let resp = client
            .post(format!("{base}/v1/chat/completions"))
            .header("Authorization", format!("Bearer {key}"))
            .json(&serde_json::json!({
                "model": "mock-llm",
                "messages": [{ "role": "user", "content": "hi" }]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["usage"]["prompt_tokens"], 1, "mock returns usage");
    }

    // usage 记录异步结算（forward_body 结束写穿）→ 轮询等待两次请求落账
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let usage = loop {
        let resp = client
            .get(format!("{base}/admin/usage"))
            .header("Authorization", "Bearer admin-token")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let arr: serde_json::Value = resp.json().await.unwrap();
        if let Some(u) = arr
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["requests"].as_u64().unwrap_or(0) >= 2)
        {
            break u.clone();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "usage should be recorded within 5s: {arr}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    // mock 每次 prompt 1 + completion 1 → 两次共 2/2
    assert_eq!(usage["prompt_tokens"], 2, "prompt tokens accumulate");
    assert_eq!(
        usage["completion_tokens"], 2,
        "completion tokens accumulate"
    );
    assert_eq!(usage["total_tokens"], 4);
    assert_eq!(usage["requests"], 2);
    assert_eq!(
        usage["estimated_requests"], 0,
        "mock provides real usage, no estimation"
    );
    assert!(
        usage["last_used_at"].as_u64().unwrap() > 0,
        "last_used_at set"
    );

    // /admin/keys 内嵌 usage 与 /admin/usage 一致
    let keys: serde_json::Value = client
        .get(format!("{base}/admin/keys"))
        .header("Authorization", "Bearer admin-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let k = keys
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["name"] == "e2e")
        .unwrap();
    assert_eq!(k["usage"]["total_tokens"], 4, "keys list embeds usage");
    let id = k["id"].as_str().unwrap().to_string();

    // 吊销 key → usage 记录仍保留（独立表，可审计）
    let resp = client
        .delete(format!("{base}/admin/keys/{id}"))
        .header("Authorization", "Bearer admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let usage_after: serde_json::Value = client
        .get(format!("{base}/admin/usage"))
        .header("Authorization", "Bearer admin-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let kept = usage_after
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key_id"] == id);
    assert!(
        kept.is_some() && kept.unwrap()["requests"] == 2,
        "usage survives key revocation"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}

/// OpenAI 兼容错误语义：error.type 按状态码映射、429 带 Retry-After、
/// 每个响应带 x-request-id（SDK 兼容性，见 TODO P0）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_openai_error_semantics() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base, key) =
        start_stack(Duration::from_secs(10), 0, 4, Some("admin-token")).await;
    let client = reqwest::Client::new();

    // 401：无 key → authentication_error
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .json(&serde_json::json!({ "model": "mock-llm", "messages": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(
        resp.headers().get("x-request-id").is_some(),
        "every response carries x-request-id"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "authentication_error");

    // 400：body 无 model → invalid_request_error
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({ "messages": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "invalid_request_error");

    // 404：model 无 agent 服务 → not_found_error（mock-llm 声明了 mock-llm 模型）
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({ "model": "no-such-model", "messages": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "not_found_error");

    // 429：限流（每 key 1 次/分钟）→ rate_limit_error + Retry-After
    let (gw2, agent2, base2, key2) = start_stack(Duration::from_secs(10), 1, 4, None).await;
    let client2 = reqwest::Client::new();
    let req = || {
        client2
            .get(format!("{base2}/v1/models"))
            .header("Authorization", format!("Bearer {key2}"))
    };
    let _ = req().send().await.unwrap(); // 第 1 次放行
    let resp = req().send().await.unwrap(); // 第 2 次 429
    assert_eq!(resp.status(), 429);
    assert_eq!(
        resp.headers().get("retry-after").unwrap().to_str().unwrap(),
        "60",
        "429 must advertise Retry-After"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "rate_limit_error");

    // 5xx：裸起一个**无 agent** 的 gateway → 请求必然 NoAgent → 503 server_error
    let (ca, server_cert, server_key, _client_cert, _client_key) = gen_certs();
    let (keys_path, lone_key) = seed_keys_db();
    let gw3 = Gateway::start(GatewayConfig {
        http_bind: "127.0.0.1:0".parse().unwrap(),
        quic_bind: "127.0.0.1:0".parse().unwrap(),
        ca_cert: vec![ca],
        server_cert: vec![server_cert],
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
    let resp = client
        .post(format!("http://{}/v1/chat/completions", gw3.http_addr))
        .header("Authorization", format!("Bearer {lone_key}"))
        .json(&serde_json::json!({ "model": "mock-llm", "messages": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "server_error");
    gw3.shutdown().await;

    agent.shutdown().await;
    agent2.shutdown().await;
    gw.shutdown().await;
    gw2.shutdown().await;
}

/// 规格：用量落库**不得拖住响应流**。
///
/// 用独占锁把 keys.db 卡住（rusqlite 默认 busy timeout 5s，所以那次写会真的阻塞）：
/// 旧实现把落库放在响应流关闭之前，客户端要等到锁释放才拿到 body 结束；
/// 正确实现下客户端应立即拿到完整响应，落库在后台完成。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_usage_write_does_not_stall_the_response() {
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
        keys_file: Some(keys_path.clone()),
        request_timeout: Duration::from_secs(30),
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
        agent_id: "usage-lock-agent".into(),
        models: vec!["mock-llm".into()],
        max_concurrency: 4,
        upstream_base: format!("http://{mock_addr}"),
        heartbeat_interval: Duration::from_millis(200),
        request_log: false,
    })
    .unwrap();
    wait_for_agents(&gw, 1, Duration::from_secs(10)).await;

    // 后台线程取 keys.db 独占锁并保持 3s（BEGIN EXCLUSIVE 立即取锁）
    let (locked_tx, locked_rx) = std::sync::mpsc::channel::<()>();
    let holder_path = keys_path.clone();
    let holder = std::thread::spawn(move || {
        let conn = rusqlite::Connection::open(&holder_path).unwrap();
        conn.execute_batch("BEGIN EXCLUSIVE").unwrap();
        locked_tx.send(()).unwrap();
        std::thread::sleep(Duration::from_secs(3));
        let _ = conn.execute_batch("ROLLBACK");
    });
    locked_rx.recv().expect("锁已取得");

    let client = reqwest::Client::new();
    let base = format!("http://{}", gw.http_addr);
    let started = std::time::Instant::now();
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({
            "model": "mock-llm",
            "messages": [{ "role": "user", "content": "hi" }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap(); // ← 等 body 真正结束（chunked 终止符）
    let elapsed = started.elapsed();
    println!(
        "PROBE: 独占锁持有期间，客户端拿到完整响应用了 {elapsed:?}（body {} 字节）",
        body.len()
    );
    assert!(
        elapsed < Duration::from_millis(1500),
        "用量落库拖住了响应流：客户端等了 {elapsed:?}（锁只持有 3s）"
    );
    holder.join().unwrap();

    // 锁释放后必须最终落库（异步结算不能丢数据）
    let deadline = std::time::Instant::now() + Duration::from_secs(6);
    let mut persisted = false;
    while std::time::Instant::now() < deadline && !persisted {
        std::thread::sleep(Duration::from_millis(100));
        if let Ok(conn) = rusqlite::Connection::open(&keys_path) {
            persisted = conn
                .query_row(
                    "SELECT COALESCE(SUM(requests), 0) FROM key_usage",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .map(|n| n >= 1)
                .unwrap_or(false);
        }
    }
    println!("PROBE: 锁释放后用量是否最终落库 = {persisted}");
    assert!(persisted, "用量必须最终落库（异步结算不能丢数据）");

    agent.shutdown().await;
    gw.shutdown().await;
}
