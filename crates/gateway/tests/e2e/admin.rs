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
