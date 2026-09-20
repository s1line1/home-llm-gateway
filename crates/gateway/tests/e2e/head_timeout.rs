//! 响应头超时：**"被堵住的慢"不能当成"隧道已死"**。
//!
//! 背景（2026-09-18 云端实测）：云 ECS 出口只有 ≈0.40 MB/s。带宽一饱和，"一个响应头都收不到"，
//! 于是连续超时计数必然爬到阈值 → 摘除**健康但被堵住**的 agent → 关连接 → agent 重连
//! （退避最长 30s）→ 期间注册表为空 → **全量 503**。一次压测里 `upstream head timeout;
//! evicting agent` 1 026 次、`registry-empty` +3 753。
//!
//! 修法是把开流超时那套"忙≠死"的思路推广到响应头超时：窗口内有过成功响应头 → 只回 504、
//! 不计连续超时、不摘除；窗口内一次都没有 → 才算死。判据见 `registry::Entry::head_timeout_is_fatal`。
//!
//! 判据用**连接是否被摘除**来钉：摘除会关连接，被测 agent 随即重连，
//! `hlmg_agent_connections_total`（累计 agent 连接次数）就会 +1。

use super::common::*;

/// 规格：**上游慢过 `head_timeout`、但仍能正常回别的请求时，只许回 504，不许摘除 agent**。
///
/// 修好之前：3 次连续响应头超时就把连接摘掉并关闭 → agent 重连 → `hlmg_agent_connections_total`
/// 从 1 变 2，而且重连窗口里后续请求全是 503。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_slow_head_does_not_evict_an_agent_that_is_still_answering() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    // head_timeout 压到 400ms，上游 /v1/slow?ms=1500 必然超时；窗口是 4×head_timeout = 1.6s，
    // 所以期间"另一个正常请求成功"就足以证明它只是慢。
    let (gw, agent, base, key) = start_stack(4, |o| {
        o.head_timeout = Duration::from_millis(400);
        o.client_stall = Duration::from_secs(5);
    })
    .await;
    let client = reqwest::Client::new();
    let normal = || {
        client
            .post(format!("{base}/v1/chat/completions"))
            .header("Authorization", format!("Bearer {key}"))
            .json(&serde_json::json!({ "model": "mock-llm", "messages": [{"role":"user","content":"hi"}] }))
    };

    // 先确认链路是通的（也把"最近有过成功响应头"这条事实立起来）
    assert_eq!(normal().send().await.unwrap().status().as_u16(), 200);
    let connections_before = metric_gauge(&base, "hlmg_agent_connections_total").await;

    // 连续 3 次慢请求：每次都超过 head_timeout → 都该 504
    for i in 0..3 {
        let resp = client
            .post(format!("{base}/v1/slow?ms=1500"))
            .header("Authorization", format!("Bearer {key}"))
            .json(&serde_json::json!({ "model": "mock-llm" }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            504,
            "第 {} 次慢请求应当是 504（上游慢于 head_timeout）",
            i + 1
        );
        // 每次慢请求之间插一个正常请求：证明这条隧道"还在干活"
        assert_eq!(normal().send().await.unwrap().status().as_u16(), 200);
    }

    // ① 三次超时全部记为 slow（被堵住的慢），一次 silent 都不该有
    let text = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        text.contains("hlmg_upstream_head_timeouts_total{class=\"slow\"} 3"),
        "三次慢请求都该记成 slow：{text}"
    );
    assert!(
        !text.contains("hlmg_upstream_head_timeouts_total{class=\"silent\"}"),
        "期间一直在正常回响应头，不该出现 silent：{text}"
    );

    // ② 关键判据：连接没有被摘除（没有重连 = 没有关连接）
    let connections_after = metric_gauge(&base, "hlmg_agent_connections_total").await;
    assert_eq!(
        connections_after, connections_before,
        "agent 被摘除并重连了（连接次数 {connections_before} → {connections_after}）——慢被当成了死"
    );

    // ③ 后续请求仍然正常
    assert_eq!(normal().send().await.unwrap().status().as_u16(), 200);

    agent.shutdown().await;
    gw.shutdown().await;
}

/// 规格：**窗口内一次响应头都没有的 agent，仍然必须被判死并摘除**。
///
/// 这是上一条的反面：放宽判据不能把"真的坏了"也放过去，否则坏连接永远摘不掉，
/// 后续每个请求都要白等一个 `head_timeout`。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_silent_agent_is_still_evicted_after_the_window() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    // 窗口 = 4 × 100ms = 400ms：比 head_timeout 长，但足够短，测试里等得起。
    let (gw, agent, base, key) = start_stack(4, |o| {
        o.head_timeout = Duration::from_millis(100);
        o.client_stall = Duration::from_secs(5);
    })
    .await;
    let client = reqwest::Client::new();

    // 一个个慢请求打过去（每个都超过 head_timeout），中间**不做**任何成功请求，
    // 让沉默时间跨过 400ms 窗口；第 4 个之后应当已经判死 → 摘除 → 重连。
    let mut saw_silent = false;
    for _ in 0..6 {
        let resp = client
            .post(format!("{base}/v1/slow?ms=800"))
            .header("Authorization", format!("Bearer {key}"))
            .json(&serde_json::json!({ "model": "mock-llm" }))
            .send()
            .await
            .unwrap();
        assert!(
            matches!(resp.status().as_u16(), 502..=504),
            "慢请求应当失败，实际 {}",
            resp.status()
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
        let text = client
            .get(format!("{base}/metrics"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        if text.contains("hlmg_upstream_head_timeouts_total{class=\"silent\"}") {
            saw_silent = true;
            break;
        }
    }
    assert!(
        saw_silent,
        "沉默超过窗口之后必须出现 class=\"silent\"（否则坏连接永远摘不掉）"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}
