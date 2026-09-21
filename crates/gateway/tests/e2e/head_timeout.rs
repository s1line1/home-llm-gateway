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
    let connections_before = metric_gauge(&base, "hlmg_agent_connections_total").await;

    // 一个个慢请求打过去（每个都超过 head_timeout），中间**不做**任何成功请求，
    // 让沉默时间跨过 400ms 窗口。
    //
    // ⚠️ **不能一看到 `class="silent"` 就收工**：这条连接**从未**回过响应头，所以第一次
    // 超时就已经判死（"从未有过"不给宽限，见 `Entry::head_timeout_is_fatal`），`silent`
    // 第一个请求就出现了。要验的是"**连续 3 次**（`TUNNEL_TIMEOUTS_BEFORE_EVICT`）之后
    // 真的摘除"，所以必须打满阈值以上。
    for i in 1..=4 {
        let resp = client
            .post(format!("{base}/v1/slow?ms=800"))
            .header("Authorization", format!("Bearer {key}"))
            .json(&serde_json::json!({ "model": "mock-llm" }))
            .send()
            .await
            .unwrap();
        assert!(
            matches!(resp.status().as_u16(), 502..=504),
            "第 {i} 次慢请求应当失败，实际 {}",
            resp.status()
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    let text = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        text.contains("hlmg_upstream_head_timeouts_total{class=\"silent\"}"),
        "沉默超过窗口之后必须出现 class=\"silent\"（否则坏连接永远摘不掉）：{text}"
    );

    // ⚠️ 光有 `class="silent"` **不足以**证明"真的摘除了"——一个"只加计数不摘除"的实现
    // 照样能让这个标签出现（这正是本用例原先的漏洞，见 `docs/PROJECT_SCAN.md` P2-16：
    // 它当时只断言状态码与标签，从没驱动到阈值、也没看连接计数）。
    // 摘除会关连接 → 被测 agent 察觉后重连 → `hlmg_agent_connections_total`（累计连接次数）+1。
    let mut reconnected = false;
    for _ in 0..40 {
        if metric_gauge(&base, "hlmg_agent_connections_total").await > connections_before {
            reconnected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(125)).await;
    }
    assert!(
        reconnected,
        "连续 3 次判死之后必须真的摘除并关闭连接（agent 重连 → 连接计数 +1，之前是 \
         {connections_before}）；只出现 class=\"silent\" 而连接计数不变，说明计了数却没摘"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}

/// 规格（判据第二层，评估 §5 H2）：**均匀慢流量不该摘掉一条还在心跳的 agent**。
///
/// 上一条用例的反面之所以成立，靠的是它"每次慢请求之间插一个正常请求"——也就是永远维持着
/// "窗口内有过成功响应头"这个前提。可一旦**所有**请求都慢过 `head_timeout`（大模型首字节慢、
/// 上游排队、链路被堵），就没有任何一次成功能刷新 `last_head_ok`，窗口必然走完 →
/// 一条活得好好的 agent 被摘除 → 关连接 → agent 重连 → 注册表为空 → 全量 503——
/// 正是这条判据本来要防的那条链（2026-09-18 实测过一次）。
///
/// 第二层的作用：对端还在发心跳 = 它还在说话，于是静默被宽限到 `head_silent_grace`
/// （默认一条请求的寿命）。本用例把该值留在 5s（远大于测试时长），于是这几次超时应当
/// **全部记 `slow`、一次 `silent` 都没有、也不该发生重连**。
///
/// 反过来说：修第二层之前，这些超时会被判死，第 3 次就摘除 → `silent` 出现 + 连接计数 +1，
/// 两条断言都会失败。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_uniformly_slow_traffic_does_not_evict_a_heartbeating_agent() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base, key) = start_stack(4, |o| {
        o.head_timeout = Duration::from_millis(100); // 窗口 = 4 × 100ms = 400ms
        o.client_stall = Duration::from_secs(5);
        // 第二层的上界给足：本例只验"对端活着就别误摘"，不验上界（上界由 registry 的单测钉）。
        o.head_silent_grace = Duration::from_secs(5);
    })
    .await;
    let client = reqwest::Client::new();

    // 先建立一个"最近成功过响应头"的事实（同时也让判据不走"从未回过"那条快路径）。
    let ok = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({ "model": "mock-llm", "messages": [{"role":"user","content":"hi"}] }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status().as_u16(), 200, "先要有一个成功请求");
    let connections_before = metric_gauge(&base, "hlmg_agent_connections_total").await;

    // 之后**只有慢请求**，中间不做任何成功请求——这就是"均匀慢流量"的形状。
    // 每个都在 100ms 后超时（上游 3s 才回），累计沉默很快跨过 400ms 窗口。
    for i in 1..=4 {
        let resp = client
            .post(format!("{base}/v1/slow?ms=3000"))
            .header("Authorization", format!("Bearer {key}"))
            .json(&serde_json::json!({ "model": "mock-llm" }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            504,
            "第 {i} 次慢请求应当 504（上游慢过 head_timeout）"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    let text = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        !text.contains("hlmg_upstream_head_timeouts_total{class=\"silent\"}"),
        "对端一直在心跳、静默也远未超过 head_silent_grace，不该出现 silent（误摘）：{text}"
    );
    assert!(
        text.contains("hlmg_upstream_head_timeouts_total{class=\"slow\"}"),
        "这些超时应当全部记成 slow（被堵住的慢）：{text}"
    );
    assert_eq!(
        metric_gauge(&base, "hlmg_agent_connections_total").await,
        connections_before,
        "agent 被摘除并重连了（连接次数 {connections_before} → 更多）——均匀慢流量被当成了死"
    );
    assert_eq!(
        gw.agent_count(),
        1,
        "均匀慢流量下条目必须还在路由里（第二层把它判成「慢」）"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}
