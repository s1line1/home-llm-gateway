//! 写帧背压：注册后**不读请求流**的 agent 会让网关的 `tunnel_write` 撑爆流控窗口而超时。
//!
//! 触发方式（本模块先用一个不带断言的实验确认过，再固化成下面的规格测试）：
//! 裸 QUIC agent 注册成功后**绝不读**任何请求流 + 单帧 `ProxyRequest` body 取 8 MiB +
//! 小 `tunnel_op_timeout` → `write_frame` 在超时量级内刷不完 → `tunnel_write` 返回 `TimedOut`。
//! 关键点是 body 必须大到超过对端 QUIC 流控窗口：小 body 会被缓冲、写"成功"，失败就落到
//! 等响应头（504）而不是写（502）——现有 `e2e_dead_tunnel_fails_fast_instead_of_hanging`
//! 正是后者。
//!
//! 背景（并集报告 H1）：`routing.rs` 的写帧臂原本无条件 `evict`，与开流臂的 busy 判据不对称——
//! 写超时会把健康但拥塞的 agent 摘除，触发 `registry-empty` 的全量 503。修好后的口径：
//! 写**超时**是背压、不计 strike；只有"写直接失败"才算坏隧道。

use super::common::*;

/// 规格：**写帧超时是背压，不得把 agent 摘除**。
///
/// 修好前：写帧臂无条件 `evict`，连续 3 次写超时（默认阈值）就把 agent 摘掉——连接被关、
/// `agent_count()` 归 0、后续请求变成 503 `"no edge available"`。这正是云端实测里
/// `registry-empty` 全量 503 的路径（`routing.rs:122-125`）。
///
/// 修好后：写超时只 warn + 重试，不计 strike；agent 一直在注册表里，后续请求最多是
/// 502（写超时），**绝不出现 503**。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_write_timeout_does_not_evict_the_agent() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let TestGateway {
        gw,
        certs,
        key,
        base,
        ..
    } = start_gateway(|o| {
        o.tunnel_op_timeout = Duration::from_millis(300);
        o.head_timeout = Duration::from_secs(3);
        o.request_timeout = Duration::from_secs(10);
        o.client_stall = Duration::from_secs(60);
    })
    .await;

    spawn_raw_agent(&gw, &certs, "slow-reader", 4).await;
    assert_eq!(gw.agent_count(), 1, "agent 应已注册");
    let connections_before = metric_gauge(&base, "hlmg_agent_connections_total").await;

    let client = reqwest::Client::new();
    let url = format!("{base}/v1/chat/completions");
    // 8 MiB 单帧：必须超过对端 QUIC 流控窗口，写才会 park 到超时（小 body 会被缓冲，测不到写路径）。
    // ⚠️ 这个触发器对上游默认窗口大小敏感：若将来 s2n-quic 把默认数据窗口抬到 8 MiB 以上，
    //    写会成功、失败变成 504，本测试会在"应当是写超时 502"处**响亮地**失败——那时把 body 调大
    //    （上限 `body::MAX_REQUEST_BODY` = 16 MiB）即可，不要改成容忍 504。
    let big = "x".repeat(8 * 1024 * 1024);
    let send_big = || {
        client
            .post(&url)
            .header("Authorization", format!("Bearer {key}"))
            .json(&serde_json::json!({
                "model": "mock-llm",
                "messages": [{ "role": "user", "content": big }],
            }))
    };

    // 连续 3 次写超时 —— 正好是默认阈值；修好前第 3 次会把 agent 摘掉。
    for attempt in 1..=3 {
        let t0 = std::time::Instant::now();
        let resp = tokio::time::timeout(Duration::from_secs(10), send_big().send())
            .await
            .unwrap_or_else(|_| panic!("第 {attempt} 次请求必须在隧道超时量级内结束"))
            .unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::BAD_GATEWAY,
            "第 {attempt} 次应当是写超时 502"
        );
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "第 {attempt} 次应在 tunnel_op_timeout 量级失败，实际 {:?}",
            t0.elapsed()
        );
        let body = resp.text().await.unwrap_or_default();
        assert!(
            body.contains("tunnel write timed out"),
            "第 {attempt} 次的失败必须来自**写帧**而不是等响应头，实际：{body}"
        );
    }

    // ① 关键判据：三次写超时之后 agent 仍在注册表里（写超时是背压，不计 strike）
    assert_eq!(
        gw.agent_count(),
        1,
        "写帧超时不得摘除 agent（修好前这里会变成 0）"
    );

    // ② 没有摘除 → 没有关连接 → agent 不需要重连
    let connections_after = metric_gauge(&base, "hlmg_agent_connections_total").await;
    assert_eq!(
        connections_after, connections_before,
        "agent 被摘除并重连了（连接次数 {connections_before} → {connections_after}）——写超时被当成了死"
    );

    // ③ 后续请求仍是"隧道写超时"，绝不能是 503 no edge available
    let resp = tokio::time::timeout(Duration::from_secs(10), send_big().send())
        .await
        .expect("摘除后的请求也应快速结束")
        .unwrap();
    assert_ne!(
        resp.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "出现 503 说明 agent 已被摘除（registry 空了）"
    );

    // ④ 专用指标：写超时必须记成 backpressure，且不得出现 broken
    let backpressure = metric_gauge(
        &base,
        "hlmg_tunnel_write_failures_total{class=\"backpressure\"}",
    )
    .await;
    assert!(
        backpressure >= 3,
        "三次写超时应记入 backpressure，实际 {backpressure}"
    );
    let text = reqwest::get(format!("{base}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        !text.contains("hlmg_tunnel_write_failures_total{class=\"broken\"}"),
        "写**超时**不得被记成 broken（那会把背压说成坏连接）：{text}"
    );

    gw.shutdown().await;
}
