//! 摘除后的**延迟关闭**：`evict_close_grace` 是"保护在途请求"与"别让 agent 变僵尸"之间的那个上界。
//!
//! 为什么补这条测试（评估报告 §5 H1 / §6）：这条契约原先只有一个单测
//! （`registry.rs` 的 `eviction_defers_close_while_other_requests_are_in_flight`），
//! 而那个单测断言完 `RemovedClosedLater` 之后**立刻 `drop` 了槽位**——也就是说
//! `close_when_drained` 的**截止分支**（"超过宽限期强制关"）从来没有代码走到过。
//! 于是"摘除会不会掐断一条正在生成的请求、以及宽限期是不是那个决定因素"既没被测过、
//! 也没被量过，而它正是 H1 那条发现的全部内容。
//!
//! 这里用一个 **A/B 对照**把它钉住（两组唯一的差别就是宽限期）：
//!
//! | 组 | `evict_close_grace` | 期望 |
//! |---|---|---|
//! | A | 1s | 正在生成的那个请求必须在宽限期结束时被打断——拿不到 `[DONE]` |
//! | B | 30s | 同样的时序下它必须**活着拿到** `[DONE]` |
//!
//! B 组同时钉住了"摘除确实走了延迟关闭这条路"：如果 `evict` 走了立刻关闭那条分支，
//! B 组的请求会当场被打断，B 组就会失败。所以两组合起来覆盖的是
//! "延迟关闭 + 截止时刻强制关"这**一整条**分支，而不只是其中一个方向。

use std::time::{Duration, Instant};

use super::common::*;

/// 被观察请求的结局。
#[derive(Debug)]
enum Settled {
    /// 正常结束，拿到完整正文。
    Body(String),
    /// 出错结束（连接被打断 → 读失败 / 响应体错误）。
    Failed(String),
    /// 观测窗口内一直没有结束。
    Pending,
}

/// 造出"同一连接上有一个正在生成的请求 + 连续 3 次响应头超时"的时序，并返回被观察请求的结局。
///
/// 时序（`head_timeout = 100ms`，所以"忙/死"窗口 = `4 × 100ms = 400ms`）：
/// 1. `t≈0`：`/v1/slow_body` 立刻回响应头、正文 3s 后才出第一块 → **一个已经过了响应头、
///    正在生成、且占着准入槽位的请求**（这正是"已送达上游"那一类）。它的响应头会刷新
///    `last_head_ok`，这是第 2 步要利用的事实。
/// 2. `t≈0.5s`：等沉默超过 400ms 窗口——否则后面的响应头超时会被判成"只是慢"。
/// 3. `t≈0.5–0.8s`：同一连接上连打 3 个 `/v1/slow?ms=3000`，每个都在 `head_timeout` 后超时
///    且被判死 → 第 3 个达阈值 → 摘除。此时在途 = 正在生成的那个 + 本次失败的这个 = 2 > 1
///    → `evict` 走**延迟关闭**，把连接交给 `defer_close` 与 `evict_close_grace`。
/// 4. 观察步骤 1 的请求在 `window` 内如何结束。
///
/// ⚠️ 这里必须把 `head_silent_grace` 压到 300ms：被测 agent 是**会心跳**的真 agent（测试里
/// 200ms 一次），而判据的第二层（评估 §5 H2）对"心跳还新鲜"的对端会把静默宽限到
/// `head_silent_grace`。不压小它，这三次超时会被判成"慢"，压根不会摘除，本用例就没有延迟关闭
/// 可测。**不能改用 `request_timeout`**（它同时是转发空闲超时）：压小它会把下面那个 3s 的
/// 在途正文提前掐断，那次切断就分不清是宽限期还是请求超时了。
async fn eviction_while_generating(grace: Duration, window: Duration) -> (Duration, Settled) {
    let (gw, agent, base, key) = start_stack(4, |o| {
        o.head_timeout = Duration::from_millis(100);
        o.evict_close_grace = grace;
        o.head_silent_grace = Duration::from_millis(300);
        // `client_stall` / `request_timeout` 保持默认（60s / 120s）：观察窗口只有几秒，
        // 所以"请求被打断"只可能来自摘除的宽限期——A/B 两组唯一不同的就是宽限期。
    })
    .await;
    let client = test_client();

    // ① 正在生成的请求。用 oneshot 确认"响应头已经到了"，否则后面的睡 500ms 可能跑在
    //    响应头之前，第 2 步的窗口前提就不成立。
    let (head_arrived_tx, head_arrived_rx) = tokio::sync::oneshot::channel::<()>();
    let started = Instant::now();
    let inflight = tokio::spawn({
        let client = client.clone();
        let base = base.clone();
        let key = key.clone();
        async move {
            let resp = client
                .post(format!("{base}/v1/slow_body"))
                .header("Authorization", format!("Bearer {key}"))
                .json(&serde_json::json!({ "model": "mock-llm" }))
                .send()
                .await?;
            assert_eq!(
                resp.status().as_u16(),
                200,
                "慢正文端点应当立刻回响应头（否则这个请求不属于已过响应头的那一类）"
            );
            let _ = head_arrived_tx.send(());
            resp.text().await
        }
    });

    head_arrived_rx.await.expect("慢正文请求应当先拿到响应头");
    // ② 让沉默跨过 4 × head_timeout 的窗口。
    tokio::time::sleep(Duration::from_millis(500)).await;

    // ③ 同一连接上 3 次"静默"响应头超时 → 第 3 次摘除（在途 > 1 → 延迟关闭）。
    for i in 1..=3 {
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
            "第 {i} 次静默超时应当 504（上游慢过 head_timeout）"
        );
    }

    // 前置条件（也把 H2 钉住）：这 3 次超时**全部**被判死。窗口内没有任何成功响应头，
    // 所以"忙/死"判据不会保护它们——这正是 H2 的内容（均匀慢流量会击穿该判据的保护）。
    // 若这里不是 3，说明窗口前提没成立，下面那组结论也就无效。
    let metrics = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("hlmg_upstream_head_timeouts_total{class=\"silent\"} 3"),
        "预期 3 次响应头超时全部判死（uniform 慢流量会击穿存活判据的保护）：{metrics}"
    );

    // ④ 观察那个正在生成的请求。
    let settled = match tokio::time::timeout(window, inflight).await {
        Ok(Ok(Ok(body))) => Settled::Body(body),
        Ok(Ok(Err(e))) => Settled::Failed(e.to_string()),
        Ok(Err(join)) => Settled::Failed(format!("join error: {join}")),
        Err(_) => Settled::Pending,
    };
    let elapsed = started.elapsed();

    agent.shutdown().await;
    gw.shutdown().await;
    (elapsed, settled)
}

/// 规格：**摘除的宽限期就是那个上界**——到期即强制关闭，正在生成的请求会被打断。
///
/// 这正是 `close_when_drained` 里那条此前零覆盖的截止分支。它也把 H1 的取舍变成可测的事实：
/// 默认宽限 **15s 且有意等于** `head_timeout`(15s)（`Options::DEFAULT_EVICT_CLOSE_GRACE`，
/// 2026-09 由 5s 上调），但远短于 `request_timeout`(120s)——所以"已经在生成"的请求在长回答上
/// 仍可能保不住（保多久＝宽限期有多长）。复扫 F6：这里原先还写着"默认宽限 5s"，已过时。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_eviction_grace_deadline_cuts_an_in_flight_generation() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    // 宽限 1s、观察窗口 5s：窗口远大于"正文 3s 后才出"，所以请求只要在窗口内结束，
    // 就一定是被打断、而不是正常完成。判据落在**有没有拿到完整正文**上，不依赖绝对耗时
    // （慢机器上整条时序会整体后移，这里不想因此假失败）。
    let (elapsed, settled) =
        eviction_while_generating(Duration::from_secs(1), Duration::from_secs(5)).await;
    match settled {
        Settled::Body(body) => assert!(
            !body.contains("[DONE]"),
            "宽限 1s 到期后，正在生成的请求（正文 3s 后才出）不该拿到完整正文；\
             耗时 {elapsed:?}，正文尾部：{:?}",
            &body[body.len().saturating_sub(120)..]
        ),
        Settled::Failed(why) => println!("in-flight request was cut after {elapsed:?}: {why}"),
        Settled::Pending => panic!(
            "宽限 1s 到期后仍在途（耗时 {elapsed:?}）——说明 close_when_drained 的截止分支没有生效"
        ),
    }
}

/// 规格（对照组）：**宽限期没到就不许关**——同样的时序下，正在生成的请求必须活着拿到 `[DONE]`。
///
/// 这一组同时钉住"摘除确实走了延迟关闭那条分支"：`evict` 若走立刻关闭（`inflight <= 1`），
/// 这个请求会当场被打断，本用例必然失败。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_eviction_defers_the_close_until_the_grace_expires() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    // 宽限 30s：远大于正文停顿（3s），所以这次连接不该在观察窗口内被关。
    let (elapsed, settled) =
        eviction_while_generating(Duration::from_secs(30), Duration::from_millis(6000)).await;
    match settled {
        Settled::Body(body) => assert!(
            body.contains("[DONE]"),
            "宽限期内不该被打断，正文应当完整（含 [DONE]）；耗时 {elapsed:?}"
        ),
        Settled::Failed(why) => panic!(
            "宽限 30s，但正在生成的请求在 {elapsed:?} 就被打断了（{why}）——\
             说明走的不是延迟关闭，或者延迟关闭没有真的等"
        ),
        Settled::Pending => {
            panic!("宽限 30s，但请求在 {elapsed:?} 仍未结束——上游正文 3s 后就该出，说明它早被掐了")
        }
    }
}
