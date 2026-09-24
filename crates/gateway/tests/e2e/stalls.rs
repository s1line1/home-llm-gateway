//! 客户端停滞 → 准入槽位必须归还。
//!
//! 背景（2026-09-18 云端实测）：`hlmg_active_requests` 恒定在 8 不再下降，而
//! `hlmg_request_count − Σ状态码 = 8` 精确对上——即 8 个请求"被准入但永不结束"，
//! 占着 `max_concurrent_requests` 那道闸只增不减，只能重启恢复。
//!
//! 根因是两处**客户端侧 await 没有超时**（票据 `Admission` 的释放挂在 Drop 上，
//! 但前提是那个任务能结束）：
//!   1. 读请求体：`Bytes` 提取器会一直等 body 读完 → 只发 headers 不发 body 的客户端；
//!   2. 写响应体：`tx.send(...).await` 在通道满时永久 park → 读完响应头就不读 socket 的客户端。
//!
//! 两条测试都用 `max_concurrent_requests: 1` 做判据：槽位若泄漏，**后续请求必然 429**。
//! 这比读指标更锐利——不需要解释读数含义，红了就一定是泄漏。

use super::common::*;

/// 规格：**只发 headers、不发 body 的客户端不能永久占住一个准入槽位**。
///
/// 修好之前：这个请求会永远停在读 body 上，票据被中间件持有，`max_concurrent_requests: 1`
/// 的门被这一个请求占死 → 此后所有请求 429，直到重启网关。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_stalled_request_body_releases_the_admission_slot() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    // 停滞阈值压到 1s：测试要快；语义与生产默认 60s 完全相同
    let stall = Duration::from_secs(1);
    let (gw, agent, base, key) = start_stack(4, |o| {
        o.client_stall = stall;
        o.max_concurrent_requests = 1;
    })
    .await;

    // ── 裸 TCP：发 headers（声明 100KB body）+ 10 字节，然后停住不再发 ──
    let mut sock = tokio::net::TcpStream::connect(gw.http_addr).await.unwrap();
    let head = format!(
        "POST /v1/chat/completions HTTP/1.1\r\n\
         Host: localhost\r\n\
         Authorization: Bearer {key}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: 100000\r\n\r\n"
    );
    tokio::io::AsyncWriteExt::write_all(&mut sock, head.as_bytes())
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut sock, b"{\"model\":")
        .await
        .unwrap();
    // 之后什么都不发，也不关闭连接（关闭 = 干净断开，那是另一条已经处理好的路径）

    // 网关应当在 stall 量级内放弃这个请求（408），并且**归还槽位**
    let deadline = tokio::time::Instant::now() + stall * 3;
    let mut buf = vec![0u8; 4096];
    let mut got = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(
            remaining,
            tokio::io::AsyncReadExt::read(&mut sock, &mut buf),
        )
        .await
        {
            Ok(Ok(0)) => break, // 连接被关
            Ok(Ok(n)) => {
                got.extend_from_slice(&buf[..n]);
                if got.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Ok(Err(_)) => break,
            Err(_) => break, // 没等到响应也不算失败：下面用"槽位是否归还"判定
        }
    }
    let text = String::from_utf8_lossy(&got).to_string();
    assert!(
        text.is_empty() || text.contains(" 408") || text.contains(" 400"),
        "停滞的请求体应当以 408（或 400）收场，实际响应：{text:?}"
    );

    // 槽位归还：等一小会儿让 Drop 走完
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        metric_gauge(&base, "hlmg_active_requests").await,
        0,
        "停滞的请求结束后不得再有在途请求占着准入槽位"
    );

    // 最锐利的判据：max_concurrent_requests = 1，槽位若泄漏则这里必然 429。
    // 这是**收尾探针、本该完成**（真正"要卡住"的是上面那个裸 TCP socket），所以用带总超时的
    // client —— 否则网关一旦卡住，`cargo test` 下整个 e2e 套件会无限期挂住（P2-17）。
    let resp = test_client()
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({ "model": "mock-llm", "messages": [{"role":"user","content":"hi"}] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "槽位被停滞的请求占住了（后续请求 429）——这正是要修的泄漏"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}

/// 规格：**读完响应头就不再读 socket 的客户端，也不能永久占住准入槽位**。
///
/// 与上一条互补：这条卡在**写响应体**上（通道容量 32，客户端不消费则发送端永久 park）。
/// 上游给一个 1MB 的 JSON 响应就足以填满 socket 缓冲与通道。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_client_that_stops_reading_the_body_releases_the_admission_slot() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let stall = Duration::from_secs(1);
    let (gw, agent, base, key) = start_stack(4, |o| {
        o.client_stall = stall;
        o.max_concurrent_requests = 1;
    })
    .await;

    // 裸 TCP：打一个**持续产出**的上游端点（`/v1/flood`），读到响应头之后停止读取。
    //
    // 为什么不用固定大小的响应：那样数据可能整个塞进 loopback 的 socket 缓冲 + 通道，
    // 通道并不会一直满着，于是"客户端不读"根本触发不到背压（实测过：这条测试会假通过）。
    // 持续产出则一定能把缓冲与通道灌满。
    let mut sock = tokio::net::TcpStream::connect(gw.http_addr).await.unwrap();
    let body = serde_json::json!({ "model": "mock-llm" }).to_string();
    let head = format!(
        "POST /v1/flood?chunks=1000000&kb=64&delay_ms=1 HTTP/1.1\r\n\
         Host: localhost\r\n\
         Authorization: Bearer {key}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    );
    tokio::io::AsyncWriteExt::write_all(&mut sock, head.as_bytes())
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut sock, body.as_bytes())
        .await
        .unwrap();

    // 只读到响应头为止
    let mut seen = Vec::new();
    let mut buf = vec![0u8; 8192];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(
            remaining,
            tokio::io::AsyncReadExt::read(&mut sock, &mut buf),
        )
        .await
        {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => seen.extend_from_slice(&buf[..n]),
            Ok(Err(_)) => break,
        }
    }
    assert!(
        String::from_utf8_lossy(&seen).contains("200")
            && String::from_utf8_lossy(&seen).contains("application/octet-stream"),
        "前置条件：应当先正常拿到 /v1/flood 的响应头，实际：{:?}",
        String::from_utf8_lossy(&seen[..seen.len().min(200)])
    );

    // 从这里开始不再读 socket（客户端"僵住"）
    tokio::time::sleep(stall * 3).await;

    assert_eq!(
        metric_gauge(&base, "hlmg_active_requests").await,
        0,
        "客户端停止消费响应体后，在途槽位必须被释放（修好前会永久占住）"
    );

    // 同上：收尾探针本该完成 → 带总超时（真正的"僵住"发生在上面那个裸 socket 上）
    let resp = test_client()
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({ "model": "mock-llm", "messages": [{"role":"user","content":"hi"}] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "槽位被「不读响应体」的客户端占住了（后续请求 429）"
    );

    drop(sock);
    agent.shutdown().await;
    gw.shutdown().await;
}
