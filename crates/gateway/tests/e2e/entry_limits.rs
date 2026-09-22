//! 公网入口**连接层**的限额：TLS 握手、请求头读取、并发连接数（评估 §5 H8 / `PROJECT_SCAN` P1-1）。
//!
//! 这三处是**准入闸门之外**的等待：闸门在"解析出请求"之后才生效，所以一个连上却不说话的
//! 客户端既不受 `max_concurrent_requests` 约束，也（此前）没有任何超时——只受 NOFILE 约束
//! （`nofile.rs` 启动时抬到 16384）。一个 fd + 一个任务被白占，进程、QUIC、`/healthz` 全都正常。
//!
//! 这三条也正好是"客户端会等、服务端没有上界"的最后一处：2026-09-21 排查 e2e
//! `TIMEOUT [180s]` 时逐段量过请求链，其余每一步都有 `head_timeout` / `request_timeout`
//! （逐帧空闲）/ `shutdown_grace` 兜住。

use super::common::*;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 连上但**一个字节都不发**（TLS 握手永远不开始）→ 必须在 `client_stall` 内被断开。
///
/// 没有超时时这里会一直挂着：服务端把 fd 与任务白白占住，而客户端看不到任何反应。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_client_that_never_completes_the_tls_handshake_is_dropped() {
    let t = start_gateway_with(|o, c| {
        o.client_stall = Duration::from_millis(300);
        o.https = Some(c.https_pem());
    })
    .await;

    let mut raw = tokio::net::TcpStream::connect(t.gw.http_addr)
        .await
        .unwrap();
    let mut buf = Vec::new();
    // 判据是"被断开"：握手都没开始，所以这里也不该有任何正经数据
    let read = tokio::time::timeout(Duration::from_secs(3), raw.read_to_end(&mut buf)).await;
    assert!(
        read.is_ok(),
        "半开连接必须在 client_stall 内被断开，否则 fd/任务无界增长"
    );
    assert!(
        buf.len() < 64,
        "握手都没开始，服务端不该发出正经数据（收到 {} 字节）",
        buf.len()
    );

    t.gw.shutdown().await;
}

/// 发了**一半请求头**就不再发 → 必须在 `client_stall` 内被断开
/// （hyper 的 `header_read_timeout`，且**必须**配 `timer` 才生效）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_client_that_stalls_mid_request_head_is_dropped() {
    let t = start_gateway(|o| o.client_stall = Duration::from_millis(300)).await;

    let mut raw = tokio::net::TcpStream::connect(t.gw.http_addr)
        .await
        .unwrap();
    // 故意不发结束的 CRLF：请求头永远不会完整
    raw.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .unwrap();

    let mut buf = Vec::new();
    // 判据是"被断开"：先回一个 408 再关也算通过，永远挂着不算
    let read = tokio::time::timeout(Duration::from_secs(3), raw.read_to_end(&mut buf)).await;
    assert!(
        read.is_ok(),
        "只发了半个请求头的连接必须被断开（hyper 的 header_read_timeout 生效了吗？）"
    );

    t.gw.shutdown().await;
}

/// 额度用满之后：新连接**留在 backlog 里排队**（而不是被收进来），有连接结束就立刻轮到它。
///
/// 这条同时钉住两件事：上限真的生效（否则 fd 仍可被半开连接吃光），以及"满额 = 排队"
/// 而不是"满额 = 拒绝"（后者会把资源保护变成 5xx）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn the_entry_holds_new_connections_back_at_the_cap() {
    // `client_stall` 保持基线（60s）：占住额度的那条连接不能被请求头超时清掉
    let t = start_gateway(|o| o.max_entry_connections = 1).await;
    let base = t.base.clone();

    // ① 占满唯一的额度：连上，一个字节都不发
    let held = tokio::net::TcpStream::connect(t.gw.http_addr)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ② 第二条连接：TCP 连得上（内核 backlog 收着），但不会被 accept ⇒ 拿不到响应
    let client = test_client();
    let blocked = tokio::time::timeout(
        Duration::from_millis(700),
        client.get(format!("{base}/healthz")).send(),
    )
    .await;
    assert!(
        blocked.is_err(),
        "额度已满时新连接必须排队，而不是被收进来服务"
    );

    // ③ 归还额度 → 排队的那条请求立刻被服务（是排队，不是丢弃）
    drop(held);
    let resp = tokio::time::timeout(
        Duration::from_secs(3),
        client.get(format!("{base}/healthz")).send(),
    )
    .await
    .expect("归还额度后新连接必须被服务")
    .unwrap();
    assert_eq!(resp.status(), 200);

    t.gw.shutdown().await;
}
