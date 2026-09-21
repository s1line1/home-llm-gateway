//! 生命周期接口：`Gateway` 析构必须释放监听口，外加 `is_serving` / `healthy_agent_count`
//! 两个可观测性接口。

use super::common::*;

/// 规格：**`Gateway` 被 drop 而未调 `shutdown()` 时，监听口必须释放**。
///
/// 修好前：`tasks` 里的 `JoinHandle` 只是被 drop（tokio 语义是 **detach**，不是 abort），
/// 于是入口任务继续跑、`TcpListener` 继续持有端口——库/测试调用方以为"析构即关闭"，
/// 实际端口泄漏、后台 flusher 继续写库。`main` 总是显式 `shutdown()`，所以只有嵌入
/// 场景会踩到（并集报告 §5-H2）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_drop_without_shutdown_releases_the_listener() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let TestGateway { gw, .. } = start_gateway(|_| {}).await;
    let addr = gw.http_addr;
    assert!(
        tokio::net::TcpStream::connect(addr).await.is_ok(),
        "启动后应当能连上公网入口"
    );

    drop(gw);

    // abort 到任务真正结束有一个调度窗口：轮询到端口不再接受连接为止。
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_err() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "drop 之后监听口仍在接受连接——入口任务没有被 abort（端口泄漏）"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// 规格：**`healthy_agent_count()` 与 `agent_count()` 必须分得开**。
///
/// `agent_count()` 是注册表条目数（含心跳已过期、连接还没关的）；`healthy_agent_count()`
/// 才是"现在能被路由"的数量。用一个注册后**从不心跳**的裸 agent 钉住：过期之后条目仍在
/// （连接没关），但已不可路由。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_healthy_agent_count_separates_registered_from_routable() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let TestGateway { gw, certs, .. } = start_gateway(|o| {
        o.agent_stale_after = Duration::from_millis(200);
    })
    .await;
    spawn_raw_agent(&gw, &certs, "no-heartbeat", 4).await;

    assert_eq!(gw.agent_count(), 1, "注册条目应在");
    assert_eq!(gw.healthy_agent_count(), 1, "刚注册时算健康");

    tokio::time::sleep(Duration::from_millis(400)).await;

    assert_eq!(
        gw.agent_count(),
        1,
        "条目还在——失联 agent 的连接没关，不会被摘除"
    );
    assert_eq!(
        gw.healthy_agent_count(),
        0,
        "心跳过期 → 不可路由（这正是 agent_count 会误导人的地方）"
    );

    gw.shutdown().await;
}

/// 规格：**`is_serving()` 能回答"入口还活着吗"**。
///
/// 今天没有别的接口能回答它：`JoinHandle` 存着但从不 poll，`hlmg_quic_accepting` 只覆盖
/// QUIC 入口，HTTP 入口死掉时进程、systemd、`/healthz` 全都正常（并集报告 H1）。
/// 这里只钉住正常态；"任务死掉 → false"需要故障注入（accept 出错 / 端点关闭），
/// 当前 harness 制造不出来（见 `quic.rs` 的测试注释）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_is_serving_reports_a_running_gateway() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let TestGateway { gw, .. } = start_gateway(|_| {}).await;
    assert!(gw.is_serving(), "刚启动、三个主任务都在跑时应为 true");
    gw.shutdown().await;
}
