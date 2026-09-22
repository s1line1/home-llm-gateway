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

/// 规格（R12）：`/healthz` 的 body 与**程序化 API 同源**，且 `start()` 返回后立刻就是 200。
///
/// 三个方向：
/// ① `start()` 返回 ⇒ 隧道入口接受中 ⇒ **立刻**探活必须 200（不需要重试窗口——
///    `Gateway::start` 为此等了 gauge，见 `quic::await_accepting`）；
/// ② 注册后**从不心跳**的裸 agent：`registered` 必须跟着涨、`healthy` 随后归零，
///    两者分别与 `Gateway::agent_count()` / `healthy_agent_count()` 逐字一致
///    （否则探针会把人带偏——"注册表里有、但全部不可路由"是排查 503 的关键区分）；
/// ③ 状态码与 body 的 `status` 永远一致。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_healthz_reports_the_same_agent_counts_as_the_api() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let TestGateway {
        gw, certs, base, ..
    } = start_gateway(|o| {
        o.agent_stale_after = Duration::from_millis(200);
    })
    .await;
    // ① 启动返回后**立刻**读：入口必须已经接受中（`start` 等过 gauge，不等就会有调度窗口）
    assert!(
        gw.tunnel_accepting(),
        "start() 返回时隧道入口必须已经接受中"
    );

    let client = test_client();
    // 探针也必须是 200（同一判据的另一面）
    let resp = bounded(
        "GET /healthz right after start",
        client.get(format!("{base}/healthz")).send(),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "start() 返回时隧道入口必须已经接受中，否则探针会在启动窗口里误报 degraded"
    );
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["status"], "ok");
    assert_eq!(v["tunnel_entry"], "accepting");
    assert_eq!(v["agents"]["registered"], 0, "还没有 agent：{v}");

    // ② 注册一个从不心跳的裸 agent
    spawn_raw_agent(&gw, &certs, "no-heartbeat", 4).await;

    let resp = client.get(format!("{base}/healthz")).send().await.unwrap();
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        v["agents"]["registered"],
        gw.agent_count(),
        "registered 必须与 Gateway::agent_count() 同源：{v}"
    );
    assert_eq!(
        v["agents"]["healthy"],
        gw.healthy_agent_count(),
        "healthy 必须与 Gateway::healthy_agent_count() 同源：{v}"
    );

    // 心跳过期：条目还在（连接没关），但已不可路由——body 必须能区分这两者
    tokio::time::sleep(Duration::from_millis(400)).await;
    let resp = client.get(format!("{base}/healthz")).send().await.unwrap();
    assert_eq!(resp.status(), 200, "agent 不健康不等于网关不存活");
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["agents"]["registered"], 1, "条目仍在：{v}");
    assert_eq!(v["agents"]["healthy"], 0, "心跳过期 ⇒ 不可路由：{v}");
    assert!(
        v["agents"]["oldest_last_seen_secs_ago"].is_number(),
        "最久心跳年龄应当是数字（注册表非空）：{v}"
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

/// 规格：**关闭先排空在途请求，再 abort**（片 A：停 accept → 排空 → abort）。
///
/// 判据故意**不看"请求最终成功没有"**（那取决于 QUIC 端点 drop 的语义），而是看
/// `shutdown()` 返回时在途请求是否已经结束：修好前 `shutdown` 立刻 abort，1.5s 的慢请求
/// 还在飞；修好后会等 `hlmg_active_requests` 归零（或到宽限期）才返回。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_shutdown_drains_in_flight_requests_before_returning() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base, key) = start_stack(4, |_| {}).await;
    let client = test_client();
    // 在途请求必须**读完响应体**：准入票据绑在 body 上，不消费 body 就永远算"在途"。
    let inflight = tokio::spawn({
        let client = client.clone();
        let url = format!("{base}/v1/slow?ms=1500");
        let auth = format!("Bearer {key}");
        async move {
            let resp = client
                .post(url)
                .header("Authorization", auth)
                .json(&serde_json::json!({ "model": "mock-llm" }))
                .send()
                .await
                .unwrap();
            let status = resp.status();
            let _ = resp.text().await;
            status
        }
    });

    // 等它真的进入在途（否则"排空"可能只是还没有请求）
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while metric_gauge(&base, "hlmg_active_requests").await == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "慢请求没有进入在途，测试前提不成立"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    gw.shutdown().await;

    assert!(
        inflight.is_finished(),
        "shutdown 返回时在途请求必须已经结束（排空），而不是被硬切"
    );
    assert_eq!(
        inflight.await.unwrap(),
        reqwest::StatusCode::OK,
        "在途请求应当自然结束"
    );

    agent.shutdown().await;
}

/// 规格：**关闭时给在途 SSE 一个可识别的"不完整"事件，并干净结束**（片 B）。
///
/// 用 `/v1/slow_body`：响应头立刻 200（`text/event-stream`），正文停 3s。
/// 宽限期压到 300ms，于是关闭时这条流必然还在途 → 网关应主动收尾。
///
/// 判据必须同时排除两种"假绿"：
/// - 连接被 reset/隧道断 → `resp.text()` 会**报错**，不是干净的流结束；
/// - 用 `data: [DONE]` 收尾 → 那是**谎报正常完成**（客户端会把残缺结果当完整结果记账）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_shutdown_announces_incomplete_sse_instead_of_cutting() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base, key) = start_stack(4, |o| {
        o.shutdown_grace = Duration::from_millis(300);
        o.client_stall = Duration::from_secs(5);
        o.request_timeout = Duration::from_secs(30);
    })
    .await;
    let client = test_client();
    let resp = client
        .post(format!("{base}/v1/slow_body"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({ "model": "mock-llm" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "SSE 响应头应当先到");

    // 等它真的进入在途
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while metric_gauge(&base, "hlmg_active_requests").await == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "SSE 请求没有进入在途，测试前提不成立"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // 关闭网关（后台），同时把流读完
    let shutdown = tokio::spawn(async move { gw.shutdown().await });
    let text = match tokio::time::timeout(Duration::from_secs(10), resp.text()).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => panic!("客户端读到的是连接错误而不是干净的流结束：{e}"),
        Err(_) => panic!("响应体既没有结束也没有报错（挂住了）"),
    };

    assert!(
        text.contains("gateway is shutting down"),
        "在途 SSE 应当收到明确的'服务端关闭、本响应不完整'事件，实际：{text:?}"
    );
    assert!(
        !text.contains("[DONE]"),
        "不得用 `[DONE]` 收尾——那会谎报'模型答完了'：{text:?}"
    );

    shutdown.await.unwrap();
    agent.shutdown().await;
}
