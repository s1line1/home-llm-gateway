//! 生命周期接口：`Gateway` 析构必须释放监听口，外加 `is_serving` / `healthy_agent_count`
//! 两个可观测性接口。

use super::common::*;

/// 规格：**keys 库不可用时必须在启动时失败**，而不是"起来了但每个请求 401"。
///
/// 记录 P2-9/P1-4 那一批讲的是**写**失败要冒到调用方；本条是同一家族的**启动**一档：库打不开 /
/// 建不出表 / 迁移或载入失败时，`KeyStore` 会降级成内存模式——库里明明有 key，网关一个都认不出来，
/// 于是每个请求 401，而进程、systemd、`/healthz` 全都正常。这与"不留一个看起来启动了的空壳进程"
/// 同源，所以在 `Gateway::start` 里 fail-fast（`keys_file: None` 的内存模式不受影响）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_unusable_keys_db_fails_fast_instead_of_starting_keyless() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let certs = TestCerts::generate();
    let dir = tempfile::tempdir().unwrap();

    // 不是 SQLite 库的文件：open 会成功（SQLite 惰性），建表时必然失败 ⇒ 降级 ⇒ 必须 fail-fast
    let bogus = dir.path().join("bogus-keys.db");
    std::fs::write(&bogus, b"this is definitely not a sqlite database").unwrap();
    let opts = Options {
        keys_file: Some(bogus.clone()),
        ..e2e_options(None)
    };
    let msg = match Gateway::start(gateway_config(&certs, opts)).await {
        Ok(gw) => {
            gw.shutdown().await;
            panic!("坏 keys 库必须让启动失败——否则网关认不出任何 key，却报健康（每个请求 401）");
        }
        Err(e) => e.to_string(),
    };
    assert!(msg.contains("keys_file"), "报错要点名配置项，实际：{msg}");
    assert!(
        msg.contains("bogus-keys.db"),
        "报错要带上具体路径与原因，实际：{msg}"
    );

    // 对照①：换成一个可用的库（不存在会被自动创建）就能起来
    let good = dir.path().join("good-keys.db");
    let opts = Options {
        keys_file: Some(good.clone()),
        ..e2e_options(None)
    };
    let gw = Gateway::start(gateway_config(&certs, opts))
        .await
        .expect("可用的 keys 库必须能启动");
    gw.shutdown().await;

    // 对照②：`keys_file: None`（内存模式）也是合法配置，不该被这条检查误伤
    let opts = e2e_options(None);
    assert!(opts.keys_file.is_none(), "前提：对照组确实没配 keys_file");
    let gw = Gateway::start(gateway_config(&certs, opts))
        .await
        .expect("内存模式必须能启动");
    gw.shutdown().await;
}

/// 规格（P2-8）：**零值旋钮必须在启动时失败，而不是让网关"起来了但全量 503"**。
///
/// `head_timeout_secs: 0` 是最毒的一个：每个请求 504，同时 `head_alive_window = 4 × 0 = 0`
/// 让"连续 3 次没等到响应头"立刻成立 ⇒ 所有 agent 被摘光 ⇒ 之后每个请求 503。配置文件里
/// 那个 `0` 看起来完全正常，所以必须在**碰任何资源之前**报错，且报错要点名 YAML 键。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_zero_valued_config_fails_fast_before_binding_anything() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let certs = TestCerts::generate();
    let opts = Options {
        head_timeout: Duration::ZERO,
        ..e2e_options(None)
    };
    let msg = match Gateway::start(gateway_config(&certs, opts)).await {
        Ok(gw) => {
            gw.shutdown().await;
            panic!("head_timeout=0 必须让启动失败（否则网关起来就开始全量 503）");
        }
        Err(e) => e.to_string(),
    };
    assert!(
        msg.contains("head_timeout_secs"),
        "报错要点名 YAML 键（配置作者写的是这个）：{msg}"
    );

    // 同一份配置把值改回非零就能起来：证明拒绝的是那一个值，不是配置本身
    let opts = Options {
        head_timeout: Duration::from_secs(5),
        ..e2e_options(None)
    };
    let gw = Gateway::start(gateway_config(&certs, opts))
        .await
        .expect("非零 head_timeout 必须能启动");
    gw.shutdown().await;
}

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

/// 规格（并集报告 H5）：**关停必须把在途转发任务叫停**，而不是等它自己的停滞上限。
///
/// 场景：客户端读完响应头就**不再读**（通道很快被灌满 → 转发任务 park 在 `send_to_client`），
/// 此时调 `Gateway::shutdown()`。修复前任务只在**循环顶部**看 `Terminating`，而它正卡在一个
/// 最长 `client_stall`（这里刻意设成 30s）的发送上：`shutdown` 1 秒收尾窗口后返回，任务仍持有
/// agent 槽位与 QUIC 流，Cancel 也要等到 30s 才发出去。
///
/// 判据放在**上游侧**（mock-llm 的 `/stats` 里"被中途取消的响应体数"）：网关日志说"发了 Cancel"
/// 只是自述，**上游真的停了**才算数。`TODO.md:414-422` 登记的那条缺口就此补上。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_shutdown_cancels_a_client_stalled_stream_without_waiting_for_the_stall() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    // 停滞上限刻意很大（30s）：若关停路径要等它，这条测试会超时；宽限压到 200ms，
    // 让 shutdown 很快走到 Terminating。
    let big_stall = Duration::from_secs(30);
    let (gw, agent, base, key, mock_addr) = start_stack_with_mock(4, |o| {
        o.client_stall = big_stall;
        o.shutdown_grace = Duration::from_millis(200);
        o.max_concurrent_requests = 1;
    })
    .await;

    // 对照（让后面的 `cancelled > 0` 有意义）：一条**读完**的 flood 请求不该被算成取消。
    // 少了这一步，即使计数器把"正常结束"也记进去，下面的断言也会假绿。
    // 这条对照请求**本该读完**（下面断言 200 + 收满 3 KiB），所以用带总超时的 client（P2-17）
    let full = test_client()
        .post(format!("{base}/v1/flood?chunks=3&kb=1&delay_ms=0"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({ "model": "mock-llm" }))
        .send()
        .await
        .unwrap();
    assert_eq!(full.status().as_u16(), 200);
    let whole = full.bytes().await.unwrap();
    assert!(
        whole.len() >= 3 * 1024,
        "应当读完整个 flood 响应：{}",
        whole.len()
    );
    let stats: serde_json::Value = reqwest::get(format!("http://{mock_addr}/stats"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        stats["cancelled"].as_u64(),
        Some(0),
        "正常读完的流不该被上游算成取消：{stats}"
    );

    // 裸 TCP：打持续产出的上游，读到响应头之后不再读 socket
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
        String::from_utf8_lossy(&seen).contains("200"),
        "前置条件：应当先正常拿到 /v1/flood 的响应头，实际：{:?}",
        String::from_utf8_lossy(&seen[..seen.len().min(200)])
    );
    // 从这里开始不读；给它一点时间把通道与 socket 缓冲灌满，让转发任务真的 park 住
    tokio::time::sleep(Duration::from_millis(400)).await;

    let started = std::time::Instant::now();
    gw.shutdown().await;
    let shutdown_took = started.elapsed();
    assert!(
        shutdown_took < Duration::from_secs(5),
        "shutdown 不该等 30s 的停滞上限（实测 {shutdown_took:?}）"
    );

    // 上游必须在**很短**的时间内看到这次取消（修复前要等满 30s 的停滞上限）
    let stats_url = format!("http://{mock_addr}/stats");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut cancelled = 0;
    while tokio::time::Instant::now() < deadline {
        if let Ok(resp) = reqwest::get(&stats_url).await {
            if let Ok(v) = resp.json::<serde_json::Value>().await {
                cancelled = v["cancelled"].as_u64().unwrap_or(0);
                if cancelled > 0 {
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        cancelled > 0,
        "关停后上游必须在数秒内看到取消（`/stats.cancelled`）；为 0 说明转发任务还卡在停滞发送上，\
         没把 Cancel 发出去（H5）"
    );

    drop(sock);
    agent.shutdown().await;
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

/// 裸 agent：注册 → 接受请求流 → 回"头 + 第一块" → **只写第二帧的前 2 字节**并通知调用方
/// → 等调用方放行 → 写完后半帧 → 结束。
///
/// 三个信号：① 半个帧头已写出（且已给足送达时间）；② 放行写剩下的一半；③ 整帧写完。
async fn spawn_split_frame_agent(
    gw: &Gateway,
    certs: &TestCerts,
    agent_id: &str,
) -> (
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
    use tokio::io::AsyncWriteExt;

    let client = s2n_quic::Client::builder()
        .with_tls(s2n_quic::provider::tls::rustls::Client::from(
            std::sync::Arc::new(
                agent::tls::rustls_client_tls(
                    &certs.ca,
                    certs.client_cert.clone(),
                    certs.client_key.clone_key(),
                )
                .unwrap(),
            ),
        ))
        .unwrap()
        .with_io("0.0.0.0:0")
        .unwrap()
        .start()
        .unwrap();
    let conn = client
        .connect(s2n_quic::client::Connect::new(gw.quic_addr).with_server_name("localhost"))
        .await
        .unwrap();
    let (mut handle, mut acceptor) = conn.split();

    // 注册流由 agent 自己开（与 `spawn_raw_agent` 同一套）
    let stream = handle.open_bidirectional_stream().await.unwrap();
    let (mut reg_recv, mut reg_send) = stream.split();
    write_frame(
        &mut reg_send,
        &Frame::Register {
            agent_id: agent_id.into(),
            models: vec!["mock-llm".into()],
            max_concurrency: 4,
            version: "test".into(),
        },
    )
    .await
    .unwrap();
    reg_send.finish().unwrap();
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        FrameReader::new(&mut reg_recv).next(),
    )
    .await;
    wait_for_agents(gw, 1, Duration::from_secs(5)).await;

    let (half_tx, half_rx) = tokio::sync::oneshot::channel();
    let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        // `conn` 已被 `split()` 消耗，保活靠它分出来的 handle/acceptor
        let _keep_alive = (client, handle, reg_recv);
        let Ok(Some(stream)) = acceptor.accept_bidirectional_stream().await else {
            return;
        };
        let (mut recv, mut send) = stream.split();

        let mut reader = proto::io::FrameReader::new(&mut recv);
        let Ok(Some(Frame::ProxyRequest { request_id, .. })) = reader.next().await else {
            return;
        };

        write_frame(
            &mut send,
            &Frame::ProxyResponseHead {
                request_id,
                status: 200,
                headers: vec![("content-type".into(), "text/plain".into())],
            },
        )
        .await
        .unwrap();
        write_frame(
            &mut send,
            &Frame::ProxyResponseBody {
                request_id,
                chunk: b"first\n".to_vec().into(),
            },
        )
        .await
        .unwrap();

        // 第二块**整帧的线上字节**，刻意从中间切开：前 2 字节单独写出（不足一个长度前缀）。
        let mut wire = Vec::new();
        write_frame(
            &mut wire,
            &Frame::ProxyResponseBody {
                request_id,
                chunk: b"second\n".to_vec().into(),
            },
        )
        .await
        .unwrap();
        assert!(wire.len() > 2, "前提：这一帧必须长于一个前缀");
        send.write_all(&wire[..2]).await.unwrap();
        send.flush().await.unwrap();
        let _ = half_tx.send(());
        let _ = resume_rx.await;
        send.write_all(&wire[2..]).await.unwrap();

        write_frame(
            &mut send,
            &Frame::ProxyResponseEnd {
                request_id,
                ok: true,
            },
        )
        .await
        .unwrap();
        let _ = send.finish();
        let _ = done_tx.send(());
    });

    (half_rx, resume_tx, done_rx)
}

/// 规格（记录 P3-26）：**关停的阶段变化不许吃掉已经读了一半的帧**。
///
/// `forward_body` 的读帧 `select!` 里有三个分支，其中 `shutdown.changed()` 是 `continue`
/// ——也就是**复用同一条流**。用当时那条不可取消的读路径（内部 `read_exact`）时，阶段变化恰好
/// 落在帧中途会让被 drop 的 future 带走已读字节，下一轮按错误偏移解析长度前缀：帧错位，
/// 客户端拿到的是读取错误而不是后半块。`docs/refactor-assessment.md:243` 早就写明"今天安全
/// 只因为读侧只有一个任务，有人加第三分支就会静默丢半帧"——`c62df2b` 加的正是这个分支。
///
/// 判据：`Draining` 期间写出的后半帧必须**完整拼回**，且响应体里不许出现读取错误。
/// 时序上刻意让"半个帧头"先落地并停留半秒，再触发关停——那半秒里网关必然已读走那 2 字节。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_a_frame_split_by_a_shutdown_phase_change_is_not_misparsed() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let TestGateway {
        gw,
        certs,
        key,
        base,
        ..
    } = start_gateway(|o| {
        // Draining 必须活到"后半帧写进来"之后：宽限给够，别让它直接滑到 Terminating
        o.shutdown_grace = Duration::from_millis(1500);
        o.head_timeout = Duration::from_secs(5);
        o.request_timeout = Duration::from_secs(15);
        o.client_stall = Duration::from_secs(30);
    })
    .await;

    let (half_written, resume, agent_done) =
        spawn_split_frame_agent(&gw, &certs, "split-frame").await;

    // 响应在关停宽限之后才回来，但仍然是**本该完成**的一步（1.5 s 宽限 ≪ 30 s 总超时），
    // 所以用带总超时的 client（P2-17）。
    let client = test_client();
    let request = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({
            "model": "mock-llm",
            "messages": [{ "role": "user", "content": "hi" }],
        }))
        .send();
    let response = tokio::spawn(request);

    // ① 等"半个帧头"落地，再留半秒让它被网关读走（此时网关正 park 在 read 上）
    half_written.await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // ② 关停（Draining：在途响应必须继续跑完），等阶段变化真的送达转发任务
    let shutdown = tokio::spawn(async move { gw.shutdown().await });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // ③ 放行后半帧
    resume.send(()).unwrap();

    let resp = response.await.unwrap().unwrap();
    assert_eq!(resp.status(), 200, "响应头在关停前就已经发出去了");
    // 帧错位后网关只能中止响应体，客户端读到的是**破损的分块编码**而不是一句错误文案
    // （实测退回旧读路径时报 "unexpected EOF during chunk size line"）。
    let body = match resp.text().await {
        Ok(body) => body,
        Err(e) => panic!("响应体读到一半断了——帧错位后网关中止了响应体（P3-26 的红）：{e}"),
    };
    assert!(
        body.contains("first"),
        "前提：关停前那一块应当已送达，实际：{body:?}"
    );
    assert!(
        !body.contains("tunnel read failed") && !body.contains("frame too large"),
        "半个帧头被吃掉后按错误偏移解析（帧错位）；响应体：{body:?}"
    );
    assert!(
        body.contains("second"),
        "`Draining` 期间写出的后半帧必须被完整拼回（P3-26 的红）：{body:?}"
    );

    agent_done.await.unwrap();
    shutdown.await.unwrap();
}
