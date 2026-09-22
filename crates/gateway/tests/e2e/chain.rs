//! chain 场景 e2e 测试。

use super::common::*;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_chain_with_mock_llm() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base, key) = start_stack(4, |_| {}).await;
    let client = test_client();

    // 无认证 → 401
    let resp = client
        .get(format!("{base}/v1/models"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "missing api key must be rejected");

    // healthz 无需认证
    let resp = client.get(format!("{base}/healthz")).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // 根路径：未配置 ui_dir 时返回 UI 构建提示页（HTML，不再内嵌管理页）
    let resp = client.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let page = resp.text().await.unwrap();
    assert!(
        page.contains("Home LLM Gateway"),
        "root should serve the UI placeholder"
    );
    assert!(
        page.contains("尚未构建"),
        "placeholder should mention building the UI"
    );
    assert!(
        page.starts_with("<!doctype html>"),
        "placeholder should be HTML"
    );

    // 认证后 /v1/models 穿透到 mock
    let resp = client
        .get(format!("{base}/v1/models"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let models: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(models["data"][0]["id"], "mock-llm");

    // chat completions 全链路（非流式）
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({
            "model": "mock-llm",
            "messages": [{"role": "user", "content": "hello from e2e"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let reply = body["choices"][0]["message"]["content"].as_str().unwrap();
    assert!(
        reply.contains("hello from e2e"),
        "mock reply should echo user content, got: {reply}"
    );

    // embeddings 也走通
    let resp = client
        .post(format!("{base}/v1/embeddings"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({"model": "mock-llm", "input": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let emb: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(emb["data"][0]["embedding"].as_array().unwrap().len(), 3);

    agent.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_sse_streaming_passthrough() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base, key) = start_stack(4, |_| {}).await;
    let client = test_client();

    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({
            "model": "mock-llm",
            "stream": true,
            "messages": [{"role": "user", "content": "流式测试"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let ctype = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        ctype.starts_with("text/event-stream"),
        "expected SSE content-type, got: {ctype}"
    );

    let text = resp.text().await.unwrap();
    // 逐字事件 + finish_reason 事件 + [DONE]
    let data_lines = text.matches("data: ").count();
    assert!(
        data_lines >= 3,
        "expected multiple SSE events, got {data_lines}: {text}"
    );
    assert!(
        text.contains("data: [DONE]"),
        "missing [DONE] terminator: {text}"
    );
    assert!(
        text.contains(r#""content":"流""#) && text.contains(r#""content":"试""#),
        "SSE should stream the echoed content per char: {text}"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_gateway_timeout_cancels_upstream() {
    use futures_util::StreamExt;

    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    // 网关**逐帧空闲**超时 300ms，而 mock 的 /v1/slow_body 立刻回响应头、正文停 3s。
    //
    // 注意用 /v1/slow_body 而不是 /v1/slow：后者卡的是**响应头**，归 `head_timeout` 管
    // （另一个语义，默认 15s —— 上游"思考"是合法的）。这里测的是"响应头已到、正文不走"
    // 这条路径，即 `forward_body` 的逐帧空闲超时。
    //
    // 契约：响应头已经发出去了，状态码不可能再变，所以**不能**断言 504；正确契约是
    // 正文在超时点被截断（收不到 [DONE]，流以错误结束），而不是让客户端一直挂着。
    let (gw, agent, base, key) =
        start_stack(4, |o| o.request_timeout = Duration::from_millis(300)).await;
    let client = test_client();

    let t0 = std::time::Instant::now();
    let resp = client
        .post(format!("{base}/v1/slow_body"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({ "model": "mock-llm" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "响应头应当正常到达");

    // 读正文：300ms 空闲超时后网关发 Cancel 并结束这条流 —— 应远早于上游的 3s
    let mut got = Vec::new();
    let mut stream = resp.bytes_stream();
    let read_all = async {
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(b) => got.extend_from_slice(&b),
                Err(_) => break, // 流被截断
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(5), read_all).await;
    let text = String::from_utf8_lossy(&got);
    assert!(
        !text.contains("[DONE]"),
        "上游还没出字就被空闲超时截断，不应收到 [DONE]；实际正文：{text:?}"
    );
    // 断言窗口 2s：相对 300ms 的空闲超时有 6 倍余量（够覆盖 argon2 校验 + 建连 + CI 抖动），
    // 又远小于上游 3s 的停顿 —— 所以"超时没生效"时必然失败，"机器慢"时不会假失败。
    // （之前是 150ms 超时配 800ms 停顿 + 700ms 断言，只有 ~95ms 余量，CI 上直接翻车。）
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "应在空闲超时（300ms）量级结束，而不是等上游 3s 出字；实际 {:?}",
        t0.elapsed()
    );

    // Cancel 不应影响 agent 连接本身，之后仍能正常服务（/v1/models 由网关聚合回答）
    let resp = client
        .get(format!("{base}/v1/models"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["object"], "list");
    assert_eq!(
        body["data"][0]["id"], "mock-llm",
        "healthy agent's declared model should be listed"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_client_disconnect_cancels_upstream() {
    use futures_util::StreamExt;

    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base, key) = start_stack(4, |_| {}).await;
    let client = test_client();

    // 发起 SSE 流式请求，读到一个 chunk 后直接丢弃响应（模拟客户端断开）
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({
            "model": "mock-llm",
            "stream": true,
            "messages": [{"role": "user", "content": "断开测试"}]
        }))
        .send()
        .await
        .unwrap();
    let mut stream = resp.bytes_stream();
    let _first = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("first SSE chunk within 5s")
        .unwrap()
        .unwrap();
    drop(stream); // 客户端断开 → 网关通道接收端被丢弃 → 发 Cancel

    // 给网关发 Cancel、agent 取消上游留时间
    tokio::time::sleep(Duration::from_millis(600)).await;

    // 网关仍可用
    let r = client
        .get(format!("{base}/v1/models"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    agent.shutdown().await;
    gw.shutdown().await;
}

/// 规格：调用方的凭据**不得**出现在上游收到的请求里。
///
/// 在**上游侧**观察，因此覆盖 网关 → 隧道帧 → agent → 上游 整条链路（而不只是网关
/// 自己的过滤函数）。客户端持有的是网关签发的 API key（对全部模型有效、能打公网网关），
/// 而 edge / 上游属于另一个信任域、三种上游（Ollama/vLLM/llama.cpp）都不认证——透传
/// 零收益纯风险：edge 一旦被攻破，攻击者白得一把可用的公网凭据，且 edge / 上游日志里
/// 会留下吊销不掉的副本。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_upstream_never_receives_client_credentials() {
    use std::sync::{Arc, Mutex};

    /// 记录收到的头名的假上游（只需要能应答一个 OpenAI 形状的响应）。
    #[derive(Clone)]
    struct Capture {
        seen: Arc<Mutex<Vec<String>>>,
    }
    async fn capture_chat(
        axum::extract::State(st): axum::extract::State<Capture>,
        headers: axum::http::HeaderMap,
    ) -> axum::Json<serde_json::Value> {
        let mut names: Vec<String> = headers.keys().map(|k| k.as_str().to_string()).collect();
        names.sort();
        st.seen.lock().unwrap().extend(names);
        axum::Json(serde_json::json!({
            "id": "chatcmpl-capture",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": "ok" },
                "finish_reason": "stop"
            }],
            "usage": { "prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2 }
        }))
    }

    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let app = axum::Router::new()
        .route("/v1/chat/completions", axum::routing::post(capture_chat))
        .with_state(Capture {
            seen: Arc::clone(&seen),
        });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let TestGateway { gw, certs, key, .. } = start_gateway(|_| {}).await;

    let agent = certs.agent(&gw, "cred-agent", &["mock-llm"], upstream_addr, 4, false);
    wait_for_agents(&gw, 1, Duration::from_secs(10)).await;

    let client = test_client();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", gw.http_addr))
        .header("Authorization", format!("Bearer {key}"))
        .header("Cookie", "session=topsecret")
        .header("X-Custom-Trace", "keep-me")
        .json(&serde_json::json!({
            "model": "mock-llm",
            "messages": [{ "role": "user", "content": "hi" }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "整条链路应当正常");

    let names = seen.lock().unwrap().clone();
    println!("PROBE: 上游收到的头名 = {names:?}");
    assert!(
        names.contains(&"x-custom-trace".to_string()),
        "普通业务头应当照旧转发到上游: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n == "authorization"),
        "上游不得收到调用方的 Authorization（网关自己的 API key）: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n == "cookie"),
        "上游不得收到调用方的 Cookie: {names:?}"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}

/// 已验证身份缓存**端到端**生效：同一 key 连续请求只跑一次 argon2。
///
/// 为什么值得一条 e2e：单元测试证明的是 `KeyStore` 的契约，而这里走的是
/// **HTTP → api_key() → spawn_blocking → KeyStore** 整条真实路径；同时它把
/// "每请求一次 argon2（19MiB）" 换成 "每凭据版本一次" 的收益钉在可观测指标上
/// （`hlmg_key_verify_misses_total` 只涨 1）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_verified_cache_reuses_argon2_across_requests() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base, key) = start_stack(4, |o| {
        o.verified_cache_max = gateway::storage::DEFAULT_VERIFIED_MAX;
    })
    .await;
    let client = test_client();
    let req = || {
        client
            .post(format!("{base}/v1/chat/completions"))
            .header("Authorization", format!("Bearer {key}"))
            .json(&serde_json::json!({ "model": "mock-llm" }))
    };

    // 冷启动一发（会跑一次 argon2），随后 9 发都应命中缓存
    for _ in 0..10 {
        let resp = req().send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let _ = resp.bytes().await;
    }

    let metrics = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let hits: u64 = metrics
        .lines()
        .find_map(|l| l.strip_prefix("hlmg_key_verify_hits_total "))
        .and_then(|v| v.trim().parse().ok())
        .expect("metrics 应包含 hlmg_key_verify_hits_total");
    let misses: u64 = metrics
        .lines()
        .find_map(|l| l.strip_prefix("hlmg_key_verify_misses_total "))
        .and_then(|v| v.trim().parse().ok())
        .expect("metrics 应包含 hlmg_key_verify_misses_total");

    assert_eq!(
        misses, 1,
        "10 个请求只应跑 1 次 argon2（缓存 + 单飞），实际 {misses}"
    );
    assert!(hits >= 9, "其余请求应命中缓存，实际 hits={hits}");

    agent.shutdown().await;
    gw.shutdown().await;
}

/// e2e 层的**并发单飞**：8 个请求同时首用同一个 key，也只应跑 1 次 argon2。
///
/// 为什么必须单独测：单元测试（`concurrent_same_token_hashes_once`）证明的是 KeyStore 的
/// 契约；这里走的是真实 HTTP + 真实并发（8 个连接同时打进来），也就是现网那个
/// "32 并发 → 654MB" 的形态。misses 计数是确定性的证据（内存数字太脆）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_concurrent_cold_requests_hash_once() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base, key) = start_stack(8, |o| {
        o.verified_cache_max = gateway::storage::DEFAULT_VERIFIED_MAX;
    })
    .await;
    let client = test_client();

    // 8 个并发请求同时到达（同一个 key，从未校验过）
    let mut handles = Vec::new();
    for _ in 0..8 {
        let client = client.clone();
        let base = base.clone();
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            client
                .post(format!("{base}/v1/chat/completions"))
                .header("Authorization", format!("Bearer {key}"))
                .json(&serde_json::json!({ "model": "mock-llm" }))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }));
    }
    for h in handles {
        assert_eq!(h.await.unwrap(), 200);
    }

    let metrics = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let misses: u64 = metrics
        .lines()
        .find_map(|l| l.strip_prefix("hlmg_key_verify_misses_total "))
        .and_then(|v| v.trim().parse().ok())
        .expect("metrics 应包含 hlmg_key_verify_misses_total");
    assert_eq!(
        misses, 1,
        "8 个并发冷请求只应跑 1 次 argon2（单飞），实际 {misses}——否则内存峰值就是 N × 19MiB"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}

/// 规格：**客户端断开后，agent 槽位必须立刻释放**，不能等到上游下次产出。
///
/// 场景是"上游静默"：`/v1/slow_body` 立刻回响应头，之后 3s（`SLOW_BODY_STALL`）才吐第一块。
/// 客户端拿到响应头就断开——此时网关正停在 `forward_body` 的 `read_frame` 上，`tx.send`
/// 根本不会被调用。
///
/// 修复前：断开只能在 `tx.send()` 失败时被发现 → 要么等上游 3s 后吐帧，要么等满
/// `idle_timeout`（本用例给 30s）才发 Cancel、才释放槽位。这就是 `REBUILD.md` §4.7 登记的
/// 缺口，而"用户看到卡顿就取消"是最常见的交互形态。
/// 修复后：`tx.closed()` 与 `read_frame` 在同一个 `select!` 里，断开即时可见。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_client_disconnect_while_upstream_is_silent_releases_the_slot() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    // idle（request_timeout）给 30s：让"等上游产出"与"立刻释放"清楚区分
    let (gw, agent, base, key) = start_stack(4, |o| {
        o.request_timeout = Duration::from_secs(30);
        o.admin_token = Some("admin-token".into());
    })
    .await;

    let mut sock = tokio::net::TcpStream::connect(gw.http_addr).await.unwrap();
    let body = br#"{"model":"mock-llm","stream":true}"#;
    let head = format!(
        "POST /v1/slow_body HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {key}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    sock.write_all(head.as_bytes()).await.unwrap();
    sock.write_all(body).await.unwrap();
    sock.flush().await.unwrap();

    // 收到响应头 → 网关已进入 forward_body（正在等上游正文）
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
        .await
        .expect("响应头必须在 5s 内到达（slow_body 立刻回头）")
        .unwrap();
    assert!(
        String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"),
        "应先拿到 200 响应头，实际：{:?}",
        String::from_utf8_lossy(&buf[..n])
    );

    let client = test_client();
    let inflight = || async {
        let v: serde_json::Value = client
            .get(format!("{base}/admin/agents"))
            .header("Authorization", "Bearer admin-token")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        v[0]["inflight"].as_u64().unwrap_or(0)
    };

    // 先确认槽位真被占上了，否则这条用例会假通过
    let t_hold = std::time::Instant::now();
    while inflight().await == 0 && t_hold.elapsed() < Duration::from_secs(2) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(inflight().await, 1, "请求应在途占住 1 个槽位");

    drop(sock); // ← 客户端断开

    let t0 = std::time::Instant::now();
    while inflight().await != 0 {
        assert!(
            t0.elapsed() < Duration::from_millis(1500),
            "客户端已断开，槽位却仍被占着 {:?}（上游还要静默 3s、idle 给的是 30s）——\
             说明断开没有被即时发现",
            t0.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    agent.shutdown().await;
    gw.shutdown().await;
}

/// 隧道 `request_id` 必须与 HTTP 层 id **同源**：不带 `x-request-id` 的请求与带 UUID 的
/// 请求，隧道 id 必须互不重复。
///
/// 回归的是拆分前的真实缺口：`metrics_middleware` 与 `proxy` 各持一个从 1 开始的静态
/// 计数器——不带头的请求走前者（`req-{n}` 写回 headers，`proxy` 沿用），带 UUID 的请求
/// `proxy` 解析失败、回落到**它自己那个**计数器 → 两个 1..N 数列互相撞号（A 的第 n 个
/// 请求与 B 的第 n 个请求拿到同一个 id，送给同一个 agent）。
///
/// 隧道 id 不是纯日志字段：`Frame::Cancel { request_id }` 按它定位请求，agent 也按它
/// 关联会话；撞号意味着可能取消到错误的请求。修法是两侧共用一个分配器
/// （`gateway::request_id`），本用例锁住这条不变量。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_tunnel_request_id_is_unique_across_x_request_id_shapes() {
    use std::sync::Arc;

    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let TestGateway {
        gw,
        certs,
        key,
        base,
        ..
    } = start_gateway(|_| {}).await;

    // 裸 s2n-quic 客户端：注册成唯一 agent，随后每收到一条代理流就把它的 request_id 报回来
    let client = s2n_quic::Client::builder()
        .with_tls(s2n_quic::provider::tls::rustls::Client::from(Arc::new(
            agent::tls::rustls_client_tls(
                &certs.ca,
                certs.client_cert.clone(),
                certs.client_key.clone_key(),
            )
            .unwrap(),
        )))
        .unwrap()
        .with_io("0.0.0.0:0")
        .unwrap()
        .start()
        .unwrap();
    let mut conn = client
        .connect(s2n_quic::client::Connect::new(gw.quic_addr).with_server_name("localhost"))
        .await
        .unwrap();
    let stream = conn.open_bidirectional_stream().await.unwrap();
    let (mut rr, mut rs) = stream.split();
    write_frame(
        &mut rs,
        &Frame::Register {
            agent_id: "raw-ids".into(),
            models: vec!["raw".into()],
            max_concurrency: 8,
            version: "test".into(),
        },
    )
    .await
    .unwrap();
    rs.finish().unwrap();
    let _ = bounded("read the register reply", read_frame(&mut rr)).await;
    drop((rs, rr));
    wait_for_agents(&gw, 1, Duration::from_secs(10)).await;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<u64>();
    let responder = tokio::spawn(async move {
        loop {
            let stream = match conn.accept_bidirectional_stream().await {
                Ok(Some(s)) => s,
                _ => break,
            };
            let (mut recv, mut send) = stream.split();
            let request_id = match read_frame(&mut recv).await {
                Ok(Some(Frame::ProxyRequest { request_id, .. })) => request_id,
                _ => continue,
            };
            let _ = tx.send(request_id);
            // 空 200：head + end，不带 body
            if write_frame(
                &mut send,
                &Frame::ProxyResponseHead {
                    request_id,
                    status: 200,
                    headers: vec![],
                },
            )
            .await
            .is_err()
            {
                break;
            }
            let _ = write_frame(
                &mut send,
                &Frame::ProxyResponseEnd {
                    request_id,
                    ok: true,
                },
            )
            .await;
        }
    });

    let http = test_client();
    let uuid = "0197f1c2-9f0b-7c31-8a44-1b2c3d4e5f60";
    let payload = serde_json::json!({"model": "raw", "messages": []});
    let mut seen = Vec::new();
    for _ in 0..3 {
        for inbound in [None, Some(uuid)] {
            let mut req = http
                .post(format!("{base}/v1/chat/completions"))
                .header("Authorization", format!("Bearer {key}"))
                .json(&payload);
            if let Some(id) = inbound {
                req = req.header("x-request-id", id);
            }
            let resp = req.send().await.unwrap();
            assert_eq!(resp.status(), 200, "裸 agent 回的是空 200");
            seen.push(
                bounded("the agent reported the proxied request", rx.recv())
                    .await
                    .expect("每个请求都应有一条代理流"),
            );
        }
    }

    let mut uniq = seen.clone();
    uniq.sort_unstable();
    uniq.dedup();
    assert_eq!(
        uniq.len(),
        seen.len(),
        "隧道 request_id 撞号：HTTP 层与隧道层必须共用同一个分配器，实得 {seen:?}"
    );

    responder.abort();
    gw.shutdown().await;
}

/// 规格（`PROJECT_SCAN` P1-2）：**带点段的路径不得被转发到上游**。
///
/// `uri.path()` 是**原样**的（HTTP/1.1 与 h2 都不做点段归一），而 agent 把它拼到上游 base
/// 之后才交给 URL 解析器——WHATWG 归一那一刻 `/v1/../api/delete` 就成了 `/api/delete`，
/// 持 key 者因此能驱动上游**任意端点**（Ollama 的 `/api/delete` 直接删模型）。
///
/// 必须用**裸 HTTP**：`reqwest` 在发送前就把 URL 归一了，`/v1/../api/delete` 会变成
/// `/api/delete`（连 `/v1/{*rest}` 都匹配不上），那样根本测不到这条攻击面。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_dot_segment_path_is_rejected_instead_of_forwarded() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, _base, key) = start_stack(4, |_| {}).await;

    let raw_post = |path: &str| {
        let body =
            r#"{"model":"mock-llm","stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
        format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {key}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };
    let raw_delete = |path: &str| {
        format!(
            "DELETE {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {key}\r\n\
             Connection: close\r\n\r\n"
        )
    };
    let status_of = |resp: &[u8]| {
        String::from_utf8_lossy(resp)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    };

    // ① 对照：同一份 body 走正常路径 → 上游确实被调用（200）
    let mut sock = tokio::net::TcpStream::connect(gw.http_addr).await.unwrap();
    sock.write_all(raw_post("/v1/chat/completions").as_bytes())
        .await
        .unwrap();
    let mut resp = Vec::new();
    bounded("read the control response", sock.read_to_end(&mut resp))
        .await
        .unwrap();
    let control = status_of(&resp);
    assert!(
        control.contains(" 200 "),
        "对照请求应当被转发给上游，实际 {control:?}"
    );

    // ② 攻击面：路径里塞点段 → 必须由网关拒绝，而不是"归一之后转发"
    let mut sock = tokio::net::TcpStream::connect(gw.http_addr).await.unwrap();
    sock.write_all(raw_post("/v1/../api/delete").as_bytes())
        .await
        .unwrap();
    let mut resp = Vec::new();
    bounded("read the guarded response", sock.read_to_end(&mut resp))
        .await
        .unwrap();
    let guarded = status_of(&resp);
    assert!(
        guarded.contains(" 400 "),
        "点段路径必须被网关拒绝（P1-2）：被转发给上游就意味着持 key 者可越权访问任意端点，实际 {guarded:?}"
    );

    // ③ 记录在案的**原样 PoC**：`DELETE /v1/../api/delete`（无 body）也必须 400——
    //    守卫在读 body 之前，所以这里不会先撞上"model is required"那条 400 而蒙混过关。
    let mut sock = tokio::net::TcpStream::connect(gw.http_addr).await.unwrap();
    sock.write_all(raw_delete("/v1/../api/delete").as_bytes())
        .await
        .unwrap();
    let mut resp = Vec::new();
    bounded("read the PoC response", sock.read_to_end(&mut resp))
        .await
        .unwrap();
    let poc = status_of(&resp);
    assert!(
        poc.contains(" 400 "),
        "记录里的 PoC（DELETE /v1/../api/delete）必须 400，实际 {poc:?}"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}
