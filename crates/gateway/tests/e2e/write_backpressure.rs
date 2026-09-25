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

    // e2e-bare-client: 要的就是"写背压把请求卡住直到网关写超时"，客户端不能自己先超时
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
    // 有界客户端（重扫 F2）：以前这里是 `reqwest::get`，它内部的 client 默认无超时
    let text = test_client()
        .get(format!("{base}/metrics"))
        .send()
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

/// "读到一半就停"的裸 agent 最终**解出了什么**——H8 的判据只能由对端自己给。
#[derive(Debug)]
pub enum HalfReadOutcome {
    /// 解出了一个**完整**的 `ProxyRequest`：写到一半被放弃的帧仍然被执行了（双执行——H8 的红）。
    CompleteRequestFrame,
    /// 帧中途 EOF：网关放弃那条流时 `SendStream` 的 Drop 会 `finish()`，对端 `read_exact`
    /// 拿到 `UnexpectedEof` ⇒ 请求永远不会被处理。
    ///
    /// 第二项：对端是**读到流结束**（`read` 返回 0）还是"3 秒静默"——`true` 才证明网关
    /// 关掉了那条被放弃的流，而不是把它挂在那里（H8 原记录的另一种担忧）。
    EofMidFrame(String, bool),
    /// 恢复读取后一个字节都没再来（既没帧也没 EOF）。
    NothingMore,
    /// 读取出错。
    ReadError(String),
}

/// 起一个**读到一半就停**的裸 QUIC agent：注册成功后接受第一条请求流、只读一小段就停住
/// （让网关的 `write_frame` 撑爆流控窗口而超时），随后由调用方发信号让它**恢复读取**，
/// 并把"最终解出了什么"报告回来。
///
/// 为什么必须有这个 peer（评估记录 H8）：`write_frame` 是一次非原子的 `write_all`，写超时
/// 只意味着"没写完"，而"没写完的帧会不会仍然被执行"只能由对端回答。
async fn spawn_half_reading_agent(
    gw: &Gateway,
    certs: &TestCerts,
    agent_id: &str,
    first_read: usize,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<HalfReadOutcome>,
) {
    use tokio::io::AsyncReadExt;

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

    // 注册（与 `spawn_raw_agent` 同一套；注册流由 agent 自己开）
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

    let (go_tx, go_rx) = tokio::sync::oneshot::channel();
    let (out_tx, out_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        // `conn` 已被 `split()` 消耗，保活靠它分出来的 handle/acceptor
        let _keep_alive = (client, handle, reg_recv);
        let Ok(Some(stream)) = acceptor.accept_bidirectional_stream().await else {
            let _ = out_tx.send(HalfReadOutcome::ReadError("no request stream".into()));
            return;
        };
        let (mut recv, _send) = stream.split();

        // ① 只读第一小段就停住：之后的字节留在流控窗口里，网关的写会 park 到超时。
        //    ⚠️ 这一小段必须留在手里：帧是从**第一个字节**开始按长度前缀解析的，
        //    恢复读取时把它丢掉就会错位，`FrameReader` 会把垃圾当长度（实测报 "frame too large"）。
        let mut first = vec![0u8; first_read];
        let mut acc: Vec<u8> = Vec::new();
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut first)).await
        {
            acc.extend_from_slice(&first[..n]);
        }

        // ② 等调用方放行（此时网关已经超时、重试并放弃过这条流）
        let _ = go_rx.await;

        // ③ 把之后收到的一切都接在后面（EOF / 出错 / 静默 3s 为止）
        let mut read_error: Option<String> = None;
        let mut saw_eof = false;
        loop {
            let mut buf = vec![0u8; 64 * 1024];
            match tokio::time::timeout(Duration::from_secs(3), recv.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    saw_eof = true;
                    break;
                }
                Err(_) => break, // 静默：没等到 EOF
                Ok(Ok(n)) => acc.extend_from_slice(&buf[..n]),
                Ok(Err(e)) => {
                    read_error = Some(e.to_string());
                    break;
                }
            }
        }

        // ④ 用**生产代码的读取器**解释这堆字节：能解出完整 ProxyRequest 才是双执行。
        let outcome = match proto::io::FrameReader::new(&acc[..]).next().await {
            Ok(Some(Frame::ProxyRequest { .. })) => HalfReadOutcome::CompleteRequestFrame,
            Ok(Some(other)) => {
                HalfReadOutcome::EofMidFrame(format!("解出的是别的帧：{other:?}"), saw_eof)
            }
            Ok(None) => match read_error {
                Some(e) => HalfReadOutcome::ReadError(e),
                None => HalfReadOutcome::NothingMore,
            },
            Err(e) => HalfReadOutcome::EofMidFrame(e.to_string(), saw_eof),
        };
        let _ = out_tx.send(outcome);
    });

    (go_tx, out_rx)
}

/// 规格（评估记录 H8 的验证）：**写到一半被超时放弃的帧，不可能在对端变成一次执行**。
///
/// H8 的担忧是"整帧已送达而超时先到 ⇒ 换 agent 重放 ⇒ 双执行"。用一个**读到一半就停**的
/// peer 直接验证：网关的写超时之后（`hlmg_tunnel_write_failures_total{class="backpressure"}`），
/// 让对端恢复读取，用生产代码的 `FrameReader` 解释它收到的字节——它只能拿到真帧的一个前缀
/// （机制见 `proto::io::tests::a_timed_out_write_leaves_only_a_strict_prefix_of_the_frame`），
/// 因此**永远解不出完整的 `ProxyRequest`**。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_a_write_that_times_out_mid_frame_never_reaches_the_agent_as_a_request() {
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

    // 只读 64 字节就停：剩下的 8 MiB 帧必然撑爆流控窗口
    let (go, outcome) = spawn_half_reading_agent(&gw, &certs, "half-reader", 64).await;

    let big = "x".repeat(8 * 1024 * 1024);
    // e2e-bare-client: client 本身不带超时，但整个请求被外层 `timeout(10s)` 包住（有界）
    let resp = tokio::time::timeout(
        Duration::from_secs(10),
        reqwest::Client::new()
            .post(format!("{base}/v1/chat/completions"))
            .header("Authorization", format!("Bearer {key}"))
            .json(&serde_json::json!({
                "model": "mock-llm",
                "messages": [{ "role": "user", "content": big }],
            }))
            .send(),
    )
    .await
    .expect("请求必须在隧道超时量级内结束")
    .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_GATEWAY,
        "前提：这次失败必须来自**写帧超时**（不是等响应头）"
    );
    let body = resp.text().await.unwrap_or_default();
    assert!(
        body.contains("tunnel write timed out"),
        "前提：失败原因应当是写超时，实际：{body}"
    );
    let backpressure = metric_gauge(
        &base,
        "hlmg_tunnel_write_failures_total{class=\"backpressure\"}",
    )
    .await;
    assert!(backpressure >= 1, "前提：写超时必须被记成背压");

    // 让对端恢复读取，看它到底能解出什么
    go.send(()).unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(10), outcome)
        .await
        .expect("对端应当在几秒内报告结论")
        .unwrap();
    match &outcome {
        // 期望形态：对端只拿到真帧的前缀，读到流结束时 `read_exact` 报"帧中途 EOF"。
        HalfReadOutcome::EofMidFrame(e, saw_eof) => {
            assert!(
                e.contains("early eof"),
                "半帧必须表现为「帧中途 EOF」；报别的错说明对端字节流错位或损坏，值得查：{e}"
            );
            assert!(
                *saw_eof,
                "对端必须是**读到流结束**才停在半帧的——那说明网关关掉了被放弃的流；\
                 若是「静默 3 秒」则说明它还挂着（H8 原记录的另一种担忧）"
            );
        }
        // 这两种同样是"没执行"（流被 reset、或对端恢复读取后什么都没再来）
        HalfReadOutcome::ReadError(e) => {
            eprintln!("H8: 对端读到流错误（也算没执行）：{e}")
        }
        HalfReadOutcome::NothingMore => eprintln!("H8: 对端恢复读取后没有新字节（也算没执行）"),
        // 这一档才是 H8 的红：写到一半被放弃的帧仍然被执行了
        HalfReadOutcome::CompleteRequestFrame => {
            panic!("写到一半被放弃的帧在对端变成了**完整请求**——那就是双执行（H8）")
        }
    }
    eprintln!("H8: 卡在中途的 peer 最终看到：{outcome:?}");

    gw.shutdown().await;
}
