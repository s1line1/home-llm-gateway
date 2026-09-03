//! https 场景 e2e 测试。

use super::common::*;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_https_public_entry() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (ca_pem, srv_pem, srv_key_pem, cli_pem, cli_key_pem) = gen_certs_pem();
    let mock_addr = start_mock_llm("mock-llm").await;
    let (keys_path, key) = seed_keys_db();

    let gw = Gateway::start(GatewayConfig {
        http_bind: "127.0.0.1:0".parse().unwrap(),
        quic_bind: "127.0.0.1:0".parse().unwrap(),
        ca_cert: parse_certs_pem(&ca_pem),
        server_cert: parse_certs_pem(&srv_pem),
        server_key: parse_key_pem(&srv_key_pem),
        admin_token: None,
        keys_file: Some(keys_path),
        request_timeout: Duration::from_secs(10),
        agent_stale_after: Duration::from_secs(10),
        rate_limit_per_min: 0,
        max_concurrent_requests: 0,
        tls: Some(TlsPem {
            cert: srv_pem.clone().into_bytes(),
            key: srv_key_pem.clone().into_bytes(),
        }),
        ui_dir: None,
    })
    .await
    .unwrap();

    let agent = Agent::start(AgentConfig {
        cloud_addr: gw.quic_addr,
        server_name: "localhost".into(),
        ca_cert: parse_certs_pem(&ca_pem),
        client_cert: parse_certs_pem(&cli_pem),
        client_key: parse_key_pem(&cli_key_pem),
        agent_id: "test-agent".into(),
        models: vec!["mock-llm".into()],
        max_concurrency: 4,
        upstream_base: format!("http://{mock_addr}"),
        heartbeat_interval: Duration::from_millis(200),
        request_log: true,
    })
    .unwrap();
    wait_for_agents(&gw, 1, Duration::from_secs(10)).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let base = format!("https://{}", gw.http_addr);

    // healthz 与根路径（管理页）走 HTTPS
    let resp = client.get(format!("{base}/healthz")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // 无 key → 401
    let resp = client
        .get(format!("{base}/v1/models"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // 认证请求穿透到 mock
    let resp = client
        .get(format!("{base}/v1/models"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let models: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(models["data"][0]["id"], "mock-llm");

    // SSE 流式同样走 HTTPS
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({
            "model": "mock-llm",
            "stream": true,
            "messages": [{"role": "user", "content": "https 流式"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert!(text.contains("data: [DONE]"), "missing [DONE]: {text}");

    // 裸 TCP 发非 TLS 字节 → 握手失败（服务端走 warn 分支，连接不崩溃）
    use tokio::io::AsyncWriteExt;
    let mut raw = tokio::net::TcpStream::connect(gw.http_addr).await.unwrap();
    let _ = raw
        .write_all(b"GET / HTTP/1.1\r\n\r\nnot a tls handshake")
        .await;
    let _ = raw.shutdown().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 握手失败后 HTTPS 服务仍正常
    let resp = client.get(format!("{base}/healthz")).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    agent.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_quic_control_stream_edge_frames() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (ca, server_cert, server_key, client_cert, client_key) = gen_certs();

    let gw = Gateway::start(GatewayConfig {
        http_bind: "127.0.0.1:0".parse().unwrap(),
        quic_bind: "127.0.0.1:0".parse().unwrap(),
        ca_cert: vec![ca.clone()],
        server_cert: vec![server_cert.clone()],
        server_key,
        admin_token: None,
        keys_file: None,
        request_timeout: Duration::from_secs(10),
        agent_stale_after: Duration::from_secs(10),
        rate_limit_per_min: 0,
        max_concurrent_requests: 0,
        tls: None,
        ui_dir: None,
    })
    .await
    .unwrap();

    // 裸 quinn 客户端（复用 agent 的 mTLS 配置），不走 agent crate 逻辑
    let client_config = agent::tls::client_config(
        std::slice::from_ref(&ca),
        vec![client_cert.clone()],
        client_key.clone_key(),
    )
    .unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    let conn = endpoint
        .connect(gw.quic_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // 正常注册 → 进入注册表
    let (mut rs, mut rr) = conn.open_bi().await.unwrap();
    write_frame(
        &mut rs,
        &Frame::Register {
            agent_id: "reg-1".into(),
            models: vec!["m".into()],
            max_concurrency: 4,
            version: "test".into(),
        },
    )
    .await
    .unwrap();
    rs.finish().unwrap();
    let _ = read_frame(&mut rr).await;
    assert_eq!(gw.agent_count(), 1);

    // 控制流上发非预期帧（Cancel）→ 服务端走 "unexpected frame" 分支，连接不受影响
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    write_frame(&mut send, &Frame::Cancel { request_id: 1 })
        .await
        .unwrap();
    send.finish().unwrap();
    let _ = read_frame(&mut recv).await;

    // 立即结束的空流 → 服务端走干净 EOF 分支
    let (mut send2, _recv2) = conn.open_bi().await.unwrap();
    send2.finish().unwrap();

    // 未注册 agent 的心跳 → registry 无害忽略
    let (mut send3, mut recv3) = conn.open_bi().await.unwrap();
    write_frame(
        &mut send3,
        &Frame::Heartbeat {
            agent_id: "ghost".into(),
            inflight: 0,
        },
    )
    .await
    .unwrap();
    send3.finish().unwrap();
    let _ = read_frame(&mut recv3).await;

    // 畸形帧（非法长度前缀）→ 控制循环读帧出错 → handle_conn 报错并摘除 reg-1
    let (mut send4, _recv4) = conn.open_bi().await.unwrap();
    send4.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
    send4.finish().unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        gw.agent_count(),
        0,
        "reg-1 should be removed after control-loop error"
    );

    // 第二个裸客户端：注册后直接关闭连接 → accept_bi 出错 → 正常摘除
    let conn2 = endpoint
        .connect(gw.quic_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut rs2, mut rr2) = conn2.open_bi().await.unwrap();
    write_frame(
        &mut rs2,
        &Frame::Register {
            agent_id: "reg-2".into(),
            models: vec![],
            max_concurrency: 4,
            version: "test".into(),
        },
    )
    .await
    .unwrap();
    rs2.finish().unwrap();
    let _ = read_frame(&mut rr2).await;
    assert_eq!(gw.agent_count(), 1);
    conn2.close(0u32.into(), b"bye");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        gw.agent_count(),
        0,
        "reg-2 should be removed after connection close"
    );

    // 错误 CA 签发的客户端证书 → 握手失败 → "connection attempt failed" 分支
    let bad_ca_key = KeyPair::generate().unwrap();
    let mut bad_ca = CertificateParams::default();
    bad_ca
        .distinguished_name
        .push(DnType::CommonName, "other ca");
    bad_ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let bad_ca_cert = bad_ca.self_signed(&bad_ca_key).unwrap();
    let bad_key = KeyPair::generate().unwrap();
    let mut bad_cli = CertificateParams::default();
    bad_cli
        .distinguished_name
        .push(DnType::CommonName, "bad agent");
    let bad_cli_cert = bad_cli
        .signed_by(&bad_key, &bad_ca_cert, &bad_ca_key)
        .unwrap();
    let bad_cfg = agent::tls::client_config(
        &[bad_ca_cert.der().clone()],
        vec![bad_cli_cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(bad_key.serialize_der())),
    )
    .unwrap();
    let mut bad_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    bad_endpoint.set_default_client_config(bad_cfg);
    let _ = bad_endpoint
        .connect(gw.quic_addr, "localhost")
        .unwrap()
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(gw.agent_count(), 0, "failed handshake must not register");

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_proxy_protocol_edge_cases() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (ca, server_cert, server_key, client_cert, client_key) = gen_certs();
    let (keys_path, key) = seed_keys_db();

    // 短转发空闲超时（200ms），用于触发 body 空闲超时场景
    let gw = Gateway::start(GatewayConfig {
        http_bind: "127.0.0.1:0".parse().unwrap(),
        quic_bind: "127.0.0.1:0".parse().unwrap(),
        ca_cert: vec![ca.clone()],
        server_cert: vec![server_cert.clone()],
        server_key,
        admin_token: None,
        keys_file: Some(keys_path),
        request_timeout: Duration::from_millis(200),
        agent_stale_after: Duration::from_secs(10),
        rate_limit_per_min: 0,
        max_concurrent_requests: 0,
        tls: None,
        ui_dir: None,
    })
    .await
    .unwrap();

    // 裸 quinn 客户端：注册后按场景应答网关的代理请求
    let client_config = agent::tls::client_config(
        std::slice::from_ref(&ca),
        vec![client_cert.clone()],
        client_key.clone_key(),
    )
    .unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    let conn = endpoint
        .connect(gw.quic_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut rs, mut rr) = conn.open_bi().await.unwrap();
    write_frame(
        &mut rs,
        &Frame::Register {
            agent_id: "raw-1".into(),
            models: vec!["raw".into()],
            max_concurrency: 10,
            version: "test".into(),
        },
    )
    .await
    .unwrap();
    rs.finish().unwrap();
    let _ = read_frame(&mut rr).await;

    // 应答循环：按场景序号对每个代理流给出不同的（异常）响应
    let client_task = tokio::spawn(async move {
        let mut sc = 0usize;
        loop {
            let (mut send, mut recv) = match conn.accept_bi().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let _ = read_frame(&mut recv).await; // 丢弃 ProxyRequest
            match sc {
                0 => {
                    // 直接回 Error 帧作为响应头
                    write_frame(
                        &mut send,
                        &Frame::Error {
                            request_id: Some(1),
                            code: 503,
                            message: "upstream boom".into(),
                        },
                    )
                    .await
                    .unwrap();
                }
                1 => {
                    // 立即回 ProxyResponseEnd（空响应）
                    write_frame(
                        &mut send,
                        &Frame::ProxyResponseEnd {
                            request_id: 1,
                            ok: true,
                        },
                    )
                    .await
                    .unwrap();
                }
                2 => {
                    // 先 Body 后 Head 再 Body + End（head 前的 body 应被忽略）
                    write_frame(
                        &mut send,
                        &Frame::ProxyResponseBody {
                            request_id: 1,
                            chunk: b"ignored".to_vec(),
                        },
                    )
                    .await
                    .unwrap();
                    write_frame(
                        &mut send,
                        &Frame::ProxyResponseHead {
                            request_id: 1,
                            status: 200,
                            headers: vec![],
                        },
                    )
                    .await
                    .unwrap();
                    write_frame(
                        &mut send,
                        &Frame::ProxyResponseBody {
                            request_id: 1,
                            chunk: b"hello".to_vec(),
                        },
                    )
                    .await
                    .unwrap();
                    write_frame(
                        &mut send,
                        &Frame::ProxyResponseEnd {
                            request_id: 1,
                            ok: true,
                        },
                    )
                    .await
                    .unwrap();
                }
                3 => {
                    // 直接关流，不回复
                }
                4 => {
                    // 响应头是畸形帧（非法长度前缀）
                    send.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
                }
                5 => {
                    // head 200 后回 Error 帧
                    write_frame(
                        &mut send,
                        &Frame::ProxyResponseHead {
                            request_id: 1,
                            status: 200,
                            headers: vec![],
                        },
                    )
                    .await
                    .unwrap();
                    write_frame(
                        &mut send,
                        &Frame::Error {
                            request_id: Some(1),
                            code: 500,
                            message: "mid-stream error".into(),
                        },
                    )
                    .await
                    .unwrap();
                }
                6 => {
                    // head 200 后回 Cancel（应被忽略）再 End
                    write_frame(
                        &mut send,
                        &Frame::ProxyResponseHead {
                            request_id: 1,
                            status: 200,
                            headers: vec![],
                        },
                    )
                    .await
                    .unwrap();
                    write_frame(&mut send, &Frame::Cancel { request_id: 1 })
                        .await
                        .unwrap();
                    write_frame(
                        &mut send,
                        &Frame::ProxyResponseEnd {
                            request_id: 1,
                            ok: true,
                        },
                    )
                    .await
                    .unwrap();
                }
                7 => {
                    // head 200 后直接关流（没有 End）
                    write_frame(
                        &mut send,
                        &Frame::ProxyResponseHead {
                            request_id: 1,
                            status: 200,
                            headers: vec![],
                        },
                    )
                    .await
                    .unwrap();
                }
                8 => {
                    // head 200 后回畸形帧
                    write_frame(
                        &mut send,
                        &Frame::ProxyResponseHead {
                            request_id: 1,
                            status: 200,
                            headers: vec![],
                        },
                    )
                    .await
                    .unwrap();
                    send.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
                }
                9 => {
                    // head 200 后沉默 → 触发网关 body 空闲超时（睡眠须 < 网关头部超时窗口，
                    // 避免阻塞后续场景的应答循环）
                    write_frame(
                        &mut send,
                        &Frame::ProxyResponseHead {
                            request_id: 1,
                            status: 200,
                            headers: vec![],
                        },
                    )
                    .await
                    .unwrap();
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
                _ => {
                    // 正常响应（query string 场景）
                    write_frame(
                        &mut send,
                        &Frame::ProxyResponseHead {
                            request_id: 1,
                            status: 200,
                            headers: vec![("content-type".into(), "text/plain".into())],
                        },
                    )
                    .await
                    .unwrap();
                    write_frame(
                        &mut send,
                        &Frame::ProxyResponseBody {
                            request_id: 1,
                            chunk: b"ok".to_vec(),
                        },
                    )
                    .await
                    .unwrap();
                    write_frame(
                        &mut send,
                        &Frame::ProxyResponseEnd {
                            request_id: 1,
                            ok: true,
                        },
                    )
                    .await
                    .unwrap();
                }
            }
            let _ = send.finish();
            sc += 1;
        }
    });

    let client = reqwest::Client::new();
    let url = |p: &str| format!("http://{}{}", gw.http_addr, p);
    // 注意：/v1/models 已被网关聚合接管（不走代理），帧协议边界场景必须走
    // 代理路径 /v1/chat/completions，并携带 agent 声明的模型（"raw"）
    let post = |p: &str| {
        client
            .post(url(p))
            .header("Authorization", format!("Bearer {key}"))
            .json(&serde_json::json!({ "model": "raw" }))
    };

    // 0: Error 帧作响应头 → 503
    let r = post("/v1/chat/completions").send().await.unwrap();
    assert_eq!(r.status(), 503);
    // 1: 空响应 → 502
    let r = post("/v1/chat/completions").send().await.unwrap();
    assert_eq!(r.status(), 502);
    // 2: head 前 body 被忽略 → 200 + "hello"
    let r = post("/v1/chat/completions").send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "hello");
    // 3: 不回复 → 502
    let r = post("/v1/chat/completions").send().await.unwrap();
    assert_eq!(r.status(), 502);
    // 4: 畸形响应头 → 502
    let r = post("/v1/chat/completions").send().await.unwrap();
    assert_eq!(r.status(), 502);
    // 5: head 200 + Error → 状态 200，body 报错
    let r = post("/v1/chat/completions").send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        r.bytes().await.is_err(),
        "mid-stream error should fail body read"
    );
    // 6: head 200 + Cancel + End → 200 正常
    let r = post("/v1/chat/completions").send().await.unwrap();
    assert_eq!(r.status(), 200);
    let _ = r.bytes().await.unwrap();
    // 7: head 200 + 提前关流 → 200，body 报错
    let r = post("/v1/chat/completions").send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        r.bytes().await.is_err(),
        "early close should fail body read"
    );
    // 8: head 200 + 畸形 → 200，body 报错
    let r = post("/v1/chat/completions").send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        r.bytes().await.is_err(),
        "garbage body should fail body read"
    );
    // 9: head 200 + 沉默 → 空闲超时 → 200，body 报错
    let r = post("/v1/chat/completions").send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        r.bytes().await.is_err(),
        "idle timeout should fail body read"
    );
    // 10: 带 query string 的请求 → 200
    let r = post("/v1/chat/completions?foo=bar").send().await.unwrap();
    assert_eq!(r.status(), 200);
    let _ = r.bytes().await.unwrap();

    client_task.abort();
    gw.shutdown().await;
}
