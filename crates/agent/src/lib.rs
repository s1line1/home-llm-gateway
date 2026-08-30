//! home-agent：常驻家里，主动拨 QUIC 长连接上云，把云端请求转发给本地 LLM。

pub mod tls;

use std::{net::SocketAddr, time::Duration};

use proto::{io::{read_frame, write_frame}, Frame};
use futures_util::StreamExt;
use quinn::Connection;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{info, warn};

/// 逐跳头，转发时剔除。
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

pub struct AgentConfig {
    /// 云端网关 QUIC 地址。
    pub cloud_addr: SocketAddr,
    /// 证书校验用的服务器名（须与网关证书 SAN 匹配）。
    pub server_name: String,
    pub ca_cert: Vec<CertificateDer<'static>>,
    pub client_cert: Vec<CertificateDer<'static>>,
    pub client_key: PrivateKeyDer<'static>,
    pub agent_id: String,
    pub models: Vec<String>,
    pub max_concurrency: u32,
    /// 本地 LLM 的 OpenAI 兼容地址，如 http://127.0.0.1:11434
    pub upstream_base: String,
    pub heartbeat_interval: Duration,
    /// 是否打印每请求的转发日志（received/responded/done/cancelled）。
    /// 高并发/压测时建议关闭，避免日志刷屏；连接/注册等低频日志不受此开关影响。
    pub request_log: bool,
}

pub struct Agent {
    task: tokio::task::JoinHandle<()>,
}

impl Agent {
    pub fn start(cfg: AgentConfig) -> anyhow::Result<Self> {
        let client_config = tls::client_config(
            &cfg.ca_cert,
            cfg.client_cert.clone(),
            cfg.client_key.clone_key(),
        )?;
        let task = tokio::spawn(run(cfg, client_config));
        Ok(Self { task })
    }

    pub async fn shutdown(self) {
        self.task.abort();
    }
}

async fn run(cfg: AgentConfig, client_config: quinn::ClientConfig) {
    let mut delay = Duration::from_millis(500);
    loop {
        match connect_once(&cfg, client_config.clone()).await {
            Ok(()) => {
                info!("disconnected from cloud, reconnecting");
                delay = Duration::from_millis(500);
            }
            Err(e) => warn!("agent error: {e}; retrying in {delay:?}"),
        }
        tokio::time::sleep(delay).await;
        delay = std::cmp::min(delay.saturating_mul(2), Duration::from_secs(30));
    }
}

async fn connect_once(cfg: &AgentConfig, client_config: quinn::ClientConfig) -> anyhow::Result<()> {
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0)))?;
    endpoint.set_default_client_config(client_config);
    let conn = endpoint
        .connect(cfg.cloud_addr, &cfg.server_name)?
        .await?;
    info!("connected to cloud gateway at {}", cfg.cloud_addr);

    register(&conn, cfg).await?;
    info!(
        agent_id = %cfg.agent_id,
        models = ?cfg.models,
        max_concurrency = cfg.max_concurrency,
        "registered with cloud gateway"
    );

    let hb = tokio::spawn(heartbeat_loop(
        conn.clone(),
        cfg.agent_id.clone(),
        cfg.heartbeat_interval,
    ));

    let http = reqwest::Client::new();
    let upstream = cfg.upstream_base.clone();
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(_) => break,
        };
        let http = http.clone();
        let upstream = upstream.clone();
        let request_log = cfg.request_log;
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, &http, &upstream, request_log).await {
                warn!("proxy stream error: {e}");
            }
        });
    }

    hb.abort();
    Ok(())
}

async fn register(conn: &Connection, cfg: &AgentConfig) -> anyhow::Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    write_frame(
        &mut send,
        &Frame::Register {
            agent_id: cfg.agent_id.clone(),
            models: cfg.models.clone(),
            max_concurrency: cfg.max_concurrency,
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
    )
    .await?;
    send.finish()?;
    // 网关不发 ack；读到 EOF 即可
    while read_frame(&mut recv).await?.is_some() {}
    Ok(())
}

async fn heartbeat_loop(conn: Connection, agent_id: String, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        match conn.open_bi().await {
            Ok((mut send, mut recv)) => {
                let _ = write_frame(&mut send, &Frame::Heartbeat { agent_id: agent_id.clone(), inflight: 0 }).await;
                let _ = send.finish();
                let _ = read_frame(&mut recv).await; // 等 EOF
            }
            Err(_) => break,
        }
    }
}

/// 处理一条代理流：读 ProxyRequest → 转发本地 LLM → 流式回传响应帧。
/// `request_log` 控制每请求的 INFO 日志（received/responded/done/cancelled）。
async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    http: &reqwest::Client,
    upstream: &str,
    request_log: bool,
) -> anyhow::Result<()> {
    let Some(Frame::ProxyRequest { request_id, method, path, headers, body }) = read_frame(&mut recv).await? else {
        anyhow::bail!("expected ProxyRequest frame");
    };
    let started = std::time::Instant::now();
    if request_log {
        info!(request_id, method = %method, path = %path, body_bytes = body.len(), "proxy request received");
    }

    let url = format!("{upstream}{path}");
    let mut rb = http.request(reqwest::Method::from_bytes(method.as_bytes())?, &url);
    for (k, v) in headers {
        if !HOP_BY_HOP.contains(&k.as_str()) {
            if let Ok(v) = reqwest::header::HeaderValue::from_str(&v) {
                rb = rb.header(k, v);
            }
        }
    }
    rb = rb.body(body);

    // 发送上游请求；期间可收到 Cancel 帧 → 立即取消
    let send_fut = rb.send();
    tokio::pin!(send_fut);
    let resp = loop {
        tokio::select! {
            r = &mut send_fut => break r?,
            f = read_frame(&mut recv) => {
                match f? {
                    Some(Frame::Cancel { .. }) | None => {
                        return send_cancelled(&mut send, request_id, started, request_log).await;
                    }
                    Some(_) => {}
                }
            }
        }
    };

    let status = resp.status().as_u16();
    let mut out_headers = Vec::new();
    for (k, v) in resp.headers() {
        let name = k.as_str();
        if HOP_BY_HOP.contains(&name) {
            continue;
        }
        if let Ok(v) = v.to_str() {
            out_headers.push((name.to_string(), v.to_string()));
        }
    }
    write_frame(&mut send, &Frame::ProxyResponseHead { request_id, status, headers: out_headers }).await?;
    if request_log {
        info!(request_id, status, elapsed_ms = started.elapsed().as_millis() as u64, "upstream responded");
    }

    // M2：流式透传——上游 body 逐块转 ProxyResponseBody 帧（SSE 天然支持），
    // 期间持续监听 Cancel，收到即中止，避免白算 token。
    let body_stream = resp.bytes_stream();
    tokio::pin!(body_stream);
    let mut ok = true;
    let mut bytes_out = 0u64;
    loop {
        tokio::select! {
            chunk = body_stream.next() => {
                match chunk {
                    Some(Ok(bytes)) => {
                        bytes_out += bytes.len() as u64;
                        write_frame(&mut send, &Frame::ProxyResponseBody { request_id, chunk: bytes.to_vec() }).await?;
                    }
                    Some(Err(e)) => {
                        warn!(request_id, "upstream stream error: {e}");
                        ok = false;
                        break;
                    }
                    None => break,
                }
            }
            f = read_frame(&mut recv) => {
                match f? {
                    Some(Frame::Cancel { .. }) | None => {
                        return send_cancelled(&mut send, request_id, started, request_log).await;
                    }
                    Some(_) => {}
                }
            }
        }
    }

    write_frame(&mut send, &Frame::ProxyResponseEnd { request_id, ok }).await?;
    send.finish()?;
    if request_log {
        info!(
            request_id,
            status,
            ok,
            bytes_out,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "proxy request done"
        );
    }
    Ok(())
}

async fn send_cancelled(
    send: &mut quinn::SendStream,
    request_id: u64,
    started: std::time::Instant,
    request_log: bool,
) -> anyhow::Result<()> {
    if request_log {
        info!(request_id, elapsed_ms = started.elapsed().as_millis() as u64, "request cancelled by gateway");
    }
    let _ = write_frame(
        send,
        &Frame::Error {
            request_id: Some(request_id),
            code: 499,
            message: "cancelled by client".into(),
        },
    )
    .await;
    let _ = send.finish();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, SanType,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;

    /// 生成 (CA, 服务端证书, 服务端私钥, 客户端证书, 客户端私钥) 的 DER。
    fn gen_pki() -> (
        CertificateDer<'static>,
        CertificateDer<'static>,
        PrivateKeyDer<'static>,
        CertificateDer<'static>,
        PrivateKeyDer<'static>,
    ) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "test ca");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let srv_key = KeyPair::generate().unwrap();
        let mut srv = CertificateParams::default();
        srv.distinguished_name.push(DnType::CommonName, "gw");
        srv.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
        srv.is_ca = IsCa::NoCa;
        srv.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        srv.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let srv_cert = srv.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();

        let cli_key = KeyPair::generate().unwrap();
        let mut cli = CertificateParams::default();
        cli.distinguished_name
            .push(DnType::CommonName, "agent");
        cli.is_ca = IsCa::NoCa;
        cli.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        cli.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let cli_cert = cli.signed_by(&cli_key, &ca_cert, &ca_key).unwrap();

        (
            ca_cert.der().clone(),
            srv_cert.der().clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(srv_key.serialize_der())),
            cli_cert.der().clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cli_key.serialize_der())),
        )
    }

    /// 建立一对本地 QUIC 端点并返回客户端连接（无 mTLS）。
    async fn test_connection() -> Connection {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cert_der = CertificateDer::from(cert.der().clone());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        let quic = QuicServerConfig::try_from(tls).unwrap();
        let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(quic));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
        scfg.transport_config(Arc::new(transport));
        let server = quinn::Endpoint::server(scfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                tokio::spawn(async move {
                    // 保持连接存活到测试结束，避免服务端 drop 导致连接提前关闭
                    if let Ok(conn) = incoming.await {
                        conn.closed().await;
                    }
                });
            }
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let client_tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let client_cfg =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls).unwrap()));
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(client_cfg);
        client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap()
    }

    /// 用 CA 签发的服务端证书建 mTLS QUIC server，把接到的连接发给测试。
    async fn test_server(
        ca: &CertificateDer<'static>,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> (SocketAddr, tokio::sync::mpsc::Receiver<Connection>) {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert], key)
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()]; // 与 agent 客户端 ALPN 匹配
        let quic = QuicServerConfig::try_from(tls).unwrap();
        let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(quic));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
        scfg.transport_config(Arc::new(transport));
        let server = quinn::Endpoint::server(scfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        let _ = tx.send(conn.clone()).await;
                        conn.closed().await;
                    }
                });
            }
        });
        (addr, rx)
    }

    fn test_agent_config(
        cloud_addr: SocketAddr,
        ca: CertificateDer<'static>,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> AgentConfig {
        AgentConfig {
            cloud_addr,
            server_name: "localhost".into(),
            ca_cert: vec![ca],
            client_cert: vec![cert],
            client_key: key,
            agent_id: "t".into(),
            models: vec!["m".into()],
            max_concurrency: 2,
            upstream_base: "http://127.0.0.1:1".into(),
            heartbeat_interval: Duration::from_millis(50),
            request_log: true,
        }
    }

    #[tokio::test]
    async fn heartbeat_loop_breaks_when_connection_closed() {
        let conn = test_connection().await;
        // 显式关闭连接：之后 open_bi 必然失败 → 心跳循环 break 退出
        conn.close(0u32.into(), b"test close");
        heartbeat_loop(conn, "agent-x".into(), Duration::from_millis(10)).await;
    }

    #[tokio::test]
    async fn heartbeat_loop_sends_frames_on_live_connection() {
        let conn = test_connection().await;
        // 间隔 20ms、运行 100ms：应至少成功发送几次心跳（写帧 + 读 EOF）
        let task = tokio::spawn(heartbeat_loop(
            conn.clone(),
            "agent-y".into(),
            Duration::from_millis(20),
        ));
        tokio::time::sleep(Duration::from_millis(120)).await;
        // 连接仍存活（未被心跳逻辑破坏）
        assert!(conn.open_bi().await.is_ok());
        task.abort();
    }

    #[tokio::test]
    async fn run_loop_retries_when_connect_fails() {
        let (ca, _srv_cert, _srv_key, cli_cert, cli_key) = gen_pki();
        let cfg = test_agent_config(
            SocketAddr::from(([127, 0, 0, 1], 1)), // 必然连接失败
            ca,
            cli_cert,
            cli_key,
        );
        let cc = tls::client_config(
            &cfg.ca_cert,
            cfg.client_cert.clone(),
            cfg.client_key.clone_key(),
        )
        .unwrap();
        let task = tokio::spawn(run(cfg, cc));
        // 第一次连接失败 → Err 分支 → 退避重试（覆盖 71/73-74 行）
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert!(!task.is_finished(), "run loop should keep retrying");
        task.abort();
    }

    #[tokio::test]
    async fn run_loop_handles_clean_disconnect() {
        let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
        let (addr, mut rx) = test_server(&ca, srv_cert, srv_key).await;
        let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
        let cc = tls::client_config(
            &cfg.ca_cert,
            cfg.client_cert.clone(),
            cfg.client_key.clone_key(),
        )
        .unwrap();
        let task = tokio::spawn(run(cfg, cc));
        // 等 agent 连上
        let server_conn = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("agent should connect")
            .unwrap();
        // 服务端主动关闭连接 → agent 干净断开（Ok 分支）→ 退避重连
        server_conn.close(0u32.into(), b"bye");
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert!(!task.is_finished(), "run loop should keep running after disconnect");
        task.abort();
    }
}
