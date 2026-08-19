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
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, &http, &upstream).await {
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
async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    http: &reqwest::Client,
    upstream: &str,
) -> anyhow::Result<()> {
    let Some(Frame::ProxyRequest { request_id, method, path, headers, body }) = read_frame(&mut recv).await? else {
        anyhow::bail!("expected ProxyRequest frame");
    };

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
                        return send_cancelled(&mut send, request_id).await;
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

    // M2：流式透传——上游 body 逐块转 ProxyResponseBody 帧（SSE 天然支持），
    // 期间持续监听 Cancel，收到即中止，避免白算 token。
    let body_stream = resp.bytes_stream();
    tokio::pin!(body_stream);
    let mut ok = true;
    loop {
        tokio::select! {
            chunk = body_stream.next() => {
                match chunk {
                    Some(Ok(bytes)) => {
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
                        return send_cancelled(&mut send, request_id).await;
                    }
                    Some(_) => {}
                }
            }
        }
    }

    write_frame(&mut send, &Frame::ProxyResponseEnd { request_id, ok }).await?;
    send.finish()?;
    Ok(())
}

async fn send_cancelled(send: &mut quinn::SendStream, request_id: u64) -> anyhow::Result<()> {
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
