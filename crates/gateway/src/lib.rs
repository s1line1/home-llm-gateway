//! cloud-gateway：公网 OpenAI 兼容入口（可选 HTTPS）+ QUIC 隧道服务端。

pub mod admin;
pub mod error;
pub mod http;
pub mod keystore;
pub mod metrics;
pub mod quic;
pub mod ratelimit;
pub mod registry;
pub mod tls;

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::Router;
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tower::Service as TowerService;
use tracing::{info, warn};

use crate::{keystore::KeyStore, metrics::Metrics, ratelimit::RateLimiter, registry::Registry};

/// HTTPS 证书 PEM 内容。
pub struct TlsPem {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

pub struct GatewayConfig {
    /// HTTP(S) 公网入口监听地址。
    pub http_bind: SocketAddr,
    /// QUIC 隧道监听地址（UDP）。
    pub quic_bind: SocketAddr,
    /// 签发 agent 客户端证书的 CA 证书。
    pub ca_cert: Vec<CertificateDer<'static>>,
    pub server_cert: Vec<CertificateDer<'static>>,
    pub server_key: PrivateKeyDer<'static>,
    /// Admin token；提供后启用 /admin/keys 管理接口。
    pub admin_token: Option<String>,
    /// 动态 API Key 持久化文件（None = 仅内存）。
    pub keys_file: Option<PathBuf>,
    /// 单次请求转发空闲超时（逐帧）。
    pub request_timeout: Duration,
    /// 超过该时长未心跳的 agent 视为失联。
    pub agent_stale_after: Duration,
    /// 每个 API Key 每分钟请求上限（0 = 不限流）。
    pub rate_limit_per_min: u32,
    /// 提供后，公网入口启用 HTTPS（rustls）。
    pub tls: Option<TlsPem>,
    /// React UI 静态目录（含 index.html；存在时 `/` 托管 Dashboard，否则显示构建提示页）。
    pub ui_dir: Option<PathBuf>,
}

pub struct Gateway {
    pub http_addr: SocketAddr,
    pub quic_addr: SocketAddr,
    registry: Registry,
    _endpoint: quinn::Endpoint,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Gateway {
    pub async fn start(cfg: GatewayConfig) -> Result<Self, crate::error::GatewayError> {
        // 显式安装 ring 为进程默认 crypto provider，保证各 rustls 使用方一致
        let _ = rustls::crypto::ring::default_provider().install_default();

        let registry = Registry::default();

        let server_config = tls::server_config(&cfg.ca_cert, cfg.server_cert, cfg.server_key)?;
        let endpoint = quinn::Endpoint::server(server_config, cfg.quic_bind)?;
        let quic_addr = endpoint.local_addr()?;

        let listener = tokio::net::TcpListener::bind(cfg.http_bind).await?;
        let http_addr = listener.local_addr()?;

        // UI 静态目录：仅当目录内存在 index.html 时启用（否则 `/` 显示构建提示页）
        let ui = cfg.ui_dir.as_ref().and_then(|p| {
            if p.join("index.html").is_file() {
                Some(p.clone())
            } else {
                warn!(path = %p.display(), "ui_dir set but index.html not found; GET / will show a placeholder");
                None
            }
        });

        let state = http::AppState {
            registry: registry.clone(),
            key_store: KeyStore::new(cfg.keys_file.clone()),
            admin_token: cfg.admin_token,
            timeout: cfg.request_timeout,
            agent_stale_after: cfg.agent_stale_after,
            rate_limiter: RateLimiter::new(cfg.rate_limit_per_min),
            metrics: Metrics::default(),
            ui,
        };
        let app = http::app(state);

        let mut tasks = Vec::new();
        match cfg.tls {
            Some(tls) => {
                info!(addr = %cfg.http_bind, "https public entry enabled");
                tasks.push(tokio::spawn(async move {
                    if let Err(e) = serve_https(listener, app, tls).await {
                        warn!("https server stopped: {e}");
                    }
                }));
            }
            None => {
                info!(addr = %cfg.http_bind, "http public entry enabled");
                tasks.push(tokio::spawn(async move {
                    if let Err(e) = axum::serve(listener, app).await {
                        warn!("http server stopped: {e}");
                    }
                }));
            }
        }
        tasks.push(tokio::spawn(quic::accept_loop(
            endpoint.clone(),
            registry.clone(),
        )));

        Ok(Self {
            http_addr,
            quic_addr,
            registry,
            _endpoint: endpoint,
            tasks,
        })
    }

    /// 当前在线 agent 数（测试/可观测性用）。
    pub fn agent_count(&self) -> usize {
        self.registry.len()
    }

    pub async fn shutdown(self) {
        for t in self.tasks {
            t.abort();
        }
    }
}

/// 基于 tokio-rustls 的 HTTPS accept 循环（每连接一个任务）。
async fn serve_https(
    listener: tokio::net::TcpListener,
    app: Router,
    tls: TlsPem,
) -> anyhow::Result<()> {
    let server_config = tls::https_server_config(&tls.cert, &tls.key)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = TokioIo::new(tls_stream);
                    // 桥接 hyper(0.4 Service) 与 axum(tower 0.5 Service)
                    let service = service_fn(move |req: hyper::Request<Incoming>| {
                        let mut app = app.clone();
                        async move { app.call(req).await }
                    });
                    if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                        warn!("https connection {peer} error: {e}");
                    }
                }
                Err(e) => warn!("tls handshake from {peer} failed: {e}"),
            }
        });
    }
}
pub mod config;
pub mod http_proxy;
