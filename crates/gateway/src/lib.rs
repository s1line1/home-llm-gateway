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
use tracing::{error, info, warn};

use crate::{keystore::KeyStore, metrics::Metrics, ratelimit::RateLimiter, registry::Registry};

/// HTTPS 证书 PEM 内容。
#[derive(Debug)]
pub struct TlsPem {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

#[derive(Debug)]
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
    /// 已验证身份缓存容量（0 = 关闭，每请求都跑 argon2 校验）。
    ///
    /// 见 `keystore::verified` 的说明：argon2 每次占 19MiB 工作内存，缓存 + 单飞
    /// 把它的成本从"每请求"降到"每(凭据版本)"，且不影响吊销即时性。
    pub verified_cache_max: usize,
    /// 单次请求转发空闲超时（逐帧）。
    pub request_timeout: Duration,
    /// 隧道控制操作超时（打开流 / 发送请求头 / 取消帧）。
    ///
    /// 与 `request_timeout` 的区别：后者是**逐帧空闲**超时，覆盖整个响应阶段（SSE 长流
    /// 靠"有帧就不超时"活着，不能收紧）；前者只覆盖"响应头到达之前"那几步——健康隧道
    /// 毫秒级完成，一旦超时即判定该 agent 的连接已死并摘除条目。没有它，隧道坏掉时
    /// 这些 await 可能长时间不返回，请求会一直挂在那里占着连接与缓冲。
    pub tunnel_op_timeout: Duration,
    /// 等待上游响应头（首字节）的超时。
    ///
    /// 独立于 `tunnel_op_timeout`：上游"思考"时间是合法的（本地大模型 1–3s 常见），
    /// 用 2s 的隧道控制超时去卡会误杀正常请求；但也不该沿用 `request_timeout`（120s），
    /// 否则 agent 卡死时每个请求都把连接与缓冲占满两分钟（实测 40 并发钉住约 620MB）。
    pub head_timeout: Duration,
    /// 超过该时长未心跳的 agent 视为失联。
    pub agent_stale_after: Duration,
    /// 每个 API Key 每分钟请求上限（0 = 不限流）。
    pub rate_limit_per_min: u32,
    /// HTTP 全局在途请求上限（0 = 不限）。
    pub max_concurrent_requests: u32,
    /// 提供后，公网入口启用 HTTPS（rustls）。
    pub tls: Option<TlsPem>,
    /// React UI 静态目录（含 index.html；存在时 `/` 托管 Dashboard，否则显示构建提示页）。
    pub ui_dir: Option<PathBuf>,
}

pub struct Gateway {
    pub http_addr: SocketAddr,
    pub quic_addr: SocketAddr,
    registry: Registry,
    /// 用量落库需要在关闭前强制 flush 一次（见 `Gateway::flush_usage_on_shutdown`）。
    key_store: KeyStore,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Gateway {
    pub async fn start(cfg: GatewayConfig) -> Result<Self, crate::error::GatewayError> {
        // 显式安装 ring 为进程默认 crypto provider（见 proto::install_ring_crypto_provider 的说明：
        // workspace 同时链接了 ring 与 aws-lc-rs，不安装 rustls 会 panic）
        proto::install_ring_crypto_provider();

        let registry = Registry::default();

        let tls = tls::rustls_server_tls(&cfg.ca_cert, cfg.server_cert, cfg.server_key)?;
        // HTTPS 侧的 TLS 材料同样在**碰任何资源之前**校验：构建不出 rustls 配置就必须
        // 让启动失败（fail fast）。否则进程会"启动成功"却从未监听公网端口——systemd
        // 显示 active(running)、日志写着 Gateway ready，而端口是 connection refused；
        // 且 /healthz、/metrics、/admin/* 全在同一端口上，可观测性一起陪葬。
        let https: Option<Arc<rustls::ServerConfig>> = match &cfg.tls {
            Some(tls) => Some(Arc::new(
                tls::https_server_config(&tls.cert, &tls.key).map_err(|e| {
                    crate::error::GatewayError::Config(format!(
                        "tls_cert/tls_key 无法构建 HTTPS 服务端配置: {e}"
                    ))
                })?,
            )),
            None => None,
        };

        let server = s2n_quic::Server::builder()
            .with_tls(s2n_quic::provider::tls::rustls::Server::from(Arc::new(tls)))?
            .with_io(cfg.quic_bind)?
            .start()?;

        let quic_addr = server.local_addr()?;

        let listener = tokio::net::TcpListener::bind(cfg.http_bind).await?;
        let http_addr = listener.local_addr()?;

        // UI 静态目录：必须确认它是**一份能用的产物**，而不只是"有 index.html"——
        // Vite 的源码目录同样有 index.html，托管出去只会让浏览器白屏（见 http::check_ui_dir）。
        // 判定不通过就降级到占位页，并把具体原因写进 state，让页面自己说清楚。
        let (ui, ui_problem) = match cfg.ui_dir.as_deref() {
            None => (None, None),
            Some(p) => match http::check_ui_dir(p) {
                http::UiDirCheck::Usable => (Some(p.to_path_buf()), None),
                // 还没构建：占位页自带的通用文案（"构建前端后配置 ui_dir"）正好适用
                http::UiDirCheck::NoIndex => {
                    warn!(path = %p.display(), "ui_dir 下没有 index.html；GET / 显示构建提示页");
                    (None, None)
                }
                http::UiDirCheck::SourceEntry => {
                    let msg = format!(
                        "ui_dir 指向的是前端**源码**目录，不是构建产物（默认 web/dist）：{}",
                        p.display()
                    );
                    error!(path = %p.display(), "{msg}；浏览器只会白屏，GET / 已改显示本提示页");
                    (None, Some(msg))
                }
                http::UiDirCheck::MissingAsset(asset) => {
                    let msg = format!(
                        "index.html 引用的产物不存在：{asset}（构建过期，或 ui_dir 指向了别处）"
                    );
                    warn!(path = %p.display(), missing = %asset, "{msg}；GET / 显示构建提示页");
                    (None, Some(msg))
                }
            },
        };

        let metrics = Metrics::default();
        let key_store = KeyStore::with_verified(
            cfg.keys_file.clone(),
            cfg.verified_cache_max,
            crate::keystore::DEFAULT_VERIFIED_TTL,
        );
        // 用量落库：后台按周期把各 key 的累计值批量写一次（热路径只做内存累加，
        // 见 `http_proxy::UsageCollector::finish`）。关闭前由
        // `flush_usage_on_shutdown` 补最后一刀，保证不丢。
        let usage_flusher = usage_flush::spawn(key_store.clone());
        let state = http::AppState {
            registry: registry.clone(),
            key_store: key_store.clone(),
            admin_token: cfg.admin_token,
            timeout: cfg.request_timeout,
            agent_stale_after: cfg.agent_stale_after,
            tunnel_op_timeout: cfg.tunnel_op_timeout,
            head_timeout: cfg.head_timeout,
            rate_limiter: RateLimiter::new(cfg.rate_limit_per_min),
            max_concurrent_requests: cfg.max_concurrent_requests,
            metrics: metrics.clone(),
            ui,
            ui_problem,
        };
        let app = http::app(state);

        let mut tasks = Vec::new();
        match https {
            Some(https) => {
                info!(addr = %cfg.http_bind, "https public entry enabled");
                tasks.push(tokio::spawn(async move {
                    if let Err(e) = serve_https(listener, app, https).await {
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
            server,
            registry.clone(),
            metrics,
        )));

        tasks.push(usage_flusher);

        Ok(Self {
            http_addr,
            quic_addr,
            registry,
            key_store,
            tasks,
        })
    }

    /// 当前在线 agent 数（测试/可观测性用）。
    pub fn agent_count(&self) -> usize {
        self.registry.len()
    }

    /// 关闭前把内存里的用量强制落库（**必须成功一次**再退出）。
    ///
    /// 落库已改成"后台按周期批量写"，所以进程退出前必须补最后这一刀，否则最后
    /// 一个周期内的用量会丢。这里返回写入的 key 数，便于日志与测试断言。
    pub fn flush_usage_on_shutdown(&self) -> usize {
        let n = self.key_store.flush_usage_blocking();
        tracing::info!(keys = n, "usage flushed before shutdown");
        n
    }

    pub async fn shutdown(self) {
        for t in self.tasks {
            t.abort();
        }
    }
}

/// 基于 tokio-rustls 的 HTTPS accept 循环（每连接一个任务）。
///
/// rustls 配置由调用方（`Gateway::start`）预先构建好传入，这样证书材料有问题会在
/// **启动时**就失败，而不是在这里默默结束、留下一个"看起来启动了"的空壳进程。
async fn serve_https(
    listener: tokio::net::TcpListener,
    app: Router,
    server_config: Arc<rustls::ServerConfig>,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(server_config);
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
pub mod usage;
pub mod usage_flush;
