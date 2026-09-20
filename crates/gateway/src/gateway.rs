//! 网关装配：配置（[`GatewayConfig`]）、启动（[`Gateway::start`]）、关闭
//! （[`Gateway::shutdown`]），以及公网入口的 accept 循环（TLS 与明文共用一套服务实现）。
//!
//! 模块声明与再导出在 crate 根 `lib.rs`；TLS 材料类型（[`TlsPem`]）在 [`crate::tls`]。

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::Router;
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tower::Service as TowerService;
use tracing::{error, info, warn};

use crate::{
    http, io_stall,
    keystore::KeyStore,
    metrics::Metrics,
    nofile, quic,
    ratelimit::RateLimiter,
    registry::Registry,
    tls::{self, TlsPem},
    usage_flush,
};

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
    /// 客户端"完全停滞"多久就放弃：请求体读不动 / 响应体客户端不消费。
    ///
    /// 这两处的 await 以前没有超时，会让在途请求永久占住准入槽位（实测云端沉淀了 8 个
    /// 僵尸槽位，`hlmg_active_requests` 只增不减）。见 `GatewayConfig` 对应配置项注释。
    pub client_stall: Duration,
    /// 每个 API Key 每分钟请求上限（0 = 不限流）。
    pub rate_limit_per_min: u32,
    /// HTTP 全局在途请求上限（0 = 不限）。
    pub max_concurrent_requests: u32,
    /// 每条 agent 连接上允许同时在途的隧道流数（QUIC 双向流额度）。
    ///
    /// s2n-quic 的 `initial_max_streams_bidi` 默认 **100**，实际可用额度取
    /// `min(本地, 对端)`。两侧都不设时，一条 agent 连接最多只有 100 条在途请求——
    /// 超过就**排队等额度回收**，上游一慢便等过 `tunnel_op_timeout`，被误判成
    /// "隧道已死"并摘除整条连接（agent 重连期间注册表为空 → 全量 503）。
    ///
    /// 必须 **≥ agent 声明的 max_concurrency**；注册时声明超限会打 WARN（见 `quic`）。
    pub max_open_tunnel_streams: u32,
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
    /// 「启动时抬过 NOFILE 额度」的凭证，见 [`nofile::Raised`] 与 [`nofile::install`]。
    ///
    /// **它没有任何运行时用途，唯一作用是编译期保险**：这个字段只能由
    /// `nofile::install()` 的返回值填上，所以删掉那次调用就构造不出 `Gateway`
    /// （`missing field` 编译错误），而不是静默地把 fd 额度留在 1024 上——
    /// 那种失败只会在高并发时以 `Too many open files` 的形式冒出来，单测/clippy 全绿。
    pub nofile: nofile::Raised,
}

impl Gateway {
    pub async fn start(cfg: GatewayConfig) -> Result<Self, crate::error::GatewayError> {
        // crypto provider 由下面的 tls 构造函数自己确保（`proto::crypto::provider` 幂等，
        // 唯一入口）——启动路径不再需要"记得先装"这一步。

        // 在**绑任何 socket 之前**把 NOFILE 的 soft 抬到目标值（默认 16384）：systemd 给的默认
        // soft 是 1024，生产水位（768 并发连接 → fd 峰值 785）下是贴脸的，撞上时表现为
        // "新连接被拒但进程健康"（`accept error: Too many open files`）。
        // 失败只告警，不阻止启动——见 `nofile` 模块注释；返回值存进结构体是**编译期保险**
        // （删掉这行就构造不出 Gateway），不要为了"省一个字段"把它丢掉。
        let nofile = nofile::install();

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

        // 隧道流额度：网关**自己**能同时开多少条双向流（每个 agent 连接一份）。
        //
        // 必须显式设置，且必须 ≥ agent 声明的 max_concurrency。默认的
        // `InitialMaxStreamsBidi::RECOMMENDED = 100` 是给"一条连接跑少量请求"的场景定的；
        // 我们一条连接就是一整台 agent 的流量，100 会让第 101 条请求去排队等额度，
        // 上游慢时排过 `tunnel_op_timeout` → 被当成坏隧道摘除（见 GatewayConfig 字段注释）。
        //
        // 幂等性/安全性：这只是**上限**，真正的在途量由注册表按 agent 声明的
        // max_concurrency 做准入控制（`try_acquire`），所以这里给大不会放大并发。
        let limits = s2n_quic::provider::limits::Limits::new()
            .with_max_open_local_bidirectional_streams(u64::from(cfg.max_open_tunnel_streams))
            .map_err(|e| {
                crate::error::GatewayError::Config(format!(
                    "max_open_tunnel_streams={} 不是合法的 QUIC 流额度: {e}",
                    cfg.max_open_tunnel_streams
                ))
            })?;

        let server = s2n_quic::Server::builder()
            .with_tls(s2n_quic::provider::tls::rustls::Server::from(Arc::new(tls)))?
            .with_io(cfg.quic_bind)?
            .with_limits(limits)?
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
            KeyStore::default_verified_ttl(),
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
            // 4 倍 head_timeout：连续四个窗口一次响应头都没回来，才算"不是慢，是死"。
            head_alive_window: cfg.head_timeout * 4,
            client_stall: cfg.client_stall,
            rate_limiter: RateLimiter::new(cfg.rate_limit_per_min),
            max_concurrent_requests: cfg.max_concurrent_requests,
            max_open_tunnel_streams: cfg.max_open_tunnel_streams,
            metrics: metrics.clone(),
            ui,
            ui_problem,
        };
        let app = http::app(state);

        let mut tasks = Vec::new();
        match https {
            Some(https) => {
                info!(addr = %cfg.http_bind, "https public entry enabled");
                let client_stall = cfg.client_stall;
                tasks.push(tokio::spawn(async move {
                    if let Err(e) = serve_https(listener, app, https, client_stall).await {
                        warn!("https server stopped: {e}");
                    }
                }));
            }
            None => {
                info!(addr = %cfg.http_bind, "http public entry enabled");
                let client_stall = cfg.client_stall;
                tasks.push(tokio::spawn(async move {
                    if let Err(e) = serve_plain(listener, app, client_stall).await {
                        warn!("http server stopped: {e}");
                    }
                }));
            }
        }

        tasks.push(tokio::spawn(quic::accept_loop(
            server,
            registry.clone(),
            metrics,
            cfg.max_open_tunnel_streams,
        )));

        tasks.push(usage_flusher);

        Ok(Self {
            http_addr,
            quic_addr,
            registry,
            key_store,
            tasks,
            nofile,
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

    /// 停网关。**目前只是 abort 监听任务，没有 drain。**
    ///
    /// 现状（`systemctl restart` → SIGTERM → `main.rs::shutdown_signal` → 这里）：在途请求被直接
    /// 切断——SSE 长流在客户端看来是"流被截断"而不是正常结束；到 agent 的隧道连接随进程一起
    /// 消失，靠 agent 侧指数退避（≤30s）重连。也就是说"干净退出"目前只覆盖**内存用量不丢**
    /// （见 [`Self::flush_usage_on_shutdown`]），**不覆盖"对用户无感"**。
    ///
    /// TODO（要求见 `REBUILD.md` §6-R12；登记见 `TODO.md`《重建蓝图 §6 未修项》R12）：
    /// 做成 drain 式关闭——① 先停 accept（不再接新请求）② 给在途请求一个宽限期
    /// ③ 到期前让在途流收到明确的结束/错误事件，使客户端能区分"被截断"与"正常结束"
    /// ④ 到点再 abort。
    ///
    /// 配套：`deploy/gateway.service` 的 `TimeoutStopSec`（当前未设 = systemd 默认 90s）必须
    /// **大于**宽限期，否则宽限期还没走完就被 SIGKILL。
    ///
    /// ⚠️ `registry.rs::close_when_drained` 是"摘除单个 agent 时等它在途请求收尾"，
    /// **不是进程退出路径**，别直接复用到这里。
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
/// 服务一条客户端连接（TLS 与明文共用）。
///
/// **写方向必须包 [`io_stall::WriteStall`]**：hyper 自己**没有写超时**，客户端读完响应头
/// 就不再读时，hyper 会永久阻塞在 `poll_write`，而准入票据绑在 response body 上——
/// body 不被丢弃，槽位就永不归还（实测云端沉淀 8 个僵尸槽位，只能重启）。
/// 应用层的响应体停滞超时修不掉这一半，因为数据已经在 hyper/socket 的缓冲里。
async fn serve_conn<I>(io: I, app: Router, peer: std::net::SocketAddr, client_stall: Duration)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(io_stall::WriteStall::new(io, client_stall));
    // 桥接 hyper(0.4 Service) 与 axum(tower 0.5 Service)
    let service = service_fn(move |req: hyper::Request<Incoming>| {
        let mut app = app.clone();
        async move { app.call(req).await }
    });
    if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
        warn!("http connection {peer} error: {e}");
    }
}

async fn serve_https(
    listener: tokio::net::TcpListener,
    app: Router,
    server_config: Arc<rustls::ServerConfig>,
    client_stall: Duration,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(server_config);
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => serve_conn(tls_stream, app, peer, client_stall).await,
                Err(e) => warn!("tls handshake from {peer} failed: {e}"),
            }
        });
    }
}

/// 明文入口：与 [`serve_https`] 同一套服务实现（含写停滞超时）。
/// 以前这里直接用 `axum::serve`，它没有写超时，客户端不读响应体就会卡住一条连接并占住票据。
async fn serve_plain(
    listener: tokio::net::TcpListener,
    app: Router,
    client_stall: Duration,
) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let app = app.clone();
        tokio::spawn(async move { serve_conn(stream, app, peer, client_stall).await });
    }
}
