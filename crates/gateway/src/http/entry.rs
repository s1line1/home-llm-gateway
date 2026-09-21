//! 公网入口的连接层：accept 循环 + 每连接的 HTTP/1.1 服务实现（TLS 与明文共用）。
//!
//! 它不在"路由层"里：本模块只认识 `TcpListener` / `Router` / `Arc<ServerConfig>`，
//! 不认识任何一条路由。而且 [`spawn_entry`] 是**启动层**调用的（`Gateway::start`），
//! 不属于请求路径。
//!
//! rustls 配置由调用方预先构建好传入：证书材料有问题要在**启动时**失败，而不是在这里
//! 默默结束、留下一个"看起来启动了"的空壳进程。
//!
//! **关停（片 A）**：accept 循环通过一个 [`Notify`] 停止接受新连接——只停 accept，
//! 已经建立的连接与在途请求继续跑，由 `Gateway::shutdown` 的排空阶段等它们收尾。

use std::{sync::Arc, time::Duration};

use axum::Router;
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tower::Service as TowerService;
use tracing::{info, warn};

use crate::io_stall;
use crate::state::ShutdownPhase;

/// 起公网入口的 accept 循环（TLS 与明文共用一套服务实现），返回任务句柄。
///
/// rustls 配置由调用方（`Gateway::start`）**预先构建好**传入：证书材料有问题要在
/// 启动时就失败，而不是在这里默默结束、留下一个"看起来启动了"的空壳进程。
///
/// `shutdown` 进入 `Draining`（或发送端被 drop）之后循环退出、`TcpListener` 随函数返回被
/// drop——于是**新连接被拒**，而已建立的连接不受影响（它们各自是独立任务）。
pub(crate) fn spawn_entry(
    listener: tokio::net::TcpListener,
    app: Router,
    https: Option<Arc<rustls::ServerConfig>>,
    client_stall: Duration,
    shutdown: watch::Receiver<ShutdownPhase>,
) -> tokio::task::JoinHandle<()> {
    // 日志记**真实**监听地址：配置写 `:0` 时只有 `local_addr()` 知道内核给了哪个端口。
    match listener.local_addr() {
        Ok(addr) if https.is_some() => info!(addr = %addr, "https public entry enabled"),
        Ok(addr) => info!(addr = %addr, "http public entry enabled"),
        Err(e) => warn!("cannot read the public entry's local_addr: {e}"),
    }
    tokio::spawn(async move {
        let result = match https {
            Some(cfg) => serve_https(listener, app, cfg, client_stall, shutdown).await,
            None => serve_plain(listener, app, client_stall, shutdown).await,
        };
        if let Err(e) = result {
            warn!("public entry stopped: {e}");
        }
    })
}

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

/// 基于 tokio-rustls 的 HTTPS accept 循环（每连接一个任务）。
async fn serve_https(
    listener: tokio::net::TcpListener,
    app: Router,
    server_config: Arc<rustls::ServerConfig>,
    client_stall: Duration,
    mut shutdown: watch::Receiver<ShutdownPhase>,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(server_config);
    loop {
        let (stream, peer) = tokio::select! {
            // 阶段一变（`Draining`）就停止接受；发送端被 drop（`Err`）同样停。
            _ = shutdown.changed() => {
                info!("shutdown requested; https public entry stops accepting new connections");
                return Ok(());
            }
            accepted = listener.accept() => accepted?,
        };
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
    mut shutdown: watch::Receiver<ShutdownPhase>,
) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = tokio::select! {
            // 阶段一变（`Draining`）就停止接受；发送端被 drop（`Err`）同样停。
            _ = shutdown.changed() => {
                info!("shutdown requested; http public entry stops accepting new connections");
                return Ok(());
            }
            accepted = listener.accept() => accepted?,
        };
        let app = app.clone();
        tokio::spawn(async move { serve_conn(stream, app, peer, client_stall).await });
    }
}
