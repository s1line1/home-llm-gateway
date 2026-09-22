//! 公网入口的连接层：accept 循环 + 每连接的 HTTP/1.1 服务实现（TLS 与明文共用）。
//!
//! 它不在"路由层"里：本模块只认识 `TcpListener` / `Router` / `Arc<ServerConfig>`，
//! 不认识任何一条路由。而且 [`spawn_entry`] 是**启动层**调用的（`Gateway::start`），
//! 不属于请求路径。
//!
//! rustls 配置由调用方预先构建好传入：证书材料有问题要在**启动时**失败，而不是在这里
//! 默默结束、留下一个"看起来启动了"的空壳进程。
//!
//! **关停（片 A）**：accept 循环通过一个 [`tokio::sync::watch`] 停止接受新连接——只停
//! accept，已经建立的连接与在途请求继续跑，由 `Gateway::shutdown` 的排空阶段等它们收尾。
//!
//! **accept 出错绝不退出循环**（并集报告 H2 / 记录 P2-10）：`accept()` 的错误几乎都是
//! 暂时性的资源问题（`EMFILE`/`ENFILE` = fd 用尽、`ECONNABORTED` = 握手期客户端跑了、
//! `EINTR` = 信号中断），而老实现用 `?` 把**一次**这样的错误变成整个公网入口永久停摆：
//! 进程活着、systemd 显示 active、日志只有一行 warn，端口却再也不接受连接。
//! 现在改为**带退避的重试**（见 [`accept_backoff`]）+ 计数指标，循环只在收到关闭信号时退出。
//! 线上实测 EMFILE 出现过 296 次（`nofile.rs`），所以这不是理论故障。

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::Router;
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::{
    net::TcpStream,
    sync::{watch, OwnedSemaphorePermit, Semaphore},
};
use tokio_rustls::TlsAcceptor;
use tower::Service as TowerService;
use tracing::{info, warn};

use crate::{io_stall, metrics::Metrics, state::ShutdownPhase};

/// accept 失败后的首次退避。
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(50);
/// accept 失败后的退避上限。
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// accept 失败后的退避：从 [`ACCEPT_BACKOFF_MIN`] 起按失败次数翻倍，到 [`ACCEPT_BACKOFF_MAX`] 封顶。
///
/// **退避是重试的必要条件**：`EMFILE` 在 fd 被释放之前会**连续**失败，立刻重试等于把 accept
/// 循环变成忙等热循环——一台 CPU 满载 + 日志刷屏，比"安静地停摆"更难排查（那种故障至少端口
/// 是不通的）。封顶 1s：重试永远继续，但不至于让"fd 回来了"这个事件被拖延几分钟。
fn accept_backoff(consecutive_failures: u32) -> Duration {
    let shift = consecutive_failures.saturating_sub(1).min(5);
    (ACCEPT_BACKOFF_MIN * 2u32.pow(shift)).min(ACCEPT_BACKOFF_MAX)
}

/// accept 的来源。
///
/// 这层抽象只为一个理由存在：**accept 出错后的行为必须能被测**。真实的 `EMFILE` 要耗尽整个
/// 进程的 fd 才复现（会污染同进程里的其它测试），而它恰恰是把线上入口打死的那个错误——
/// 所以把"取连接"抽出来，测试注入错误、真实现仍是 [`tokio::net::TcpListener`]。
trait AcceptSource {
    async fn accept(&self) -> std::io::Result<(TcpStream, SocketAddr)>;
}

impl AcceptSource for tokio::net::TcpListener {
    async fn accept(&self) -> std::io::Result<(TcpStream, SocketAddr)> {
        tokio::net::TcpListener::accept(self).await
    }
}

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
    max_connections: usize,
    shutdown: watch::Receiver<ShutdownPhase>,
    metrics: Metrics,
) -> tokio::task::JoinHandle<()> {
    // 日志记**真实**监听地址：配置写 `:0` 时只有 `local_addr()` 知道内核给了哪个端口。
    let acceptor = https.map(TlsAcceptor::from);
    match listener.local_addr() {
        Ok(addr) if acceptor.is_some() => info!(addr = %addr, "https public entry enabled"),
        Ok(addr) => info!(addr = %addr, "http public entry enabled"),
        Err(e) => warn!("cannot read the public entry's local_addr: {e}"),
    }
    let entry = if acceptor.is_some() { "https" } else { "http" };
    let limiter = connection_limiter(max_connections);
    tokio::spawn(async move {
        serve_entry(
            listener,
            entry,
            acceptor,
            app,
            client_stall,
            limiter,
            shutdown,
            metrics,
        )
        .await;
    })
}

/// 连接额度：`0` = 不限。
///
/// "不限"用 [`Semaphore::MAX_PERMITS`] 表达，而不是 `Option<Semaphore>`：每个连接都要
/// `acquire`，多一个 `Option` 只会让循环多一层分叉。
fn connection_limiter(max_connections: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(if max_connections == 0 {
        Semaphore::MAX_PERMITS
    } else {
        max_connections
    }))
}

/// 取一个连接额度；`None` = 收到关闭信号（`Draining` 或发送端被 drop）。
///
/// **先取额度、再 accept**：满额时循环停在这里，新连接留在内核 backlog 里排队，
/// 而不是先收进来再拒绝（后者只是把"fd 耗尽"换成"5xx"）。
async fn acquire_connection(
    limiter: &Arc<Semaphore>,
    shutdown: &mut watch::Receiver<ShutdownPhase>,
) -> Option<OwnedSemaphorePermit> {
    tokio::select! {
        _ = shutdown.changed() => None,
        permit = limiter.clone().acquire_owned() => permit.ok(),
    }
}

/// 唯一的 accept 循环（TLS 与明文共用）：取额度 → 接受连接 → 每连接一个任务。
///
/// 以前 TLS 与明文各有一份逐字重复的循环，于是"accept 出错就退出"这个缺陷也存在两份
/// （评估记录 P2-10 只登记了其中一处）。合并之后策略只有一处，不会再漏掉另一边。
#[allow(clippy::too_many_arguments)]
async fn serve_entry<S>(
    source: S,
    entry: &'static str,
    acceptor: Option<TlsAcceptor>,
    app: Router,
    client_stall: Duration,
    limiter: Arc<Semaphore>,
    mut shutdown: watch::Receiver<ShutdownPhase>,
    metrics: Metrics,
) where
    S: AcceptSource,
{
    let mut consecutive_failures: u32 = 0;
    loop {
        let Some(permit) = acquire_connection(&limiter, &mut shutdown).await else {
            info!(
                entry,
                "shutdown requested; public entry stops accepting new connections"
            );
            return;
        };
        let accepted = tokio::select! {
            // 阶段一变（`Draining`）就停止接受；发送端被 drop（`Err`）同样停。
            _ = shutdown.changed() => {
                info!(
                    entry,
                    "shutdown requested; public entry stops accepting new connections"
                );
                return;
            }
            accepted = source.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(pair) => {
                consecutive_failures = 0;
                pair
            }
            Err(e) => {
                // 一次 accept 失败**只是这一轮的失败**：退避后重试，绝不退出循环。
                // 额度先还回去（这一轮没有连接可服务），免得退避期间白占一个名额。
                drop(permit);
                consecutive_failures = consecutive_failures.saturating_add(1);
                let backoff = accept_backoff(consecutive_failures);
                metrics.record_accept_error();
                warn!(
                    entry,
                    error = %e,
                    consecutive = consecutive_failures,
                    backoff_ms = backoff.as_millis(),
                    "accept failed; the public entry keeps listening and will retry"
                );
                // 退避期间也要能被关闭信号打断，否则关停最坏要等一个退避周期。
                let interrupted = tokio::select! {
                    _ = shutdown.changed() => true,
                    _ = tokio::time::sleep(backoff) => false,
                };
                if interrupted {
                    info!(
                        entry,
                        "shutdown requested; public entry stops accepting new connections"
                    );
                    return;
                }
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            // 额度随这个任务存活：响应写完 / 停滞超时 / 握手失败才归还。
            let _permit = permit;
            match acceptor {
                None => serve_conn(stream, app, peer, client_stall).await,
                Some(acceptor) => {
                    // **握手必须有上界**（评估 §5 H8）：客户端连上却不发 ClientHello 时，
                    // `acceptor.accept` 永不返回——一个 fd + 一个任务被白占，且这类半开连接
                    // 不经准入闸门（闸门在解析出请求之后才生效），此前只受 NOFILE 约束。
                    match tokio::time::timeout(client_stall, acceptor.accept(stream)).await {
                        Ok(Ok(tls_stream)) => serve_conn(tls_stream, app, peer, client_stall).await,
                        Ok(Err(e)) => warn!("tls handshake from {peer} failed: {e}"),
                        Err(_) => warn!(
                            peer = %peer,
                            stall_ms = client_stall.as_millis(),
                            "tls handshake stalled; dropping the connection (the client never spoke)"
                        ),
                    }
                }
            }
        });
    }
}

/// 服务一条客户端连接（TLS 与明文共用）。
///
/// **写方向必须包 [`io_stall::WriteStall`]**：hyper 自己**没有写超时**，客户端读完响应头
/// 就不再读时，hyper 会永久阻塞在 `poll_write`，而准入票据绑在 response body 上——
/// body 不被丢弃，槽位就永不归还（实测云端沉淀 8 个僵尸槽位，只能重启）。
/// 应用层的响应体停滞超时修不掉这一半，因为数据已经在 hyper/socket 的缓冲里。
///
/// **读方向（请求头）也要显式设界**（评估 §5 H8）：客户端连上（甚至握手完成）却不发完
/// 请求头，同样是白占一个 fd 与一个任务，而且**不经准入闸门**（闸门在解析出请求之后才
/// 生效）。hyper 的 `header_read_timeout` 需要 [`Builder::timer`] 才生效——它的默认值
/// 30s 一直没生效，就是因为这里没有 set timer；不设 timer 只配超时值会 panic。
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
    if let Err(e) = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(client_stall)
        .serve_connection(io, service)
        .await
    {
        warn!("http connection {peer} error: {e}");
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicU32, Ordering},
        time::Instant,
    };

    use axum::routing::get;

    use super::*;

    /// 前 N 次 `accept()` 失败（注入 `EMFILE`）、之后从真 listener 收连接的源。
    ///
    /// 真实 EMFILE 要耗尽整个进程的 fd 才能复现，而且会污染同进程的其它测试——注入是唯一
    /// 既能测又不伤别人的办法。
    struct FlakyListener {
        inner: tokio::net::TcpListener,
        failures_left: AtomicU32,
    }

    impl FlakyListener {
        async fn bind(failures: u32) -> (Self, SocketAddr) {
            let inner = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = inner.local_addr().unwrap();
            (
                Self {
                    inner,
                    failures_left: AtomicU32::new(failures),
                },
                addr,
            )
        }
    }

    impl AcceptSource for FlakyListener {
        async fn accept(&self) -> std::io::Result<(TcpStream, SocketAddr)> {
            // EMFILE = 24（Linux 与 macOS 同值）；`checked_sub` 到 0 后就不再加失败。
            let injected =
                self.failures_left
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
            if injected.is_ok() {
                return Err(std::io::Error::from_raw_os_error(24));
            }
            self.inner.accept().await
        }
    }

    fn test_app() -> Router {
        Router::new().route("/ping", get(|| async { "pong" }))
    }

    /// 规格：退避必须**单调增并封顶**。
    ///
    /// 两个方向都有代价：不翻倍 ⇒ 连续 EMFILE 下变成忙等热循环（CPU 满载 + 日志刷屏）；
    /// 不封顶 ⇒ "fd 已经回来了"这个事件被拖延几分钟，入口等于长时间停摆。
    #[test]
    fn accept_backoff_grows_and_caps() {
        assert_eq!(accept_backoff(1), Duration::from_millis(50));
        assert_eq!(accept_backoff(2), Duration::from_millis(100));
        assert_eq!(accept_backoff(3), Duration::from_millis(200));
        assert_eq!(accept_backoff(5), Duration::from_millis(800));
        assert_eq!(accept_backoff(6), ACCEPT_BACKOFF_MAX, "第 6 次开始封顶");
        assert_eq!(
            accept_backoff(1_000),
            ACCEPT_BACKOFF_MAX,
            "再多次也不超过上限"
        );
        for n in 1..20 {
            assert!(
                accept_backoff(n + 1) >= accept_backoff(n),
                "退避必须单调不减（n={n}）"
            );
        }
    }

    /// 规格（P2-10 / H2）：**一次 accept 错误不得停掉入口**。
    ///
    /// 修复前这条会失败：`accepted?` 直接把整个循环结束掉，客户端 requests 永远等不到响应
    /// （端口还监听着，连接也建得上——这正是它难发现的原因）。
    #[tokio::test]
    async fn accept_errors_are_retried_and_the_entry_keeps_serving() {
        let metrics = Metrics::default();
        let (source, addr) = FlakyListener::bind(2).await;
        let (_tx, rx) = watch::channel(ShutdownPhase::Running);

        let entry = tokio::spawn(serve_entry(
            source,
            "http",
            None,
            test_app(),
            Duration::from_secs(5),
            connection_limiter(0),
            rx,
            metrics.clone(),
        ));

        let started = Instant::now();
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            reqwest::get(format!("http://{addr}/ping")),
        )
        .await
        .expect("两次 accept 失败之后仍必须接受这条连接")
        .expect("请求应当成功");
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "pong");

        assert_eq!(metrics.http_accept_errors(), 2, "两次 EMFILE 都要被计数");
        // 50ms + 100ms 退避必须真的睡过：没有退避的重试是忙等热循环
        assert!(
            started.elapsed() >= Duration::from_millis(100),
            "重试之间必须有退避，实测只花了 {:?}",
            started.elapsed()
        );
        entry.abort();
    }

    /// 规格：退避期间收到关闭信号要**立刻**退出，不能等满一个退避周期。
    ///
    /// 先让失败累积到退避涨到 ~400ms，再发关闭信号：没有那个 select 的话，关停会卡住。
    #[tokio::test]
    async fn a_retrying_entry_still_stops_promptly_on_shutdown() {
        let metrics = Metrics::default();
        // u32::MAX 次失败：这个入口会一直失败下去
        let (source, _addr) = FlakyListener::bind(u32::MAX).await;
        let (tx, rx) = watch::channel(ShutdownPhase::Running);

        let entry = tokio::spawn(serve_entry(
            source,
            "http",
            None,
            test_app(),
            Duration::from_secs(5),
            connection_limiter(0),
            rx,
            metrics.clone(),
        ));

        // 等到退避涨到 ≥ 400ms（失败 4 次：50+100+200 已睡过，正要睡 400ms）
        let deadline = Instant::now() + Duration::from_secs(5);
        while metrics.http_accept_errors() < 4 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            metrics.http_accept_errors() >= 4,
            "前提：失败次数应当累积（实际 {}）",
            metrics.http_accept_errors()
        );

        tx.send(ShutdownPhase::Draining).unwrap();
        let stopped = tokio::time::timeout(Duration::from_millis(150), entry)
            .await
            .expect("退避期间收到关闭信号必须立刻退出（不能等满一个退避周期）");
        assert!(stopped.is_ok(), "任务应当正常结束而不是 panic");
    }
}
