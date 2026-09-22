//! 网关装配：配置（[`GatewayConfig`]）、启动（[`Gateway::start`]）、关闭（[`Gateway::shutdown`]）。
//!
//! 模块声明与再导出在 crate 根 `lib.rs`；启动旋钮（[`Options`]）在 [`crate::options`]；
//! TLS 材料（[`TlsPem`]、[`TunnelTls`]）与 rustls 配置构造在 [`crate::tls`]；端口绑定在
//! 私有模块 `listen`；公网入口的 accept 循环在 [`crate::http`]。

use std::{net::SocketAddr, time::Duration};

use tokio::sync::watch;

use crate::{
    error::GatewayError, http, listen, metrics::Metrics, nofile, quic, registry::Registry, state,
    storage::KeyStore, tls::TlsPem, usage_flush,
};

/// 启动旋钮住在 [`crate::options`]；这里再导出，保住 `gateway::Options` 这个既有公开路径
/// （`lib.rs` 与 `tests/e2e` 按它引用）。
pub use crate::options::Options;

/// 隧道身份材料住在 [`crate::tls`]；同样再导出以保住 `gateway::TunnelTls` 路径。
pub use crate::tls::TunnelTls;

/// 启动配置：**必填的身份材料** + 全部可选项。
///
/// **不要**给它加 `#[non_exhaustive]`：`tests/e2e` 是独立 crate，加了之后连
/// `..Options::default()` 这种 FRU 写法都用不了，正好毁掉本结构存在的意义。
#[derive(Debug)]
pub struct GatewayConfig {
    pub tunnel: TunnelTls,
    pub opts: Options,
}

pub struct Gateway {
    /// 实际绑定的公网入口地址（配置 `:0` 时是内核分配的临时端口）。
    pub http_addr: SocketAddr,
    /// 实际绑定的 QUIC 地址（UDP）。
    pub quic_addr: SocketAddr,
    /// [`Options::agent_stale_after`] 的副本：`healthy_agent_count()` 需要它。
    ///
    /// 不留整个 `Options`（它已随 `AppState` 进 Router，再存一份就是同一状态两处），
    /// 只多存这一个"派生接口要用到"的标量。
    agent_stale_after: Duration,
    /// [`Options::shutdown_flush_timeout`] 的副本：关闭时那次强制落库的等待上限。
    shutdown_flush_timeout: Duration,
    /// [`Options::shutdown_grace`] 的副本：排空在途请求的最长等待。
    shutdown_grace: Duration,
    /// 关闭阶段的广播端（见 [`state::ShutdownPhase`]）：`Draining` 停 accept、
    /// `Terminating` 让在途响应带明确事件收尾。
    shutdown: watch::Sender<state::ShutdownPhase>,
    /// 在途请求读数（与 `hlmg_active_requests` 同一份计数）：排空的判据靠它。
    metrics: Metrics,
    registry: Registry,
    /// 用量落库需要在关闭前强制 flush 一次（见 [`Gateway::shutdown`]）。
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
    /// 启动网关。**全有或全无**：返回 `Err` 时没有 socket 被绑住、没有任务被拉起、
    /// 也不会改动任何进程级状态；返回 `Ok` 时两个监听口都已就绪。
    ///
    /// 注意 `Ok` **不代表**已有 agent 注册（`start` 不等任何握手），要看
    /// [`Self::agent_count`] 或 `hlmg_agents` 指标。
    ///
    /// 必须在 tokio runtime 内调用（要 `tokio::spawn` 与 `TcpListener::bind`）。
    /// 每个进程可以起多个网关实例（仅有的进程级副作用是 crypto provider 与 NOFILE，
    /// 两者都幂等）。
    ///
    /// 顺序约束由**类型**固定，不靠注释：
    /// ① TLS 材料构建成 `Arc<ServerConfig>`——构建不出来就**在碰任何资源之前**失败；
    /// ② `nofile::install()` 产出凭证；③ `listen::Sockets::bind` 同时要求这两样
    /// （已校验的 TLS + 已抬额度的凭证），所以"先绑端口再校验"与"没抬额度就绑"都写不出来。
    ///
    /// 错误：`Config`（HTTPS 材料构建不出 / 流额度非法）、`Tls`、`Verifier`、
    /// `Io`（端口占用）、`QuicStart`。**已知的刻意放宽**（保持原有设计）：NOFILE 抬不动
    /// 只 WARN、`ui_dir` 不可用只降级成占位页，两者都不阻止启动。
    pub async fn start(cfg: GatewayConfig) -> Result<Self, GatewayError> {
        let GatewayConfig { tunnel, opts } = cfg;

        // ① 纯校验 + 派生：TLS 材料有问题必须**在碰任何资源之前**失败（fail fast）。
        //    否则进程会"启动成功"却从未监听公网端口——systemd 显示 active(running)、
        //    日志写着 Gateway ready，而端口是 connection refused；且 /healthz、/metrics、
        //    /admin/* 全在同一端口上，可观测性一起陪葬。
        let quic_tls = tunnel.server_config()?;
        let https = opts.https.as_ref().map(TlsPem::server_config).transpose()?;

        // 配置自检：**摘除宽限短于 `head_timeout`** 时吵一声。在途集合里包含"仍在等响应头"
        // 的请求（槽位覆盖 `read_head`），所以宽限短于 `head_timeout` 就意味着：摘除发生后，
        // 那些还在合法等待的请求会被宽限到期强制切断（评估 §5 H1）。默认值两者相等，
        // 这条 WARN 只会在人为把宽限配小时出现——与 `quic.rs` 里"agent 声明容量 > 端点流额度"
        // 那条同一风格：配置不一致要在启动时看得见，而不是等生产出事。
        if opts.evict_close_grace < opts.head_timeout {
            tracing::warn!(
                evict_close_grace_secs = opts.evict_close_grace.as_secs(),
                head_timeout_secs = opts.head_timeout.as_secs(),
                "evict_close_grace_secs is shorter than head_timeout_secs: when an agent is \
                 evicted, requests on that connection which are still legitimately waiting for a \
                 response head will be cut at the grace deadline; raise evict_close_grace_secs \
                 (or lower head_timeout_secs)"
            );
        }

        // 同类自检：「对端还活着」那层静默宽限若**不严格长于窗口**（`4 × head_timeout`），
        // 它永远不可能生效——窗口一过就已经按第一层判死了，延长无从谈起（评估 §5 H2 的修法
        // 就是这么用的）。0 是**有意**关掉这一层，不算配错，所以那种情况不吵。
        let head_window = opts.head_timeout * 4;
        if !opts.head_silent_grace.is_zero() && opts.head_silent_grace <= head_window {
            tracing::warn!(
                head_silent_grace_secs = opts.head_silent_grace.as_secs(),
                head_alive_window_secs = head_window.as_secs(),
                "head_silent_grace_secs is not longer than the busy/dead window \
                 (4 x head_timeout_secs): the second-tier check that tolerates silence while the \
                 peer keeps heartbeating can never take effect; raise head_silent_grace_secs, or \
                 set it to 0 to disable that tier on purpose"
            );
        }

        // ② 进程级副作用：在**绑任何 socket 之前**把 NOFILE 的 soft 抬到目标值（默认
        //    16384）。systemd 给的默认 soft 是 1024，生产水位（768 并发连接 → fd 峰值
        //    785）下是贴脸的，撞上时表现为"新连接被拒但进程健康"
        //    （`accept error: Too many open files`）。失败只告警，不阻止启动。
        let nofile = nofile::install();

        // ③ 绑端口：QUIC(UDP) + HTTP(TCP) 在同一处完成，失败不会只绑一半。
        let sockets = listen::Sockets::bind(&nofile, quic_tls, &opts).await?;

        // ④ 进程内状态
        let registry = Registry::default();
        let metrics = Metrics::default();
        let key_store = KeyStore::with_verified(
            opts.keys_file.clone(),
            opts.verified_cache_max,
            KeyStore::default_verified_ttl(),
        );
        let app_state =
            state::AppState::new(registry.clone(), key_store.clone(), metrics.clone(), &opts);
        // 关闭阶段的发送端留在 `Gateway`；接收端给 accept 循环，在途响应各自 `subscribe()`。
        // 发送端只有这里拿得到（`shutdown_sender` 是 pub(crate)）：推进关闭阶段的能力
        // 属于进程生命周期，不随 `AppState` 外流（评估 §2 S3）。
        let shutdown = app_state.shutdown_sender();
        let app = http::app(app_state);

        // ⑤ 起任务。入列顺序有意义：用量 flusher 必须在 serve 任务之前就位（它按周期
        //    批量写库，见 `proxy::UsageCollector::finish`；关闭时由 `shutdown` 补最后一刀）。
        let tasks = vec![
            usage_flush::spawn(key_store.clone()),
            http::spawn_entry(
                sockets.http,
                app,
                https,
                opts.client_stall,
                opts.max_entry_connections,
                shutdown.subscribe(),
                metrics.clone(),
            ),
            tokio::spawn(quic::accept_loop(
                sockets.server,
                registry.clone(),
                metrics.clone(),
                opts.stream_ceiling(),
            )),
        ];

        // 「`start()` 返回 ⇒ 隧道入口接受中」：把这条不变量在这里做出来，而不是让探针在启动
        // 窗口里误报 degraded（判据见 `quic::await_accepting`）。等不到只告警、不失败启动——
        // 端口已经绑好，"入口还没标上"是**健康信号**该说的事，不是启动失败。
        if !quic::await_accepting(&metrics, std::time::Duration::from_secs(5)).await {
            tracing::warn!(
                "the tunnel entry has not marked itself as accepting yet; /healthz will report \
                 degraded until it does"
            );
        }

        Ok(Self {
            http_addr: sockets.http_addr,
            quic_addr: sockets.quic_addr,
            agent_stale_after: opts.agent_stale_after,
            shutdown_flush_timeout: opts.shutdown_flush_timeout,
            shutdown_grace: opts.shutdown_grace,
            shutdown,
            metrics,
            registry,
            key_store,
            tasks,
            nofile,
        })
    }

    /// 注册表里的条目数（**含心跳已过期、连接还没关的**）。
    ///
    /// 要"现在能被路由"的数量用 [`Self::healthy_agent_count`]：排查"所有请求 503"时
    /// 两者必须分开看（见 `registry.rs` 的 `len` / `healthy_count`）。
    pub fn agent_count(&self) -> usize {
        self.registry.len()
    }

    /// 心跳未过期、**真正可路由**的 agent 数。
    ///
    /// 与 [`Self::agent_count`] 的区别：条目要等连接真正关闭才摘除，所以失联 agent 会被
    /// `agent_count()` 算作"在线"却不参与路由——只看前者会把"有人注册但全部失联"误判成
    /// "agent 掉了"。
    pub fn healthy_agent_count(&self) -> usize {
        self.registry.healthy_count(self.agent_stale_after)
    }

    /// 启动时那三个主任务（用量 flusher、HTTP 入口、QUIC accept）是否都还活着。
    ///
    /// 判据是 `JoinHandle::is_finished()`：任何一条结束（accept 出错、panic、被 abort）
    /// 即返回 `false`。HTTP 入口死掉时进程、systemd 与 `/healthz` 全都正常，`hlmg_quic_accepting`
    /// 又只覆盖 QUIC 入口——这是唯一能回答"入口还活着吗"的接口（并集报告 H1）。
    ///
    /// 注意它**不**覆盖每连接/每请求的派生任务，也不覆盖 `registry` 的摘除宽限任务。
    pub fn is_serving(&self) -> bool {
        self.tasks.iter().all(|t| !t.is_finished())
    }

    /// 隧道入口是否仍在接受新 agent（`hlmg_quic_accepting` 的程序化形式）。
    ///
    /// 与 [`Self::is_serving`] 分工不同：这个回答**具体故障**（UDP 驱动/端点失效，`quic.rs`
    /// 说"需要重启网关"），`is_serving` 回答"三个主任务是否都还在跑"。`/healthz` 的存活判据
    /// 就是它；[`Gateway::start`] 保证**返回时为 `true`**（见 `quic::await_accepting`）。
    pub fn tunnel_accepting(&self) -> bool {
        self.metrics.quic_accepting() == 1
    }

    /// 停网关：**停 accept → 有界排空 → 在途带明确事件收尾 → 有界落库 → abort**。
    ///
    /// 两个阶段通过 [`state::ShutdownPhase`] 广播：
    /// - `Draining`：公网入口停止 accept（新连接被拒），**在途请求继续正常跑**；
    /// - `Terminating`：宽限期到了仍有在途，就让它们带一个明确的"不完整"事件收尾
    ///   （见 `proxy/forward.rs`），而不是被硬切。
    ///
    /// flush 并进来是为了消掉一个顺序陷阱：以前 `main.rs` 可以先 `shutdown()` 而忘了
    /// `flush_usage_on_shutdown()`，最后一个周期内的用量就随进程一起消失。落库是同步的
    /// （一次 SQLite 事务，毫秒级），而且**排在排空与收尾之后**——这期间结算的用量也会被
    /// 这次落库带上。
    ///
    /// 只停**公网入口**、不停 QUIC 端点：在途响应还要靠它从 agent 回来。端点与任务一起在
    /// 最后 abort 时消失。配套：`deploy/gateway.service` 的 `TimeoutStopSec` 必须**大于**
    /// `shutdown_grace + shutdown_flush_timeout`（再加收尾窗口），否则没走完就被 SIGKILL。
    ///
    /// ⚠️ `registry.rs::close_when_drained` 是"摘除单个 agent 时等它在途请求收尾"，
    /// **不是进程退出路径**，别直接复用到这里。
    pub async fn shutdown(self) {
        // ① 进入 Draining：公网入口停止 accept；在途请求继续正常跑。
        let _ = self.shutdown.send(state::ShutdownPhase::Draining);
        // ② 排空在途 HTTP 请求（有界）。放在落库之前，排空期间结算的用量才会被带上。
        self.drain().await;
        // ③ 宽限期到了仍有在途 → 进入 Terminating：它们会带一个明确的"不完整"事件收尾，
        //    这里给一个发送窗口，让事件真的写出去。
        if self.metrics.active_count() > 0 {
            let _ = self.shutdown.send(state::ShutdownPhase::Terminating);
            self.await_end_event_window().await;
        }
        // ④ 有界强制落库：阻塞池 + 超时（见 [`Options::shutdown_flush_timeout`]）。
        //    超时**不取消**那个阻塞任务（同步代码取消不了），只是不再等它。
        let store = self.key_store.clone();
        match run_bounded(self.shutdown_flush_timeout, move || {
            store.flush_usage_blocking()
        })
        .await
        {
            Ok(Some(n)) => tracing::info!(keys = n, "usage flushed before shutdown"),
            Ok(None) => tracing::warn!("usage flush task did not finish before shutdown"),
            Err(()) => tracing::warn!(
                timeout_ms = self.shutdown_flush_timeout.as_millis(),
                "usage flush exceeded shutdown_flush_timeout; aborting tasks anyway \
                 (usage settled since the last periodic flush may be lost)"
            ),
        }
        // ⑤ abort；`Drop` 还会再兜一次（对已结束的任务是 no-op）。用 `&self.tasks` 而不是
        //    `self.tasks`：`Gateway` 有 `Drop`，不能把字段移出去。
        for t in &self.tasks {
            t.abort();
        }
    }

    /// 等在途 HTTP 请求归零，或到 [`Options::shutdown_grace`]。
    ///
    /// 判据用 `Metrics::active_count()`（与 `hlmg_active_requests` 同一份计数）：它覆盖
    /// "准入之后、响应体结束之前"的整段；响应体结束意味着隧道与用量结算都已收口。
    async fn drain(&self) {
        let grace = self.shutdown_grace;
        let deadline = tokio::time::Instant::now() + grace;
        loop {
            let active = self.metrics.active_count();
            if active == 0 {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(
                    active,
                    grace_secs = grace.as_secs(),
                    "shutdown grace elapsed with requests still in flight; announcing termination"
                );
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// 宣布 `Terminating` 之后，等在途响应把明确事件写出去：在途归零或到
    /// [`END_EVENT_WINDOW`] 为止。正常情况下一个调度周期内就归零。
    async fn await_end_event_window(&self) {
        let deadline = tokio::time::Instant::now() + END_EVENT_WINDOW;
        loop {
            if self.metrics.active_count() == 0 {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// 宣布 `Terminating` 后留给在途响应把"不完整"事件写出去的窗口。
///
/// 刻意不做成新旋钮：它只是"把事件从网关写到客户端"的调度余量，通常一两个调度周期就够；
/// 给固定上限是为了不让一个不读的客户端拖住关闭。
const END_EVENT_WINDOW: Duration = Duration::from_secs(1);

/// 在阻塞池上跑 `f`，最多等 `limit`。
///
/// 返回 `Ok(Some(v))` = 正常完成；`Ok(None)` = 阻塞任务 panic；`Err(())` = 超时。
/// 超时**不会**取消那个阻塞任务（Rust 取消不了同步代码），只是不再等它——所以调用方
/// （[`Gateway::shutdown`]）必须接受"落库可能还没写完就继续往下走"。
async fn run_bounded<F, T>(limit: Duration, f: F) -> Result<Option<T>, ()>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    match tokio::time::timeout(limit, tokio::task::spawn_blocking(f)).await {
        Ok(Ok(v)) => Ok(Some(v)),
        Ok(Err(_join)) => Ok(None),
        Err(_elapsed) => Err(()),
    }
}

impl Drop for Gateway {
    /// drop 而**没有**调 [`Gateway::shutdown`] 时的兜底：abort 所有任务，别把监听口与后台
    /// flusher 留给进程——tokio 里 drop `JoinHandle` 只是 **detach**，任务会继续跑（并集
    /// 报告 §5-H2 实测：drop 之后端口仍可 connect）。
    ///
    /// **刻意不做用量落库**：`flush_usage_blocking` 是阻塞式 SQLite 写，在析构里做会在
    /// 不可预期的上下文（runtime worker、unwind）里阻塞；丢的只是最后一个 flush 周期
    /// （≤1s），与崩溃同级。要"已结算用量不丢"就调 `shutdown()`（`main` 就是这么做的）。
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::run_bounded;
    use std::time::Duration;

    /// 规格：**有界等待**——到点必须放弃，而不是陪着慢任务一起卡住。
    ///
    /// 这是关闭路径不挂死的保险：`shutdown` 的强制落库跑在阻塞池上，磁盘/库锁慢时只有
    /// 这个超时能保证进程还能走到 abort 与退出（见 [`crate::Options::shutdown_flush_timeout`]）。
    #[tokio::test]
    async fn run_bounded_gives_up_at_the_deadline() {
        let t0 = std::time::Instant::now();
        let out = run_bounded(Duration::from_millis(20), || {
            std::thread::sleep(Duration::from_millis(300));
            7usize
        })
        .await;
        assert_eq!(out, Err(()), "到点必须放弃等待");
        assert!(
            t0.elapsed() < Duration::from_millis(200),
            "应在超时量级返回，而不是等满阻塞任务，实际 {:?}",
            t0.elapsed()
        );
    }

    #[tokio::test]
    async fn run_bounded_returns_the_value_when_it_finishes() {
        assert_eq!(
            run_bounded(Duration::from_secs(5), || 7usize).await,
            Ok(Some(7))
        );
    }
}
