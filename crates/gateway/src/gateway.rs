//! 网关装配：配置（[`GatewayConfig`]）、启动（[`Gateway::start`]）、关闭（[`Gateway::shutdown`]）。
//!
//! 模块声明与再导出在 crate 根 `lib.rs`；启动旋钮（[`Options`]）在 [`crate::options`]；
//! TLS 材料（[`TlsPem`]）与 rustls 配置构造在 [`crate::tls`]；端口绑定在私有模块 `listen`；
//! 公网入口的 accept 循环在 [`crate::http`]。

use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::{
    error::GatewayError,
    http, listen,
    metrics::Metrics,
    nofile, quic,
    registry::Registry,
    state,
    storage::KeyStore,
    tls::{self, TlsPem},
    usage_flush,
};

/// 启动旋钮住在 [`crate::options`]；这里再导出，保住 `gateway::Options` 这个既有公开路径
/// （`lib.rs` 与 `tests/e2e` 按它引用）。
pub use crate::options::Options;

/// 隧道侧的 mTLS 身份材料。**必填**，没有它网关证明不了任何 agent 的身份。
///
/// 刻意**不给 `Default`、也不放进 [`Options`]**：`PrivateKeyDer` 本身没有 `Default`，
/// 所以"忘了配证书"在类型层面就构造不出来。反面例子是 `ca_cert: vec![]`——那在 rustls 里
/// 是一套"谁也不信"的信任根：网关照常启动、日志照常写 ready，而每个 agent 的握手都被拒，
/// 表现成"agent 永远注册不上"。身份材料与可调旋钮分开，就是为了让这类错误不可表达。
#[derive(Debug)]
pub struct TunnelTls {
    /// 签发 agent 客户端证书的 CA 证书。
    pub ca_cert: Vec<CertificateDer<'static>>,
    pub server_cert: Vec<CertificateDer<'static>>,
    pub server_key: PrivateKeyDer<'static>,
}

impl TunnelTls {
    /// 从三个 PEM 文件装载（生产路径）。文件缺失 / 解析失败一律**启动即失败**。
    pub fn from_pem_files(ca: &Path, cert: &Path, key: &Path) -> Result<Self, GatewayError> {
        Ok(Self {
            ca_cert: proto::pem::load_certs(ca).map_err(|e| {
                GatewayError::Other(format!("cannot load ca cert {}: {e}", ca.display()))
            })?,
            server_cert: proto::pem::load_certs(cert).map_err(|e| {
                GatewayError::Other(format!("cannot load cert {}: {e}", cert.display()))
            })?,
            server_key: proto::pem::load_key(key).map_err(|e| {
                GatewayError::Other(format!("cannot load key {}: {e}", key.display()))
            })?,
        })
    }

    /// 构建 QUIC 隧道用的 mTLS rustls 配置。调用方拿到 `Arc` 才能交给 s2n-quic。
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, GatewayError> {
        tls::rustls_server_tls(
            &self.ca_cert,
            self.server_cert.clone(),
            self.server_key.clone_key(),
        )
        .map(Arc::new)
    }
}

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
        let app = http::app(state::AppState::new(
            registry.clone(),
            key_store.clone(),
            metrics.clone(),
            &opts,
        ));

        // ⑤ 起任务。入列顺序有意义：用量 flusher 必须在 serve 任务之前就位（它按周期
        //    批量写库，见 `proxy::UsageCollector::finish`；关闭时由 `shutdown` 补最后一刀）。
        let tasks = vec![
            usage_flush::spawn(key_store.clone()),
            http::spawn_entry(sockets.http, app, https, opts.client_stall),
            tokio::spawn(quic::accept_loop(
                sockets.server,
                registry.clone(),
                metrics,
                opts.stream_ceiling(),
            )),
        ];

        Ok(Self {
            http_addr: sockets.http_addr,
            quic_addr: sockets.quic_addr,
            agent_stale_after: opts.agent_stale_after,
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

    /// 停网关：**先强制把用量落库，再 abort 所有任务**。
    ///
    /// flush 并进来是为了消掉一个顺序陷阱：以前 `main.rs` 可以先 `shutdown()` 而忘了
    /// `flush_usage_on_shutdown()`，最后一个周期内的用量就随进程一起消失。落库是同步的
    /// （一次 SQLite 事务，毫秒级）。
    ///
    /// **仍然没有 drain**（TODO R12）：abort 是立即的，在途请求被直接切断——SSE 长流在
    /// 客户端看来是"流被截断"而不是正常结束；到 agent 的隧道连接随进程一起消失，靠 agent
    /// 侧指数退避（≤30s）重连。也就是说"干净退出"目前只覆盖**内存用量不丢**，
    /// **不覆盖"对用户无感"**。
    ///
    /// TODO（要求见 `REBUILD.md` §6-R12；登记见 `TODO.md`《重建蓝图 §6 未修项》R12）：
    /// 做成 drain 式关闭——① 先停 accept（不再接新请求）② 给在途请求一个宽限期
    /// ③ 到期前让在途流收到明确的结束/错误事件，使客户端能区分"被截断"与"正常结束"
    /// ④ 到点再 abort。配套：`deploy/gateway.service` 的 `TimeoutStopSec`（当前未设 =
    /// systemd 默认 90s）必须**大于**宽限期，否则宽限期还没走完就被 SIGKILL。
    ///
    /// ⚠️ `registry.rs::close_when_drained` 是"摘除单个 agent 时等它在途请求收尾"，
    /// **不是进程退出路径**，别直接复用到这里。
    pub async fn shutdown(self) {
        let n = self.key_store.flush_usage_blocking();
        tracing::info!(keys = n, "usage flushed before shutdown");
        // 显式 abort 只是让这里读起来完整；`Drop` 还会再 abort 一次（对已结束的任务是 no-op）。
        // 注意用 `&self.tasks` 而不是 `self.tasks`：`Gateway` 有 `Drop`，不能把字段移出去。
        for t in &self.tasks {
            t.abort();
        }
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
