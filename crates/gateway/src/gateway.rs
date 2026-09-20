//! 网关装配：配置（[`GatewayConfig`]）、启动（[`Gateway::start`]）、关闭（[`Gateway::shutdown`]）。
//!
//! 模块声明与再导出在 crate 根 `lib.rs`；TLS 材料（[`TlsPem`]）与 rustls 配置构造在
//! [`crate::tls`]；端口绑定在私有模块 `listen`；公网入口的 accept 循环在 [`crate::http`]。

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

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

/// 启动的全部可选项，**一次 [`Default`] 收口所有旋钮**。
///
/// 为什么必须是独立结构体：以前这些旋钮平铺在 `GatewayConfig` 上，于是新增一个旋钮要让
/// 每一个调用点都改一遍——`tests/e2e` 里 17 处 18 字段字面量、以及被逼出来的 7 个
/// `start_stack*` 辅助函数，都是这个形状的产物。现在新旋钮只改这里与 [`Options::default`]：
/// 既有调用点用 `..Options::default()`（FRU）一行都不用动。
///
/// [`Default`] 是**库 / 测试默认**：只绑本机临时端口、不碰任何文件。部署默认
/// （`0.0.0.0:8080` / `0.0.0.0:4433` / `keys.db` / `web/dist`）留在 `config::ConfigFile`
/// 的 serde 默认里——一个 `Default` 顺手把公网端口暴露出去是设计缺陷，不是便利。
/// 两者**刻意不保持 parity**：`config::from_file` 总是显式设置它们。
#[derive(Debug)]
pub struct Options {
    // ── 监听 ──
    /// HTTP(S) 公网入口监听地址。默认 `127.0.0.1:0`（内核分配临时端口）。
    pub http_bind: SocketAddr,
    /// QUIC 隧道监听地址（UDP）。默认 `127.0.0.1:0`。
    ///
    /// 注意它是 **UDP**，与 `http_bind` 的端口号含义不同，可以重合。
    pub quic_bind: SocketAddr,
    /// 提供后，公网入口启用 HTTPS（rustls）；与 QUIC 侧共用同一套身份材料。
    pub https: Option<TlsPem>,

    // ── 落地 ──
    /// Admin token；提供后启用 `/admin/*`（None = 整块路由不注册）。
    pub admin_token: Option<String>,
    /// 动态 API Key 持久化文件（None = 仅内存：**进程重启后所有 Key 消失**）。
    pub keys_file: Option<PathBuf>,
    /// React UI 静态目录（含 index.html；None = `/` 显示构建提示页）。
    pub ui_dir: Option<PathBuf>,

    // ── 旋钮 ──
    /// 已验证身份缓存容量（0 = 关闭，每请求都跑 argon2 校验）。
    ///
    /// 见 `storage::verified` 的说明：argon2 每次占 19MiB 工作内存，缓存 + 单飞
    /// 把它的成本从"每请求"降到"每(凭据版本)"，且不影响吊销即时性。
    pub verified_cache_max: usize,
    /// 单次请求转发空闲超时（逐帧）。语义是**逐帧空闲**而不是总时长，所以 SSE 长流
    /// 靠"有帧就不超时"活着。
    pub request_timeout: Duration,
    /// 隧道控制操作超时（打开流 / 发送请求头 / 取消帧）。
    ///
    /// 与 `request_timeout` 的区别：后者覆盖整个响应阶段；前者只覆盖"响应头到达之前"
    /// 那几步——健康隧道毫秒级完成，一旦超时即判定该 agent 的连接已死并摘除条目。
    /// 没有它，隧道坏掉时这些 await 可能长时间不返回，请求会一直挂在那里占着连接与缓冲。
    pub tunnel_op_timeout: Duration,
    /// 等待上游响应头（首字节）的超时。
    ///
    /// 独立于 `tunnel_op_timeout`：上游"思考"时间是合法的（本地大模型 1–3s 常见），
    /// 用 2s 的隧道控制超时去卡会误杀正常请求；但也不该沿用 `request_timeout`（120s），
    /// 否则 agent 卡死时每个请求都把连接与缓冲占满两分钟（实测 40 并发钉住约 620MB）。
    ///
    /// 它**同时**决定 [`crate::state::AppState::head_alive_window`]（4 倍），不单独设旋钮。
    pub head_timeout: Duration,
    /// 超过该时长未心跳的 agent 视为失联。
    pub agent_stale_after: Duration,
    /// 客户端"完全停滞"多久就放弃：请求体读不动 / 响应体客户端不消费。
    ///
    /// 这两处的 await 以前没有超时，会让在途请求永久占住准入槽位（实测云端沉淀了 8 个
    /// 僵尸槽位，`hlmg_active_requests` 只增不减）。0 不是"关闭"，而是"立刻超时"。
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
    /// **0 不是"不限"**：s2n-quic 里 0 意味着一条双向流都不许开（agent 连注册流都开不出来），
    /// 所以 0 会被 [`Options::stream_ceiling`] 归一到默认值。
    pub max_open_tunnel_streams: u32,
}

impl Options {
    /// 单次转发空闲超时默认值（秒）。
    pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
    /// 隧道控制操作超时默认值。见 `config::default_tunnel_op_secs` 的实测依据。
    pub const DEFAULT_TUNNEL_OP_TIMEOUT: Duration = Duration::from_secs(10);
    /// 等待上游响应头默认值。
    pub const DEFAULT_HEAD_TIMEOUT: Duration = Duration::from_secs(15);
    /// agent 失联判定默认值。
    pub const DEFAULT_AGENT_STALE_AFTER: Duration = Duration::from_secs(15);
    /// 客户端停滞阈值默认值。
    pub const DEFAULT_CLIENT_STALL: Duration = Duration::from_secs(60);
    /// 每连接隧道流额度默认值（依据见 `config::default_max_open_tunnel_streams`）。
    pub const DEFAULT_MAX_OPEN_TUNNEL_STREAMS: u32 = 1024;

    /// 实际生效的 QUIC 双向流额度：`0` 归一到默认值。
    ///
    /// **归一只在这一处发生**（以前在 `config.rs` 里，于是"库调用方传 0"与"YAML 传 0"
    /// 是两套语义——前者会被原样交给 s2n-quic，变成一条流都开不出来）。所有消费点
    /// （绑端点 / `AppState` / accept 循环）都必须走这里。
    pub fn stream_ceiling(&self) -> u32 {
        if self.max_open_tunnel_streams == 0 {
            Self::DEFAULT_MAX_OPEN_TUNNEL_STREAMS
        } else {
            self.max_open_tunnel_streams
        }
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            http_bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            quic_bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            https: None,
            admin_token: None,
            keys_file: None,
            ui_dir: None,
            verified_cache_max: KeyStore::default_verified_max(),
            request_timeout: Self::DEFAULT_REQUEST_TIMEOUT,
            tunnel_op_timeout: Self::DEFAULT_TUNNEL_OP_TIMEOUT,
            head_timeout: Self::DEFAULT_HEAD_TIMEOUT,
            agent_stale_after: Self::DEFAULT_AGENT_STALE_AFTER,
            client_stall: Self::DEFAULT_CLIENT_STALL,
            rate_limit_per_min: 0,
            max_concurrent_requests: 0,
            max_open_tunnel_streams: Self::DEFAULT_MAX_OPEN_TUNNEL_STREAMS,
        }
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
        for t in self.tasks {
            t.abort();
        }
    }
}
