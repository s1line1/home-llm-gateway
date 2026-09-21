//! 请求处理共享状态：[`AppState`] —— 路由、代理、管理接口与认证都用它。
//!
//! 为什么它不在 `http` 模块里：它曾是"路由模块"的一部分，而真正的消费者跨越了每一层
//! （`proxy`、`auth`、`admin`、metrics 中间件）。那样会让路由层成为所有人的上游，
//! 并形成 `http <-> proxy` 的模块环。搬到这里之后那三个层只**读**它，环没有了：
//! `state <- {http, proxy, auth, admin}`。
//!
//! **反向边已消**：`new` 的入参 [`Options`] 住在叶子模块 [`crate::options`]，本模块
//! **不再依赖 `gateway.rs`**——原先那条 `state <-> gateway` 随 `Options` 搬家一起消掉了。
//! `gateway::Options` 这个既有公开路径由 `gateway.rs` 再导出继续保住（`lib.rs` 与
//! `tests/e2e` 按它引用）。
//!
//! `new` 承担**全部派生**（`head_alive_window`、`RateLimiter`、`stream_ceiling`、UI 判定），
//! 所以每个派生量在整仓库只存在一处；调用方只给一个 [`Options`]。

use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::watch;

use crate::metrics::Metrics;
use crate::options::Options;
use crate::ratelimit::RateLimiter;
use crate::registry::Registry;
use crate::storage::KeyStore;
use crate::ui::{resolve_ui, IndexHtml};

/// 关闭阶段。`Running` → `Draining` → `Terminating`，只向一个方向走。
///
/// `Gateway::shutdown` 通过 [`AppState::shutdown`] 这个 `watch` 通道广播它，两类消费者：
/// - **accept 循环**（`http/entry.rs`）：`Draining` 起停止接受新连接，但在途请求继续跑；
/// - **每条在途响应**（`proxy/forward.rs`）：`Terminating` 起带一个明确的"不完整"事件收尾，
///   而不是被硬切。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShutdownPhase {
    Running,
    Draining,
    Terminating,
}

#[derive(Clone)]
pub struct AppState {
    pub registry: Registry,
    pub key_store: KeyStore,
    /// Admin token（None 表示不启用 /admin/*）。
    pub admin_token: Option<String>,
    pub timeout: Duration,
    pub agent_stale_after: Duration,
    /// 隧道控制操作超时（打开流 / 发送请求头 / 取消帧）。见 [`crate::Options`] 的说明。
    pub tunnel_op_timeout: Duration,
    /// 等待上游响应头（首字节）的超时。见 [`crate::Options`] 的说明。
    pub head_timeout: Duration,
    /// 客户端停滞阈值：请求体/响应体两个方向"完全没动静"多久就放弃。
    /// 见 [`crate::Options::client_stall`]——没有它，在途请求会永久占住准入槽位。
    pub client_stall: Duration,
    /// 响应头超时的"忙/死"判据窗口：这么久内有过成功响应头，就只是"慢"。
    ///
    /// 由 `head_timeout` 派生（4 倍），不单独设配置项：它表达的是"连续 4 个响应头超时窗口
    /// 一次都没回过"——到这个程度就不再是"排队慢"了（见 `registry::Entry::head_timeout_is_fatal`）。
    pub head_alive_window: Duration,
    pub rate_limiter: Option<RateLimiter>,
    /// HTTP 全局在途请求上限（0 = 不限；per-key 限流之外的总闸门）。
    pub max_concurrent_requests: u32,
    /// 每条 agent 连接允许的同时在途隧道流数（QUIC 双向流额度）。
    ///
    /// 两个用途：① 建 QUIC 端点时作为双向流额度（见 `Gateway::start`）；
    /// ② 开流超时时用来区分"忙"（额度排满，排队超时）与"死"（见
    /// `registry::Entry::open_timeout_is_fatal`）。
    pub max_open_tunnel_streams: u32,
    pub metrics: Metrics,
    /// React UI 静态目录（None = `/` 显示构建提示页）。
    pub ui: Option<PathBuf>,
    /// `ui/index.html` 的缓存读（按 mtime 校验），`ui` 为 None 时也是 None。
    /// 从 `ui` 派生而不是各自 `dir.join("index.html")`：读盘只有这一条路径。
    ///
    /// `pub(crate)` 而非 `pub`：其余字段是"配置值"，外部（`config.rs`/`main.rs`）会读；
    /// 这个字段只给 `http` 的 handler 用，没必要把 [`IndexHtml`] 带进公开 API。
    pub(crate) ui_index: Option<IndexHtml>,
    /// `ui_dir` 不可用的具体原因（None = 没配 ui_dir，或配了且可用）。
    /// 由启动时 [`resolve_ui`] 判定后写入，占位页会把它显示出来——否则用户只看到白屏/通用文案。
    pub ui_problem: Option<String>,
    /// 关闭阶段的广播端。见 [`ShutdownPhase`]：`Gateway::shutdown` 发，accept 循环与
    /// 在途响应任务收（各自 `subscribe()` 一个接收端）。
    pub shutdown: watch::Sender<ShutdownPhase>,
}

impl AppState {
    /// 从 [`Options`] 组装请求处理状态：配置 → `AppState` 的映射与**派生只在这一处发生**。
    ///
    /// 两个派生量都不单独设旋钮：
    /// - `head_alive_window = head_timeout × 4`：连续四个窗口一次响应头都没回来，才算"不是慢，是死"；
    /// - `max_open_tunnel_streams = opts.stream_ceiling()`：0 → 默认值，与绑 QUIC 端点同一口径。
    ///
    /// `ui_dir` 的可用性判定（[`resolve_ui`]）也在这里：它是**非致命**的启动自检，
    /// 不通过就降级成占位页，并把原因交给页面自己显示。
    pub fn new(registry: Registry, key_store: KeyStore, metrics: Metrics, opts: &Options) -> Self {
        let (ui, ui_problem) = resolve_ui(opts.ui_dir.as_deref());
        let ui_index = ui
            .as_ref()
            .map(|dir| IndexHtml::new(dir.join("index.html")));
        Self {
            registry,
            key_store,
            admin_token: opts.admin_token.clone(),
            timeout: opts.request_timeout,
            agent_stale_after: opts.agent_stale_after,
            tunnel_op_timeout: opts.tunnel_op_timeout,
            head_timeout: opts.head_timeout,
            head_alive_window: opts.head_timeout * 4,
            client_stall: opts.client_stall,
            rate_limiter: RateLimiter::new(opts.rate_limit_per_min),
            max_concurrent_requests: opts.max_concurrent_requests,
            max_open_tunnel_streams: opts.stream_ceiling(),
            metrics,
            ui,
            ui_index,
            ui_problem,
            // 关闭通道由 `AppState` 自己建：接收端各自 `subscribe()`，所以起始的接收端丢弃即可。
            shutdown: {
                let (tx, _rx) = watch::channel(ShutdownPhase::Running);
                tx
            },
        }
    }
}
