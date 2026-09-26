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
/// `Gateway::shutdown` 推进它（发送端由 `Gateway` **独占**，见 `AppState::shutdown_sender`），
/// 三类消费者：
/// - **accept 循环**（`http/entry.rs`）：`Draining` 起停止接受新连接，但在途请求继续跑；
/// - **每条在途响应**（`proxy/forward.rs`）：`Terminating` 起带一个明确的"不完整"事件收尾，
///   而不是被硬切；
/// - **每连接任务**：只关心**发送端消失**（= `Gateway` 被 drop），见
///   `state::until_gateway_is_gone`——那条路径等于"硬停"，与阶段推进不是一回事。
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
    /// 摘除一条连接后，等它在途请求收尾的宽限。见 [`crate::Options::evict_close_grace`]。
    ///
    /// 透传给 `registry::Registry::evict`。与 `head_timeout` 的大小关系是**刻意保留**的：
    /// 默认与 `head_timeout` **相等（都是 15s，2026-09 由 5s 上调）**，于是"仍在合法等响应头"
    /// 的那类在途请求不会被宽限掐断；把它配得更短时启动会 WARN（见 `Gateway::start`）。
    /// 这个值该调到多少是策略决策（见评估报告 §5 H1），本字段只负责让它可配、可回滚。
    pub evict_close_grace: Duration,
    /// 「响应头静默」判据里对端还在说话时的静默容忍上限。见 [`crate::Options::head_silent_grace`]。
    pub head_silent_grace: Duration,
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
    /// 关闭阶段的广播端。见 [`ShutdownPhase`]：`Gateway` 发，accept 循环与在途响应任务收。
    ///
    /// **`Option`，而且是 `AppState` 里唯一的一份**（复扫 D5）：`Gateway::start` 通过
    /// [`AppState::shutdown_sender`] 把它**取走**（`take()`），此后 `AppState`——以及它被克隆
    /// 进每条连接任务的那份——只剩接收端。这条不变量很要紧：`watch` 通道在**最后一个发送端
    /// 被 drop** 时才让接收端看到 `Err`，而如果 `AppState` 也留着一个发送端，那么它会被
    /// "每条连接任务手里的 Router"钉活 ⇒ `drop(Gateway)` 之后谁都不会看到通道关闭，
    /// 在途转发任务不会收尾、已接受的连接要挂到 `client_stall`（默认 60s）。
    ///
    /// **刻意私有**（评估 §2 S3）：推进阶段是**进程生命周期**的能力，只有 `Gateway` 该有。
    /// 外部拿到一个 `AppState` 只能 [`AppState::shutdown_phase`] 查询、
    /// [`AppState::subscribe_shutdown`] 订阅——`pub` 的 `watch::Sender` 等于把"停服"
    /// 交给每一个持有者。发送端只经 `pub(crate) fn shutdown_sender` **取走一次**。
    shutdown_tx: Option<watch::Sender<ShutdownPhase>>,
    /// 同一个通道的接收端：查询与订阅都从这里出发，所以发送端被取走之后
    /// [`AppState::shutdown_phase`] / [`AppState::subscribe_shutdown`] 照旧可用。
    shutdown_rx: watch::Receiver<ShutdownPhase>,
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
        let (shutdown_tx, shutdown_rx) = watch::channel(ShutdownPhase::Running);
        Self {
            registry,
            key_store,
            // `admin_token` 的**首尾空白在这里剪掉**（复扫 D2）。不剪的话它是"配了却用不了"：
            // `Options::validate` 只拒"全是空白"，而 `admin_token: " x "` 能过校验、`/admin/*`
            // 也照样挂载（下面的挂载判据与 `admin.rs` 的比较都看这个字段），但每个管理请求都是
            // 401——因为入站凭据到不了带空白的那一步：`auth::bearer_token` 在 scheme 之后
            // `trim_start_matches(' ')`，httparse 解析头部时又 **trim trailing whitespace**
            // （它显式去掉 `' '`、`'\t'`、`'\r'`、`'\n'`，见 `httparse::parse_headers` 里那句
            // 注释）。这里剪的两端正是这组字符，而不是 `str::trim()` 的 Unicode 空白——后者会把
            // 一个**本来能用**的（比如尾随 NBSP）token 改成不能用的。
            //
            // 修好它而不是拒绝它，与 E3 的 `upstream` 尾斜杠同一口径（等价写法不该把一份合法
            // 配置判死）；空串 / 全空白仍在 `Options::validate` 里拒绝——那种剪完什么都不剩，
            // 是另一回事。
            admin_token: opts
                .admin_token
                .as_deref()
                .map(|token| token.trim_matches([' ', '\t', '\r', '\n']).to_owned()),
            timeout: opts.request_timeout,
            agent_stale_after: opts.agent_stale_after,
            tunnel_op_timeout: opts.tunnel_op_timeout,
            head_timeout: opts.head_timeout,
            evict_close_grace: opts.evict_close_grace,
            head_silent_grace: opts.head_silent_grace,
            head_alive_window: opts.head_alive_window(),
            client_stall: opts.client_stall,
            rate_limiter: RateLimiter::new(opts.rate_limit_per_min),
            max_concurrent_requests: opts.max_concurrent_requests,
            max_open_tunnel_streams: opts.stream_ceiling(),
            metrics,
            ui,
            ui_index,
            ui_problem,
            // 关闭通道由 `AppState` 建、**发送端交给调用方**（`Gateway`）取走：接收端各自
            // `subscribe()`，所以起始的接收端留着做查询即可（见字段文档里那条不变量）。
            shutdown_tx: Some(shutdown_tx),
            shutdown_rx,
        }
    }

    /// 当前关闭阶段（只读）。给"探针要不要报不健康"这类判断用。
    pub fn shutdown_phase(&self) -> ShutdownPhase {
        *self.shutdown_rx.borrow()
    }

    /// 订阅关闭阶段的变化：每个在途响应各持一个接收端（`Gateway` 用 `Draining` 停 accept、
    /// 用 `Terminating` 给在途 SSE 一个明确的收尾事件）。
    pub fn subscribe_shutdown(&self) -> watch::Receiver<ShutdownPhase> {
        self.shutdown_rx.clone()
    }

    /// 把关闭通道的发送端**取走**：只给进程生命周期（`Gateway`）。
    ///
    /// `pub(crate)` 而不是 `pub`：拿不到发送端就推不动阶段，这正是收窄后的契约
    /// （见字段文档与评估 §2 S3）。`&mut self` + `take()` 而不是克隆，是复扫 D5 的要害：
    /// **发送端全仓只有一份**，"所有接收端看到 `Err`" 才真正等于"`Gateway` 没了"。
    ///
    /// 取第二次是代码错误（一个进程只有一个 `Gateway` 推进关闭阶段），所以 `.expect` 而不是
    /// 静默返回一个新的：静默克隆会把刚刚建立的不变量又破掉。
    pub(crate) fn shutdown_sender(&mut self) -> watch::Sender<ShutdownPhase> {
        self.shutdown_tx
            .take()
            .expect("shutdown_sender 只能取一次（只有 Gateway::start 该取）")
    }
}

/// 等到关闭通道**关闭**：也就是持有唯一发送端的 `Gateway` 被 drop。
///
/// 与 [`ShutdownPhase`] 的推进**不是一回事**，两个方向都不能混：
/// - `Draining` 只停 accept，已建立的连接要继续服务在途请求；
/// - `Terminating` 之后还有 `END_EVENT_WINDOW` 让在途响应把"不完整"事件真的写出去。
///
/// 只有"发送端没了"才意味着网关对象已经不在了、连接没有继续存在的理由（复扫 D5：
/// `Drop for Gateway` 承诺 abort 所有任务，而它只能 abort 那三个主任务句柄）。
/// `watch::Receiver::changed()` 在阶段变化时返回 `Ok`、在**所有发送端消失**后返回 `Err`，
/// 所以这个循环只在后者退出。返回后接收端仍可 `borrow()` 到最后一个阶段值，只是没有
/// 任何东西会再改它。
pub(crate) async fn until_gateway_is_gone(rx: &mut watch::Receiver<ShutdownPhase>) {
    while rx.changed().await.is_ok() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> AppState {
        AppState::new(
            Registry::default(),
            KeyStore::new(None),
            Metrics::default(),
            &Options::default(),
        )
    }

    /// 规格（复扫 D2）：**`admin_token` 的首尾空白在装配时剪掉**，否则它是"配了却用不了"。
    ///
    /// 这条钉的是装配点：字段是 `pub`，如果有人绕过 `AppState::new` 直接塞一个带空白的值，
    /// 鉴权仍然会 401——但那不是配置作者的路径，`Options::validate` 也拦不住空白（只拦全空白）。
    /// 走完整路由的版本在 `admin::tests::a_padded_admin_token_still_authenticates`。
    #[test]
    fn a_padded_admin_token_is_trimmed_when_the_state_is_built() {
        let opts = Options {
            admin_token: Some("  tok\t".into()),
            ..Options::default()
        };
        let state = AppState::new(
            Registry::default(),
            KeyStore::new(None),
            Metrics::default(),
            &opts,
        );
        assert_eq!(
            state.admin_token.as_deref(),
            Some("tok"),
            "两端空白必须剪掉（入站凭据到不了带空白的那一步，见 `AppState::new` 的说明）"
        );

        // 内部空白是 token 的一部分，不许动
        let opts = Options {
            admin_token: Some("to k".into()),
            ..Options::default()
        };
        let state = AppState::new(
            Registry::default(),
            KeyStore::new(None),
            Metrics::default(),
            &opts,
        );
        assert_eq!(state.admin_token.as_deref(), Some("to k"));

        // `None`（不启用 /admin/*）不受影响
        let state = AppState::new(
            Registry::default(),
            KeyStore::new(None),
            Metrics::default(),
            &Options::default(),
        );
        assert!(state.admin_token.is_none());
    }

    /// 规格（并集评估 §2 S3）：关闭阶段**可查、可订阅**，但推进阶段的能力只属于
    /// 进程生命周期——`shutdown_tx` 私有且**只有一份**，发送端只经 `pub(crate)` 取走。
    ///
    /// 这条测试钉的是"新接口的行为"：查询反映当前阶段，订阅端能收到后续变化。
    /// "外部拿不到发送端"由编译器保证（把 `shutdown_tx` 改回 `pub` 或把
    /// `shutdown_sender` 提成 `pub` 不在任何测试里会被拦住，所以字段文档里写了理由）。
    #[test]
    fn shutdown_phase_is_queryable_and_subscribable() {
        let mut state = state();
        assert_eq!(state.shutdown_phase(), ShutdownPhase::Running);

        let mut rx = state.subscribe_shutdown();
        // 发送端只有 crate 内（`Gateway` 的角色）拿得到；测试用它模拟一次推进。
        let tx = state.shutdown_sender();
        let _ = tx.send(ShutdownPhase::Draining);
        assert_eq!(state.shutdown_phase(), ShutdownPhase::Draining);
        assert_eq!(*rx.borrow_and_update(), ShutdownPhase::Draining);

        // 订阅者是**独立**接收端：第二个订阅者只看到自己订阅之后的变化
        let mut rx2 = state.subscribe_shutdown();
        let _ = tx.send(ShutdownPhase::Terminating);
        assert_eq!(*rx.borrow_and_update(), ShutdownPhase::Terminating);
        assert_eq!(*rx2.borrow_and_update(), ShutdownPhase::Terminating);
    }

    /// 规格（复扫 D5）：**`AppState` 及其克隆不得把关闭通道钉活**。
    ///
    /// 通道在最后一个发送端消失时才算"关闭"，而在途转发任务与每连接任务靠这个信号判断
    /// "网关对象没了"。如果 `AppState` 自己也留着一个发送端（修好前它确实留着一个，
    /// 且 `shutdown_sender` 给的是克隆），那么每条连接任务手里的 Router 都会把它钉活
    /// ⇒ `drop(Gateway)` 之后谁都看不到关闭：在途响应不会收尾、已接受的空闲连接要挂到
    /// `client_stall`（默认 60s）。
    ///
    /// 判据写成 `changed()` 返回 `Err`：它只可能在**所有发送端消失**时发生。
    #[tokio::test]
    async fn app_state_does_not_pin_the_shutdown_sender() {
        let mut state = state();
        let mut rx = state.subscribe_shutdown();

        // `Gateway` 的角色：取走唯一发送端，随后被 drop
        let tx = state.shutdown_sender();
        drop(tx);

        // "每条连接任务手里那份 Router"里的 AppState 克隆
        let per_connection = state.clone();
        // 带超时：判据本身就是"通道关了"，而这个缺陷的形态是"永远关不了"——不设超时的话
        // 这条测试会挂到被外部打断，而不是给出一个干净的红（`Err(Elapsed)` 直接说明原因）。
        let verdict = tokio::time::timeout(Duration::from_secs(1), rx.changed()).await;
        assert!(
            matches!(verdict, Ok(Err(_))),
            "AppState 或其克隆仍持有发送端 ⇒ 通道不会关闭，drop 网关后没人会醒来：{verdict:?}"
        );
        assert_eq!(
            per_connection.shutdown_phase(),
            ShutdownPhase::Running,
            "通道关闭只是不再变化，阶段值仍可查（连接任务据此打的日志才不会撒谎）"
        );
    }
}
