//! 启动旋钮：[`Options`] 的数据形状、库/测试默认值，以及唯一的派生点。
//!
//! **为什么单独成模块**：`Options` 是纯数据（无行为、无 I/O、无状态），却被
//! `listen`/`state`/`config`/`http` 等下层模块直接依赖。它原先住在 `gateway.rs`（顶层装配）
//! 里，于是形成两条"低层 → 顶层"的反向边：`state ↔ gateway` 与 `gateway ↔ listen`。
//! 搬到这里之后，那些模块只依赖一个叶子模块，两条边都消掉；`gateway::Options` 这个既有
//! 公开路径由 `gateway.rs` 再导出继续保住（`lib.rs` 与 `tests/e2e` 按它引用）。
//!
//! 这里**只放数据与它的默认值/派生**；装配（五阶段启动、任务、关闭）仍在 `gateway.rs`。

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use crate::{storage::KeyStore, tls::TlsPem};

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
    /// 摘除一条连接后，**等它在途请求收尾的最长时间**：超时就强制关闭。
    ///
    /// 这条宽限期要保护的正是"已经在途"的请求，而在途集合**包含两类**——已经送达 agent、
    /// 模型正在生成的，以及**仍在等响应头**的（槽位从 `try_acquire` 取得、一直持有到响应结束，
    /// 覆盖 `read_head`）。由此得到判据：**不得短于 [`Options::head_timeout`]**，否则会在别人
    /// 还在合法等响应头的时候把连接掐掉（默认值 2026-09 已由 5s 上调到与它相等的 15s；
    /// 配置得比它短时启动会打一条 WARN）。
    ///
    /// 反方向也不能无限大：连接迟迟不关，agent 侧察觉不到自己被摘除，就变回"自认为在线的
    /// 僵尸"（心跳照通、连接照开、请求永远路由不到它）。它仍远小于
    /// [`Options::request_timeout`]，所以**长回答在被摘除的连接上依然会被切断**——这是本机制
    /// 没有消除的取舍（见评估报告 §5 H1）。`0` 表示不等、立刻关。
    pub evict_close_grace: Duration,
    /// 「响应头静默」判据：**对端还在说话时**，静默最多可以被宽限到多久。
    ///
    /// 背景（评估报告 §5 H2）："忙/死"那条判据靠"最近有没有成功响应头"来分辨，而它的唯一
    /// 刷新点就是成功响应头本身。于是一旦**所有**请求都慢过 `head_timeout`（大模型首字节慢、
    /// 上游排队、链路被堵），就没有任何一次成功能刷新它 → 窗口必然走完 → 一条**活得好好的**
    /// agent 被摘除（2026-09-18 那条事故链）。这一层用"对端还在发心跳"作为它活着的证据，
    /// 把静默的容忍度延长到这里为止。
    ///
    /// 默认取 [`Options::DEFAULT_REQUEST_TIMEOUT`]（一条请求的寿命）：静默超过一整个请求的
    /// 寿命、心跳却还在，那更像**数据面卡死**而不是"慢"——那正是这条判据本来要抓的东西，
    /// 所以给它一个上界，而不是"心跳还在就永不摘除"（否则卡死的连接会永远留在路由里，
    /// 每个请求白等一次 `head_timeout` 再拿 504）。
    ///
    /// **注意**：它对"从未回过响应头"的连接不生效——那一支保持原来的快路径（见
    /// `Entry::head_timeout_is_fatal`）：注册后一个响应头都没回过，就没有任何"它能服务"的证据。
    pub head_silent_grace: Duration,
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
    /// 关闭时强制落库的**等待上限**：超过它就放弃等待、继续 abort 任务。
    ///
    /// 为什么需要：`Gateway::shutdown` 的强制落库是阻塞式 SQLite 写，而
    /// `deploy/gateway.service` 没设 `TimeoutStopSec`（systemd 默认 90s）。落库卡住时
    /// （磁盘慢、库被别处占着）进程会一直等到被 SIGKILL——**反而丢掉这次强制落库**。
    /// 有界之后 `shutdown` 至少能走完"abort 任务"并留下 WARN。
    ///
    /// 与 `TimeoutStopSec` 的关系：后者必须 **大于** 本值，否则宽限期没走完就被 SIGKILL。
    pub shutdown_flush_timeout: Duration,
    /// 关闭时等待**在途请求**收尾的最长时间：超时就切断。
    ///
    /// 顺序是"先停 accept（不再接新请求）→ 等在途归零或到本时限 → 有界落库 → abort 任务"。
    /// 取值权衡：太短则长回答被硬切（客户端看到 SSE 截断），太长则 `systemctl restart`
    /// 迟迟不返回。它与 [`Options::shutdown_flush_timeout`] 之和必须落在 `TimeoutStopSec` 之内。
    pub shutdown_grace: Duration,
}

impl Options {
    /// 单次转发空闲超时默认值（秒）。
    pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
    /// 隧道控制操作超时默认值。见 `config::default_tunnel_op_secs` 的实测依据。
    pub const DEFAULT_TUNNEL_OP_TIMEOUT: Duration = Duration::from_secs(10);
    /// 等待上游响应头默认值。
    pub const DEFAULT_HEAD_TIMEOUT: Duration = Duration::from_secs(15);
    /// 摘除后等待在途请求收尾的宽限默认值。
    ///
    /// **与 [`Options::DEFAULT_HEAD_TIMEOUT`] 相等（15s），这是有意的**（2026-09 由 5s 上调）：
    /// 宽限短于 `head_timeout` 时，宽限到期会掐断"仍在合法等响应头"的在途请求；取等之后
    /// 这一类不再被宽限切断，正在生成的那一类保护也从 5s 提到 15s。另一头的代价是僵尸窗口
    /// 从 5s 变成 15s——与 [`Options::DEFAULT_AGENT_STALE_AFTER`] 同量级，不会更久。
    /// 两者的大小关系由本文件末尾的单测钉住，防止被无声改回去。
    pub const DEFAULT_EVICT_CLOSE_GRACE: Duration = Duration::from_secs(15);
    /// 「对端还在说话时」静默容忍上限的默认值。
    ///
    /// 取 [`Options::DEFAULT_REQUEST_TIMEOUT`]（120s）：语义是"一条请求的寿命"——静默比一条
    /// 请求活得还久、心跳却仍在，那就不再像"慢"了。
    pub const DEFAULT_HEAD_SILENT_GRACE: Duration = Self::DEFAULT_REQUEST_TIMEOUT;
    /// agent 失联判定默认值。
    pub const DEFAULT_AGENT_STALE_AFTER: Duration = Duration::from_secs(15);
    /// 客户端停滞阈值默认值。
    pub const DEFAULT_CLIENT_STALL: Duration = Duration::from_secs(60);
    /// 每连接隧道流额度默认值（依据见 `config::default_max_open_tunnel_streams`）。
    pub const DEFAULT_MAX_OPEN_TUNNEL_STREAMS: u32 = 1024;
    /// 关闭时强制落库的等待上限默认值。见 [`Options::shutdown_flush_timeout`]。
    pub const DEFAULT_SHUTDOWN_FLUSH_TIMEOUT: Duration = Duration::from_secs(10);
    /// 关闭排空的等待上限默认值。见 [`Options::shutdown_grace`]。
    pub const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(15);

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
            evict_close_grace: Self::DEFAULT_EVICT_CLOSE_GRACE,
            head_silent_grace: Self::DEFAULT_HEAD_SILENT_GRACE,
            agent_stale_after: Self::DEFAULT_AGENT_STALE_AFTER,
            client_stall: Self::DEFAULT_CLIENT_STALL,
            rate_limit_per_min: 0,
            max_concurrent_requests: 0,
            max_open_tunnel_streams: Self::DEFAULT_MAX_OPEN_TUNNEL_STREAMS,
            shutdown_flush_timeout: Self::DEFAULT_SHUTDOWN_FLUSH_TIMEOUT,
            shutdown_grace: Self::DEFAULT_SHUTDOWN_GRACE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 契约：**摘除宽限不得短于 `head_timeout`**。
    ///
    /// 这不是风格偏好。在途集合里包含"仍在等响应头"的请求（槽位从 `try_acquire` 取得、
    /// 一直持有到响应结束，覆盖 `read_head`），而 `head_timeout` 正是它们自己会超时的时刻；
    /// 宽限比它短，就等于在别人还在合法等待时把连接掐掉——这就是评估报告 §5 H1 的全部内容。
    /// 断言放这里，是为了让"把宽限调小"这类改动无法静默通过。
    #[test]
    fn default_evict_close_grace_is_not_shorter_than_head_timeout() {
        assert!(
            Options::DEFAULT_EVICT_CLOSE_GRACE >= Options::DEFAULT_HEAD_TIMEOUT,
            "摘除宽限（{:?}）短于 head_timeout（{:?}）：摘除会掐断仍在合法等响应头的请求",
            Options::DEFAULT_EVICT_CLOSE_GRACE,
            Options::DEFAULT_HEAD_TIMEOUT
        );
    }

    /// 契约：**「对端还活着」的静默宽限必须长于"忙/死"窗口**，否则第二层判据形同虚设
    /// （窗口还没走完就已经按第一层处理了，延长无从谈起）。
    #[test]
    fn default_head_silent_grace_exceeds_the_busy_dead_window() {
        let window = Options::DEFAULT_HEAD_TIMEOUT * 4; // AppState::head_alive_window 的派生式
        assert!(
            Options::DEFAULT_HEAD_SILENT_GRACE > window,
            "head_silent_grace（{:?}）不长于窗口（{:?}）：第二层判据不会生效",
            Options::DEFAULT_HEAD_SILENT_GRACE,
            window
        );
    }
}
