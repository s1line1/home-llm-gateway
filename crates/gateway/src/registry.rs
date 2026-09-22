//! edge-agent 注册表：agent_id → 连接 + 健康状态 + 并发占位。

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
        Arc, RwLock,
    },
    time::Duration,
};

use serde::Serialize;
use tracing::{info, warn};

use crate::sync::{read_or_recover, write_or_recover};

/// 连接身份发号器：给每条注册进来的连接发一个**进程内唯一且永不复用**的编号。
///
/// 为什么不用 `Handle::id()`：那是 s2n-quic 的**端点内部**连接序号，源码注释写的是
/// "stable and internally identifies a connection over the whole lifetime of **an endpoint**"，
/// 而生成器是每个端点各自从 0 开始（s2n-quic-transport/src/endpoint/mod.rs:79,323、
/// src/connection/internal_connection_id.rs:26-32）——跨端点必然撞号：注册表的单元测试
/// 里每次新建一对端点，两条连接的 id 都是 0，于是 `remove_if_same` 会误删同名新连接的条目。
/// 注册表要的是"同一进程内、对一条连接稳定、且不复用"的编号（复用同样会导致误删），自己发号最稳。
static NEXT_CONN_ID: AtomicUsize = AtomicUsize::new(1);

/// agent 明细快照（供 /admin/agents 管理接口序列化）。
#[derive(Debug, Clone, Serialize)]
pub struct AgentInfo {
    pub agent_id: String,
    pub models: Vec<String>,
    pub max_concurrency: u32,
    /// 当前在途请求数。
    pub inflight: u32,
    /// 距上次心跳的秒数。
    pub last_seen_secs_ago: u64,
}

/// `agent_id → Entry` 的注册表，外加准入（`try_acquire*`）与隧道失败的判定/记账。
///
/// **两条锁纪律**（都是事故换来的，改动这里的任何方法前先看一眼）：
/// - **写锁下只碰 map 与原子量**：不 `spawn`、不调传输句柄。`tokio::spawn` 若在守卫内 panic，
///   守卫会在 unwind 中释放 → 锁**永久中毒**，之后每一次注册/心跳/选路都跟着 panic
///   （见 `Registry::evict` 与 [`Registry::register`] 的写法：动作一律留到锁外）。
/// - **心跳只取读锁**（见 [`Registry::heartbeat`]）：它只是刷新一个原子毫秒值，
///   不该与正在选路的读路径互斥。
#[derive(Clone, Default)]
pub struct Registry {
    inner: Arc<RwLock<HashMap<String, Entry>>>,
}

/// 注册表里的一条 agent 连接：身份 + 传输句柄 + 健康计数。
///
/// **字段全部私有**，外部只能通过只读访问器（[`Entry::stable_id`]、[`Entry::agent_id`]、
/// [`Entry::max_concurrency`]、[`Entry::inflight`]、[`Entry::open_stream`]）与判据方法看它。
/// 为什么必须这样：`try_acquire` 会把 `Entry` **克隆出去**给调用方长期持有（响应结束前都在），
/// 而克隆里的 `Arc<Atomic*>` 与注册表里那份是**同一块内存**——字段一旦可写，
/// 任何持有者都能改在途数、改计数、甚至关掉这条连接，注册表就没法在自己的边界内保证
/// "连续失败计数"这类不变量了。访问器给的是值（`usize`/`u32`/`&str`）或受控动作
/// （[`Entry::open_stream`]），不是那块内存本身。
#[derive(Debug, Clone)]
pub struct Entry {
    conn: s2n_quic::connection::Handle,
    stable_id: usize,
    /// 注册时的 agent_id。`try_acquire` 只交出 `Entry`（HashMap 的 key 不在其中），
    /// 而隧道写超时后需要按 stable_id 把这条坏连接摘掉（内部走 `Registry::evict`），
    /// 所以 id 必须随条目一起带出来。
    agent_id: String,
    models: Vec<String>,
    max_concurrency: u32,
    /// 当前在途请求数（admission control）。
    inflight: Arc<AtomicU32>,
    /// 最近一次心跳的时刻（自 `epoch` 起的毫秒数）。
    ///
    /// 与 `last_head_ok` **共用同一个时间基准**。早先这里存 `Instant`、那边存相对毫秒：
    /// 两套时钟并存时"心跳新鲜"与"响应头新鲜"没法直接对账，而且 `Instant` 不是原子类型，
    /// 只能靠写锁 + `get_mut` 才能改——于是每来一帧心跳都要独占整张表（见
    /// [`Registry::heartbeat`]）。换成原子毫秒之后这两件事一起解决。
    ///
    /// 用 `Arc` 包一层是为了让 `Entry: Clone`（`AtomicU64` 自身不是 `Clone`），与同结构里
    /// `inflight` / 三个 strike 计数 / `last_head_ok` 保持同一种形状。
    last_seen_millis: Arc<AtomicU64>,
    /// **收到过心跳**的时刻（自 `epoch` 起的毫秒数）；初值 `NEVER` = 从未收到过。
    ///
    /// 与 `last_seen_millis` 刻意分开：那个在注册时就写了一次（"刚注册的 agent 可以立刻
    /// 参与路由"）。而"对端还活着吗"要的是**它说过话**这个事实——注册本身不算说话。
    /// 用途见 [`Entry::peer_alive`]（响应头静默判据的第二层）。
    last_heartbeat_millis: Arc<AtomicU64>,
    /// 连续"**开流**超时且判定为死"的次数（判据见 [`Entry::open_timeout_is_fatal`]）。
    ///
    /// **每一种失败原因各有一条计数**（开流 / 响应头 / 写帧失败）：混在一起时，三种
    /// **不同**的轻微失败会凑满同一个阈值，把一条其实健康的连接摘掉；而且一种失败达到
    /// 阈值后，另一种的"连续"语义会被无声改写。
    open_timeouts: Arc<AtomicU32>,
    /// 连续"**响应头**静默超时"的次数（判据见 [`Entry::head_timeout_is_fatal`]）。
    head_timeouts: Arc<AtomicU32>,
    /// 连续"**写请求帧直接失败**"的次数。
    ///
    /// 只有"写直接返回错误"计这里；**写超时不计**——那是连接级背压（共享发送缓冲/拥塞），
    /// 不是隧道死亡。写帧超时的死亡检出交给开流与响应头两条判据。
    tunnel_write_failures: Arc<AtomicU32>,
    /// **最近一次真的收到响应头**的时刻（自 `epoch` 起的毫秒数）。
    ///
    /// 初值是 `NEVER`（从未收到过）。**注册不算"活着"**：注册只证明连接建起来了，
    /// 而这条判据问的是响应头有没有在流动。
    ///
    /// 为什么要单独记它：上面那几条计数只回答"连续失败了几次"，回答不了
    /// "这条隧道最近还干不干活"。链路被堵住时是"一个响应头都收不到"，于是计数必然爬到阈值，
    /// 把**健康但被堵住**的 agent 摘掉（实测：出口 0.4 MB/s 饱和时 1 026 次
    /// `upstream head timeout; evicting agent`，随后全量 503）。有了这个时间戳，
    /// 响应头超时就能像开流超时那样区分"忙/慢"与"死"（见 [`Entry::head_timeout_is_fatal`]）。
    last_head_ok: Arc<AtomicU64>,
}

/// 一次隧道失败的原因。[`Registry::evict`] 按它**分别**计连续次数，互不充值对方的阈值。
///
/// **内部类型**：调用方不再自己判断该记哪一种，而是通过 [`Registry::report_open_timeout`]、
/// [`Registry::report_open_failed`]、[`Registry::report_head_timeout`]、
/// [`Registry::report_write_failed`] 四个入口上报"发生了什么"，由注册表决定原因与后果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvictCause {
    /// 开流这条路失败：**超时且未达承载上限**（见 [`Entry::open_timeout_is_fatal`]），
    /// 或**直接返回错误**（见 [`Registry::report_open_failed`]）。两者在注册表看来是同一件事
    /// ——开不出流——所以共用这一条计数。
    OpenTimeout,
    /// 响应头静默超时 → 判定为死（见 [`Entry::head_timeout_is_fatal`]）。
    HeadTimeout,
    /// 写请求帧**直接失败**（非超时）→ 连接确已不可用。
    TunnelWriteFailed,
}

/// "从未收到过响应头"的哨兵值。
///
/// 不能用 0 当"从未"：时间基准是**首次使用时才创建**的，进程刚起来那一瞬间
/// `now_millis()` 就是 0，会和"从未"撞在一起。`u64::MAX` 不可能被真实时间戳取到。
const NEVER: u64 = u64::MAX;

/// 时间基准：进程内单调时钟的原点（`Instant` 不能放进原子变量，所以存相对毫秒）。
fn epoch() -> std::time::Instant {
    static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    *EPOCH.get_or_init(std::time::Instant::now)
}

/// 自 `epoch` 起的毫秒数（用于 `last_head_ok` 这类无锁时间戳）。
///
/// **内部函数**：对外只通过 [`Entry::last_head_ago`] 暴露"安静了多久"，进程相对时钟与
/// `NEVER` 哨兵都不出注册表。
fn now_millis() -> u64 {
    epoch().elapsed().as_millis() as u64
}

/// 距上次心跳过了多久（毫秒）。
fn since_millis(last_seen_millis: u64, now_millis: u64) -> u64 {
    now_millis.saturating_sub(last_seen_millis)
}

/// 心跳是否仍在新鲜期内（= 这条条目参与路由与模型聚合）。
///
/// **这条判据原先在五个地方各写一遍**（`healthy_count`、`status`、`snapshot`、
/// `try_acquire_excluding`、`healthy_models`）。口径一旦分叉，"可路由的 agent 数"与
/// "选路时真正被过滤掉的数量"就对不上——而这两个数正是排查"所有请求 503"时唯一能互相
/// 对照的东西（见 `hlmg_agents` 与 `hlmg_agents_healthy` 的 HELP）。
fn is_fresh(last_seen_millis: u64, now_millis: u64, stale_after: Duration) -> bool {
    since_millis(last_seen_millis, now_millis) < stale_after.as_millis() as u64
}

/// 「响应头静默」判据需要的三个时间窗。
///
/// 三个都是 `Duration`、语义却完全不同（窗口 / 对端活着 / 静默上限），所以用结构体传而不是
/// 三个位置参数——顺序写错不会有任何编译错误，只会让判据悄悄变松或变紧。
#[derive(Debug, Clone, Copy)]
pub struct HeadSilence {
    /// "忙/死"窗口：这么久内有过成功响应头就只是慢。= `head_timeout × 4`。
    pub window: Duration,
    /// "对端还活着"的判据：心跳在这个时间内 = 它还在说话。= `agent_stale_after`。
    pub peer_alive_window: Duration,
    /// 对端活着时，静默最多可以被宽限到多久。= `Options::head_silent_grace`（默认一条请求的寿命）。
    pub stuck_after: Duration,
}

impl Entry {
    /// 这条条目的连接身份：进程内唯一、**永不复用**（见 [`Registry::register`] 的说明）。
    pub fn stable_id(&self) -> usize {
        self.stable_id
    }

    /// 注册时声明的 agent_id。
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// agent 声明的并发上限（`0` = 不限）。只用于日志/展示。
    pub fn max_concurrency(&self) -> u32 {
        self.max_concurrency
    }

    /// 当前在途请求数。**含正在等响应头的那一类**（槽位从 `try_acquire` 取得，一直持有到
    /// 响应结束）。只给日志/展示用——判据请走 [`Self::open_timeout_is_fatal`]，
    /// 不要拿这个数自己推"忙还是死"。
    pub fn inflight(&self) -> u32 {
        self.inflight.load(Ordering::Relaxed)
    }

    /// 在这条连接上打开一条双向流。
    ///
    /// **超时策略不在这里**：多久算超时是 `Options::tunnel_op_timeout`，由调用方
    /// （`proxy::tunnel::open_tunnel`）用 `tokio::time::timeout` 包住。本方法的作用是把
    /// 传输句柄挡在注册表里面——否则每个想开流的模块都得拿到 `s2n_quic::connection::Handle`，
    /// 也就等于拿到了"关掉这条连接"的能力。
    ///
    /// 需要 `&mut self`：`s2n_quic::connection::Handle::open_bidirectional_stream` 自身就是
    /// `&mut self`（它在句柄内部记流状态）。这是唯一一处需要 `Entry` 可变借用的地方。
    pub async fn open_stream(
        &mut self,
    ) -> Result<s2n_quic::stream::BidirectionalStream, s2n_quic::connection::Error> {
        self.conn.open_bidirectional_stream().await
    }

    /// 一次「开流超时」是否足以判定这条连接**已死**（该摘除）。
    ///
    /// 为什么不能一律摘除：`open_bidirectional_stream()` 在**连接级流额度**排满时会
    /// 排队等回收（s2n-quic 的额度声明，实际可用取 `min(本地, 对端)`）。这条路径上的
    /// 超时既可能是"对端死了"，也可能只是"对端忙"：在途请求数已经顶到这条连接能承载的
    /// 上限时，排队超时是**正常背压**的表现。
    ///
    /// 把它一律当"死"的代价在云端实测过：上游一慢 → 开流排队超时 → 摘除**健康但繁忙**的
    /// agent → 连接被关 → agent 重连 → 注册表瞬间为空 → 其间所有请求 503
    /// （单次 30s 压测 +6835 次 `registry-empty`），是"局部过载"被放大成"全站不可用"。
    ///
    /// 判定口径：在途数是否已达到这条连接的实际承载上限
    /// （`min(声明的 max_concurrency, 端点流额度)`；`max_concurrency == 0` = 不限，
    /// 此时上限就是端点流额度）。达到 → 忙，不摘除；未达到 → 说明并不是没额度，
    /// 那就是真死了。
    /// 一次「响应头超时」是否足以判定这条连接**已死**（该摘除）。
    ///
    /// 与 [`Entry::open_timeout_is_fatal`] 同一套思路，但问的是另一个问题：开流超时问
    /// "还有额度吗"，响应头超时问 **"这条隧道最近还在干活吗"**——因为响应头超时的两种成因
    /// 在现象上完全一样（`head_timeout` 内没等到头），区别只在于"是被堵住的慢"还是"真的没有了"。
    ///
    /// **两层口径**（第二层是 2026-09 为修"均匀慢流量"那条误判加的，见评估报告 §5 H2）：
    ///
    /// 1. `window` 内**有过**成功响应头 → 只是慢（返回 `false`，调用方只回 504、不计 strike）。
    /// 2. 窗口已过，但**对端还在说话**（心跳新鲜，见 `Entry::peer_alive`）且静默没超过
    ///    `stuck_after` → 仍然只是慢。为什么需要它：`last_head_ok` 的唯一刷新点就是成功响应头
    ///    本身，所以一旦**所有**请求都慢过 `head_timeout`（大模型首字节慢、上游排队、链路被堵），
    ///    就没有任何一次成功能刷新它，窗口必然走完 → 一条活得好好的 agent 被摘除 → 关连接 →
    ///    agent 重连 → 注册表为空 → 全量 503，**正是这条判据本来要防的那条链**（2026-09-18 实测）。
    ///    对端还在发心跳就说明它还在说话；而"数据面被堵住的慢"与"数据面卡死"在网关侧**观察上
    ///    无法区分**，这一层选择"宁可晚摘，不误摘"。
    /// 3. 其余 → 死：窗口已过，且（对端不再说话 **或** 静默已超过 `stuck_after`）。
    ///
    /// **"从未回过响应头"仍然是快路径**：没有成功响应头就**没有"它能服务"的证据**，于是不做
    /// 第 2 层的延长，直接交给连续 3 次摘除（既有 e2e
    /// `e2e_dead_tunnel_fails_fast_instead_of_hanging` 钉着这一点）。已知代价：一条**注册后
    /// 一次都没回包**、但还在心跳的连接（例如首字节一直慢过 `head_timeout`）仍会在 3 次之后
    /// 被摘除——这是这一层明确不覆盖的形态。
    ///
    /// 代价与兜底（第一层的旧账）：真死但"最近刚成功过"的 agent 会晚 `window` 才被摘除。
    /// 这不影响路由——真死的 agent 心跳会停，`agent_stale_after` 会先把它从候选里剔掉；
    /// 而进程直接消失时，QUIC 连接关闭会走 `remove_if_same` 正常摘除，根本不经过这里。
    /// 第二层的代价：一条**心跳正常但数据面卡死**的连接要等到静默超过 `stuck_after`
    /// （默认一条请求的寿命）才会被摘除，这期间它的每个请求都要白等一次 `head_timeout` 再拿 504。
    pub fn head_timeout_is_fatal(&self, ctx: HeadSilence) -> bool {
        let silence = self.last_head_ago();
        let Some(silence) = silence else {
            // 从未回过响应头：无"它能服务"的证据 → 快路径判死（见上）。
            return true;
        };
        if silence <= ctx.window {
            return false;
        }
        // 窗口已过。对端还在说话，且沉默还没到"一条请求的寿命"→ 更像被堵住，不摘。
        !(self.peer_alive(ctx.peer_alive_window) && silence <= ctx.stuck_after)
    }

    /// 对端最近还在说话吗：**收到过心跳**，且心跳在 `window` 内。
    ///
    /// 注意它与 `last_seen` **不是同一个问题**：`last_seen` 在注册时就写过一次（用于"刚注册
    /// 的 agent 可以立刻参与路由"），所以"注册时间戳很新"不能当成"对端还活着"。这里要的是
    /// "收到过心跳"这个**事实**，因此单独记 `last_heartbeat_millis`，初值 `NEVER`——一个注册后
    /// 什么都不做的对端（既有 e2e 里的"裸 agent"）永远不满足它。
    fn peer_alive(&self, window: Duration) -> bool {
        let hb = self.last_heartbeat_millis.load(Ordering::Relaxed);
        hb != NEVER && is_fresh(hb, now_millis(), window)
    }

    /// 距**最近一次真的收到响应头**过了多久；`None` = 从未收到过。
    ///
    /// 只给失败路径的日志用（"这条隧道到底安静了多久"）。把 `NEVER` 哨兵与进程相对时钟
    /// 都挡在注册表里面——调用方原先要自己 `now_millis() - last_head_ok.load(..)`，
    /// 那等于让每个调用方都知道哨兵的存在。
    pub fn last_head_ago(&self) -> Option<Duration> {
        let last = self.last_head_ok.load(Ordering::Relaxed);
        if last == NEVER {
            return None;
        }
        Some(Duration::from_millis(now_millis().saturating_sub(last)))
    }

    pub fn open_timeout_is_fatal(&self, stream_ceiling: u32) -> bool {
        let ceiling = stream_ceiling.max(1);
        let effective = if self.max_concurrency == 0 {
            ceiling
        } else {
            self.max_concurrency.min(ceiling)
        };
        self.inflight.load(Ordering::Relaxed) < effective
    }
}

/// 一次隧道失败的**处置**：注册表判定，调用方只负责渲染。
///
/// 为什么是一个类型而不是 `bool`：三个调用点问的是同一个问题的三种问法——"还有额度吗"
/// （开流超时）、"最近还干活吗"（响应头超时）、"是不是直接失败了"（写帧）。判据只该存在
/// 一处，而**后果**（记哪条 strike、要不要摘除、要不要关连接）也只该由那一处决定。
/// 以前两个调用方各自把 `open_timeout_is_fatal` / `head_timeout_is_fatal` 与
/// `matches!(failure, TimedOut)` 拼成 `busy` 布尔量，再各自决定记哪个指标、回什么状态码——
/// "什么算忙、什么算死"这条策略因此散在两个模块里。
///
/// **调用方拿它做什么**：只映射成对外的文案与指标标签（`busy`/`dead`、`slow`/`silent`、
/// `backpressure`/`broken`）以及状态码。那些是外部契约，留在原处。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// 只是一时受阻（忙 / 慢 / 背压）：**不计 strike、不摘除**，调用方按容量或超时回应。
    Transient,
    /// 判定为**死**：已计一次 strike（连续达到阈值时，条目已被移出路由并安排关闭）。
    Fatal,
}

/// 选路规则（**纯函数**，评估 §8 的 passB 建议）：从当前条目里挑出**按优先级排好序**的候选。
///
/// 次序：新鲜 → 不在 `exclude` 里 → 能服务该模型 → 精确声明优先于 `*` 通配 → 负载轻优先
/// → 心跳新者优先。两个错误变体各代表"被哪一层滤空"（`NoAgent` = 没人可用/都过期，
/// `NoModel` = 有人但都不声明这个模型），调用方据此区分 503 文案。
///
/// 为什么抽成纯函数：规则以前与"占位 + 返回槽位"的副作用揉在 `try_acquire_excluding` 里，
/// 只能靠注册表端到端测；现在规则本身可以直接用一组条目断言（见单测
/// `pick_orders_exact_over_wildcard_then_lightest`）。
fn pick<'a>(
    entries: impl Iterator<Item = &'a Entry>,
    now: u64,
    stale_after: Duration,
    model: &str,
    exclude: &[usize],
) -> Result<Vec<&'a Entry>, AcquireError> {
    let mut candidates: Vec<&Entry> = entries
        .filter(|e| is_fresh(e.last_seen_millis.load(Ordering::Relaxed), now, stale_after))
        .filter(|e| !exclude.contains(&e.stable_id))
        .collect();
    if candidates.is_empty() {
        return Err(AcquireError::NoAgent);
    }
    // 模型过滤：只保留能服务请求模型的 agent（声明含 "*" 或含 model）
    candidates.retain(|e| e.models.iter().any(|m| m == "*" || m == model));
    if candidates.is_empty() {
        return Err(AcquireError::NoModel);
    }
    // 排序：精确声明（exact=true）排前 → 负载轻优先 → 心跳新者优先。
    // bool 排序 false < true，故用 !exact 让精确者排前。
    candidates.sort_by_key(|e| {
        let exact = e.models.iter().any(|m| m == model);
        (
            !exact,
            e.inflight.load(Ordering::Relaxed),
            std::cmp::Reverse(e.last_seen_millis.load(Ordering::Relaxed)),
        )
    });
    Ok(candidates)
}

impl Registry {
    /// 注册 agent；若同名 agent 已有其他连接，关闭旧连接。
    ///
    /// 返回本次注册分配的 `stable_id`：调用方之后要用它调 [`Self::remove_if_same`] 摘除条目，
    /// 所以**必须用这个返回值**，不要自己另算一份——`Entry.stable_id` 由这里独占决定，
    /// 两处各算一次就会对不上，连接结束时条目永远摘不掉（注册表只增不减）。
    pub fn register(
        &self,
        agent_id: String,
        models: Vec<String>,
        max_concurrency: u32,
        conn: s2n_quic::connection::Handle,
    ) -> usize {
        let stable_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        // 写锁下只碰 map（与 `evict` 同一条纪律）：被顶替的那条连接的关闭动作留到锁外，
        // 免得把传输调用夹在守卫里。
        let superseded = {
            let mut inner = write_or_recover(&self.inner);
            let superseded = match inner.get(&agent_id) {
                Some(old) if old.stable_id != stable_id => {
                    warn!(agent = %agent_id, "duplicate agent connection, closing old one");
                    Some(old.conn.clone())
                }
                _ => None,
            };
            inner.insert(
                agent_id.clone(),
                Entry {
                    conn,
                    stable_id,
                    agent_id,
                    models,
                    max_concurrency,
                    inflight: Arc::new(AtomicU32::new(0)),
                    open_timeouts: Arc::new(AtomicU32::new(0)),
                    head_timeouts: Arc::new(AtomicU32::new(0)),
                    tunnel_write_failures: Arc::new(AtomicU32::new(0)),
                    // 注册不是"活着"的证据：注册只说明连接建起来了，而这条判据问的是
                    // "**响应头**最近有没有流动"。所以从 NEVER 开始——一条注册后从不回响应头的
                    // 坏隧道必须能被原来的连续 3 次规则摘掉，不能因为"刚注册"而获得宽限
                    // （这条正是既有 e2e `e2e_dead_tunnel_fails_fast_instead_of_hanging` 钉住的）。
                    last_head_ok: Arc::new(AtomicU64::new(NEVER)),
                    last_seen_millis: Arc::new(AtomicU64::new(now_millis())),
                    // 注册**不算**"对端说过话"：初值 NEVER，等真收到心跳才算。
                    last_heartbeat_millis: Arc::new(AtomicU64::new(NEVER)),
                },
            );
            superseded
        };
        if let Some(old) = superseded {
            old.close(0u32.into());
        }
        stable_id
    }

    /// 刷新某条条目的心跳时刻。
    ///
    /// **只取读锁**：刷新心跳只是往一个原子量里写毫秒数，不需要独占整张表。以前这里用
    /// `write()` + `get_mut()`，因为 `Instant` 不是原子类型、只能靠可变借用来写——代价是
    /// 每来一帧心跳（agent 侧每 5s 一帧，多 agent 时叠加）就把**所有正在选路的读锁**挡在门外。
    /// 换成原子毫秒后，这个热点不再与路由争锁。
    pub fn heartbeat(&self, agent_id: &str) {
        if let Some(e) = read_or_recover(&self.inner).get(agent_id) {
            let now = now_millis();
            e.last_seen_millis.store(now, Ordering::Relaxed);
            // 同时也是"对端说过话"的证据：响应头静默判据的第二层靠它（见 `Entry::peer_alive`）。
            e.last_heartbeat_millis.store(now, Ordering::Relaxed);
        }
    }

    /// 仅当条目仍对应给定连接（stable_id）时才移除，防止误删新连接的同名条目。
    pub fn remove_if_same(&self, agent_id: &str, stable_id: usize) {
        let mut inner = write_or_recover(&self.inner);
        if let Some(e) = inner.get(agent_id) {
            if e.stable_id == stable_id {
                inner.remove(agent_id);
                info!(agent = %agent_id, "agent removed (connection closed)");
            }
        }
    }

    /// 同一原因的连续隧道失败阈值：达到它才认为"这条连接真的死了"。
    ///
    /// 取 3 而不是 1：单次失败在高并发下是**排队假象**——开流/写帧都要过连接级流管理器，
    /// 768 并发时很容易超过 `tunnel_op_secs`。实测（2026-09-17，双 agent/768 并发）：
    /// 第一次超时就把条目摘掉，而连接其实完好、agent 也毫不知情，于是每 5s 心跳继续
    /// 刷新心跳时刻（那时注册表里已经没有它）、所有请求 `503 registry-empty`（占比 92.6%）。
    ///
    /// 阈值对**每一种原因**各自适用（内部按 `EvictCause` 分开记；对外的入口是
    /// [`Registry::report_open_timeout`] 等四个方法）。
    pub const TUNNEL_TIMEOUTS_BEFORE_EVICT: u32 = 3;

    /// 一次**成功收到响应头**：清掉全部连续失败计数，并记下"这条隧道最近真的在干活"。
    ///
    /// 为什么一次成功要清三种计数：一次真正回来的响应头证明的是"这条隧道现在是通的"，
    /// 对开流、写帧、响应头三条判据都是同一份证据。唯一的调用点在响应头那一支
    /// （`proxy/mod.rs`）——**开流或写帧成功不算**：agent 卡死时流照样能开、帧也照样写得出去，
    /// 只是永远不回帧。
    ///
    /// **这里是按 `stable_id` 的全表扫描**（`:238` 与 `evict` 的查找同理）：map 以 `agent_id`
    /// 为键，而这条路径手上只有 `stable_id`。暂时不改成双索引：生产上 `n` 只有 1–4 个 agent
    /// （云端实测 `hlmg_agents 1`），扫 4 个元素远比它旁边那次 HTTP 往返便宜。真要动它，
    /// 先拿 profiling 说话（评估 §2 C4 的结论也是"别在没数据时动"）。
    pub fn note_tunnel_op_ok(&self, stable_id: usize) {
        let inner = read_or_recover(&self.inner);
        if let Some(e) = inner.values().find(|e| e.stable_id == stable_id) {
            e.open_timeouts.store(0, Ordering::Relaxed);
            e.head_timeouts.store(0, Ordering::Relaxed);
            e.tunnel_write_failures.store(0, Ordering::Relaxed);
            // 顺手记下"这条隧道最近真的回过响应头"——响应头超时的"忙/死"判据靠它。
            e.last_head_ok.store(now_millis(), Ordering::Relaxed);
        }
    }

    /// 上报一次「**开流超时**」，由注册表判定是**忙**还是**死**。
    ///
    /// 判据在 [`Entry::open_timeout_is_fatal`]：在途已达这条连接的承载上限 → 只是排队等额度
    /// （[`Disposition::Transient`]，**不记账**）；没到上限却开不出流 → 死。
    /// 返回 [`Disposition::Fatal`] 时**已经**记过一次 strike，连续到阈值时条目也已被摘除；
    /// 调用方只需把它映射成文案、指标标签与状态码。
    pub fn report_open_timeout(
        &self,
        entry: &Entry,
        stream_ceiling: u32,
        close_grace: Duration,
    ) -> Disposition {
        if entry.open_timeout_is_fatal(stream_ceiling) {
            self.evict(entry.stable_id, EvictCause::OpenTimeout, close_grace);
            Disposition::Fatal
        } else {
            Disposition::Transient
        }
    }

    /// 上报一次「**开流直接失败**」（不是超时）。没有"忙"这种可能，直接记账。
    pub fn report_open_failed(&self, entry: &Entry, close_grace: Duration) {
        self.evict(entry.stable_id, EvictCause::OpenTimeout, close_grace);
    }

    /// 上报一次「**响应头超时**」，由注册表判定是**慢**还是**死**。
    ///
    /// 判据在 [`Entry::head_timeout_is_fatal`]，**两层**：窗口内有过成功响应头 → 只是被链路或
    /// 上游堵住（[`Disposition::Transient`]，只回 504、**不计 strike**）；窗口过了但**对端还在
    /// 说话**（心跳新鲜）且静默没超过"一条请求的寿命" → 仍然算慢（这是 2026-09 为修"均匀慢流量"
    /// 那条误判加的，见评估 §5 H2）；其余 → 死。窗口与两个时限都由调用方从 `AppState` 传入
    /// （见 [`HeadSilence`]）。
    pub fn report_head_timeout(
        &self,
        entry: &Entry,
        silence: HeadSilence,
        close_grace: Duration,
    ) -> Disposition {
        if entry.head_timeout_is_fatal(silence) {
            self.evict(entry.stable_id, EvictCause::HeadTimeout, close_grace);
            Disposition::Fatal
        } else {
            Disposition::Transient
        }
    }

    /// 上报一次「**写请求帧直接失败**」（不是超时）。同样没有判据，直接记账。
    ///
    /// 写**超时**不走这里——那是连接级背压（同一条连接上的流共享发送缓冲/UDP socket），
    /// 见 `WriteFailure::is_tunnel_broken`。
    pub fn report_write_failed(&self, entry: &Entry, close_grace: Duration) {
        self.evict(entry.stable_id, EvictCause::TunnelWriteFailed, close_grace);
    }

    /// 记录一次隧道失败，并在**同一原因连续**达到阈值时摘除条目。
    ///
    /// **内部实现**：调用方走 [`Self::report_open_timeout`] / [`Self::report_head_timeout`] /
    /// [`Self::report_broken_tunnel`]——那三个方法才是"判定 + 记账 + 摘除"的对外入口，
    /// 本方法只负责"给定原因就记一笔"这一层。
    ///
    /// `cause` 决定计哪一条连续计数（见 [`EvictCause`]）：不同原因的阈值互不充值——
    /// 否则三种不同的轻微失败会凑满一个阈值，把健康连接摘掉。
    ///
    /// 关键：摘除时**同时关闭连接**。只删条目不关连接会留下"僵尸"——agent 侧看不到
    /// 任何异常（心跳照通、连接照开），却永远无法再被路由；agent 只有等到自己判断
    /// 连接不可用才会重连，而那一刻可能永远不来。
    ///
    /// `close_grace` 是"移出路由之后最多再等多久就关连接"：由调用方从
    /// [`crate::Options::evict_close_grace`] 传入。与 `stale_after`、`stream_ceiling`、
    /// `window` 一样采取**每调用注入**——注册表自己不存配置。
    ///
    /// 返回是否真的摘掉了（false = 计数未达阈值，或条目已被别人摘掉/替换）。
    fn evict(&self, stable_id: usize, cause: EvictCause, close_grace: Duration) -> EvictOutcome {
        // 写锁的范围**只够**做 map 与原子量的事：查找、计 strike、移出路由、读在途数。
        // 关闭连接与 spawn 调度一律留到锁外——`tokio::spawn` 若在守卫内 panic，守卫会在
        // unwind 中释放 → 锁**永久中毒**，之后每一次 register/heartbeat/选路都跟着 panic
        // （评估 §5 H3）。这条纪律对 `register` 同样适用。
        let (agent_id, entry, n, inflight) = {
            let mut inner = write_or_recover(&self.inner);
            let hit = inner
                .iter()
                .find(|(_, e)| e.stable_id == stable_id)
                .map(|(k, e)| (k.clone(), e.clone()));
            let Some((agent_id, entry)) = hit else {
                return EvictOutcome::NotFound;
            };
            let strikes = match cause {
                EvictCause::OpenTimeout => &entry.open_timeouts,
                EvictCause::HeadTimeout => &entry.head_timeouts,
                EvictCause::TunnelWriteFailed => &entry.tunnel_write_failures,
            };
            let n = strikes.fetch_add(1, Ordering::Relaxed) + 1;
            if n < Self::TUNNEL_TIMEOUTS_BEFORE_EVICT {
                warn!(
                    agent = %agent_id,
                    consecutive = n,
                    threshold = Self::TUNNEL_TIMEOUTS_BEFORE_EVICT,
                    cause = ?cause,
                    "tunnel failure; keeping the entry for now"
                );
                return EvictOutcome::BelowThreshold { consecutive: n };
            }

            // ① 先移出路由：后续请求不会再选中它（这一步与关闭时机无关）。
            inner.remove(&agent_id);
            let inflight = entry.inflight.load(Ordering::Relaxed);
            (agent_id, entry, n, inflight)
        };

        // ② 再决定何时关闭连接。**不能立刻关**：这条连接上往往还有别的在途请求，
        //    而它们在 `inflight` 里有两类，**两类都不该被连带打断**：
        //      · 已经把请求完整送达 agent、模型正在生成的——早过了响应头那一关，
        //        不属于"建立阶段可重试"的范围，打断就是纯损失（客户白花钱还拿不到结果）；
        //      · **还在等响应头的**——槽位是从 `try_acquire` 取得、一直持有到响应结束的
        //        （`routing.rs` 取得 → `proxy/mod.rs` 的 `read_head` → `forward.rs` 持有），
        //        所以它们也在 `inflight` 里；它们并没有出错，只是还没轮到回包。
        //    所以在途归零后再关；超过宽限期也强制关，否则 agent 永远是僵尸。
        //    调度与期限都在 `crate::evict_close` 里（连同"宽限不得短于 head_timeout"那条约束）。
        if inflight <= 1 {
            // 只有当前这个失败请求占着槽位 → 关掉不会牵连别人。
            // 而且要**立刻**关，好让 agent 察觉并重连，别变回僵尸。
            entry.conn.close(0u32.into());
            warn!(
                agent = %agent_id,
                consecutive = n,
                cause = ?cause,
                "agent evicted (repeated tunnel failures); closing connection so one side notices"
            );
            EvictOutcome::RemovedClosed
        } else {
            warn!(
                agent = %agent_id,
                consecutive = n,
                inflight,
                grace_secs = close_grace.as_secs(),
                "agent evicted; deferring connection close until in-flight requests drain"
            );
            crate::evict_close::defer_close(
                entry.conn.clone(),
                entry.inflight.clone(),
                &entry.agent_id,
                close_grace,
            );
            EvictOutcome::RemovedClosedLater { inflight }
        }
    }

    pub fn len(&self) -> usize {
        read_or_recover(&self.inner).len()
    }

    /// 注册表里 **心跳未过期** 的 agent 数（= 真正能被路由的候选数）。
    ///
    /// 与 [`Self::len`] 的区别很要紧：条目要等连接真正关闭才摘除，所以失联 agent
    /// 会继续被 `len()`（以及 `/metrics hlmg_agents`、`/admin/agents`）算作"在线"，
    /// 但它**不参与路由**。排查"所有请求 503"时必须能区分这两者——否则会误判为
    /// "agent 掉了"，实际是"注册表里有、但全部不健康"。
    pub fn healthy_count(&self, stale_after: Duration) -> usize {
        let inner = read_or_recover(&self.inner);
        let now = now_millis();
        inner
            .values()
            .filter(|e| is_fresh(e.last_seen_millis.load(Ordering::Relaxed), now, stale_after))
            .count()
    }

    /// 挑不出候选时的诊断快照（只用于失败路径的日志/指标，不进热路径）。
    pub fn status(&self, stale_after: Duration) -> RegistryStatus {
        let inner = read_or_recover(&self.inner);
        let now = now_millis();
        let mut healthy = 0usize;
        let mut oldest: Option<Duration> = None;
        for e in inner.values() {
            let last = e.last_seen_millis.load(Ordering::Relaxed);
            let age = Duration::from_millis(since_millis(last, now));
            if is_fresh(last, now, stale_after) {
                healthy += 1;
            }
            oldest = Some(match oldest {
                Some(o) if o >= age => o,
                _ => age,
            });
        }
        RegistryStatus {
            registered: inner.len(),
            healthy,
            oldest_last_seen_ago: oldest,
        }
    }

    /// 注册表是否为空。
    ///
    /// **看起来没人调用，但删不得**：clippy 的 `len_without_is_empty` 是**默认开启**的，
    /// 一个公开类型有 `pub fn len` 却没有 `is_empty` 就会告警（实测：删掉它会得到
    /// `struct Registry has a public len method, but no is_empty method`，而 CI 跑的是
    /// `clippy -- -D warnings`）。它是与 [`Self::len`] 配对存在的方法，不是死代码。
    pub fn is_empty(&self) -> bool {
        read_or_recover(&self.inner).is_empty()
    }

    /// 返回全部已注册 agent 的明细快照（按 agent_id 排序）。
    pub fn snapshot(&self) -> Vec<AgentInfo> {
        let inner = read_or_recover(&self.inner);
        let now = now_millis();
        let mut out: Vec<AgentInfo> = inner
            .iter()
            .map(|(id, e)| AgentInfo {
                agent_id: id.clone(),
                models: e.models.clone(),
                max_concurrency: e.max_concurrency,
                inflight: e.inflight.load(Ordering::Relaxed),
                last_seen_secs_ago: since_millis(e.last_seen_millis.load(Ordering::Relaxed), now)
                    / 1000,
            })
            .collect();
        out.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
        out
    }

    /// 聚合所有**健康** agent 显式声明的模型（去重、排序）。
    /// `["*"]` 不贡献条目（全匹配，但具体能跑什么只有上游知道）。
    pub fn healthy_models(&self, stale_after: Duration) -> Vec<String> {
        let inner = read_or_recover(&self.inner);
        let now = now_millis();
        let mut out: Vec<String> = inner
            .values()
            .filter(|e| is_fresh(e.last_seen_millis.load(Ordering::Relaxed), now, stale_after))
            .flat_map(|e| e.models.iter().filter(|m| m.as_str() != "*").cloned())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// 在**能服务指定模型**的健康 agent 中挑选一个并原子占用并发槽位；
    /// 返回的 [`SlotGuard`] 期间该请求计入在途数。
    ///
    /// 模型匹配语义：agent 声明的 `models` 含 `"*"`（全匹配/兜底）或含 `model`。
    /// 优先级：**精确声明该模型者优先于仅 `*` 通配者**（通配是兜底，不抢单）；
    /// 同级内按负载最轻优先，同等负载取最近心跳者（多 agent 均衡）。
    ///
    /// **生产路径走的是 [`Self::try_acquire_excluding`]**：`routing.rs` 总要把"刚失败的那条
    /// 连接"排除掉（否则重试没有意义），所以本方法在 `crates/gateway/src` 里没有调用者。
    /// 它是**单测的便利入口**（24 处调用，省掉一个 `&[]`），因此收进 `#[cfg(test)]`：
    /// 不进非测试构建，也不占 `Registry` 的公开 API（评估 §7 步骤 6 的"死 API"清理）。
    #[cfg(test)]
    pub fn try_acquire(
        &self,
        stale_after: Duration,
        model: &str,
    ) -> Result<(Entry, SlotGuard), AcquireError> {
        self.try_acquire_excluding(stale_after, model, &[])
    }

    /// 同 `try_acquire`（测试便利入口，见下），但**跳过 `exclude` 里列出的连接**（按 `stable_id`）。
    ///
    /// 用于"换一个 agent 重试"：刚失败的那条连接不该再被选中（否则重试没有意义）。
    pub fn try_acquire_excluding(
        &self,
        stale_after: Duration,
        model: &str,
        exclude: &[usize],
    ) -> Result<(Entry, SlotGuard), AcquireError> {
        let inner = read_or_recover(&self.inner);
        // 规则全在 [`pick`] 里（纯函数）：这里只负责"按序号占位、占不到就换下一个"。
        let candidates = pick(inner.values(), now_millis(), stale_after, model, exclude)?;
        for candidate in candidates {
            let entry = candidate.clone();
            // `max_concurrency == 0` = 不限：**不做上限判定**，但自增必须照做。
            // `inflight` 不只是准入闸门，它同时是另外三处的输入：开流超时的忙/死判据
            // （[`Entry::open_timeout_is_fatal`]，`0` 时以端点流额度为上限）、摘除时
            // "是否还有别人在途"（[`Registry::evict`] 的 `inflight <= 1`）、以及下面
            // `sort_by_key` 的负载排序键。
            //
            // 曾经写成 `entry.max_concurrency == 0 || …fetch_update(…)`：短路使"不增"，
            // 而 `SlotGuard::drop` 仍然"减" → `AtomicU32` 下溢回绕成 4294967295。
            // 后果是开流判据对该连接永久失效、每次摘除都白等满宽限期、这台 agent 永远排
            // 最后、`/admin/agents` 显示天文数字。回归测试：
            // `max_concurrency_zero_always_acquires_and_still_counts_inflight`。
            //
            // 用 `try_update` 而不是 `fetch_update`：后者在 nightly 1.100.0 起被标记为
            // `deprecated: renamed to try_update for consistency`（纯改名，签名与返回值
            // 语义一致），`try_update` 在 stable 1.97.1 就有（见 `TODO.md` 的那条）。
            let acquired = if entry.max_concurrency == 0 {
                let _ = entry.inflight.fetch_add(1, Ordering::Relaxed);
                true
            } else {
                entry
                    .inflight
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                        (n < entry.max_concurrency).then_some(n + 1)
                    })
                    .is_ok()
            };
            if acquired {
                let guard = SlotGuard(entry.inflight.clone());
                return Ok((entry, guard));
            }
        }
        Err(AcquireError::AtCapacity)
    }
}

/// 摘除后的收尾方式。存在的意义有二：让**注册表内部与测试**能区分"立刻关闭"与"等在途收尾"，
/// 以及把"为什么不能立刻关"这件事写进类型里（见 [`Registry::evict`]）。
///
/// **内部类型**：对外只暴露 [`Disposition`]（"忙还是死"）。调用方今天没有任何一处需要知道
/// "这次是延迟关闭还是立刻关闭"——把它摆到公共接口上只会是没人消费的宽度。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvictOutcome {
    /// 连续超时未达阈值：条目保留，只累计计数。
    BelowThreshold { consecutive: u32 },
    /// 已摘除且连接已立即关闭（没有别的在途请求会被牵连）。
    RemovedClosed,
    /// 已摘除，连接会在在途请求收尾后（或超过宽限期）关闭。
    RemovedClosedLater { inflight: u32 },
    /// 条目已不存在（被别人摘掉，或已被新连接替换）。
    NotFound,
}

/// 拒绝请求时的注册表诊断快照（仅日志/指标用）。
#[derive(Debug, Clone, Copy, Default)]
pub struct RegistryStatus {
    /// 注册表条目数（含失联但连接未关的）。
    pub registered: usize,
    /// 心跳未过期、真正可路由的条目数。
    pub healthy: usize,
    /// 最久没有心跳的条目距今多久（None = 注册表为空）。
    pub oldest_last_seen_ago: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireError {
    /// 没有任何健康 agent。
    NoAgent,
    /// 有健康 agent，但没有任何一个能服务请求的模型。
    NoModel,
    /// agent 并发已满。
    AtCapacity,
}

/// Drop 时自动归还并发槽位。
pub struct SlotGuard(Arc<AtomicU32>);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    /// 摘除宽限：单测不关心具体时长（那由 `Options::evict_close_grace` 决定，默认 15s），
    /// 给一个固定值即可。
    const GRACE: Duration = Duration::from_secs(5);

    /// 建一对本地 s2n-quic 端点，返回**客户端连接句柄**（无 mTLS，只为构造 Handle）。
    ///
    /// 返回 `Handle` 而不是 `Connection`，因为注册表里存的就是 Handle（`Entry.conn`）：
    /// Handle 是 `#[derive(Clone, Debug)]`（s2n-quic/src/connection/handle.rs:431），
    /// 既能进 HashMap 也能被 `try_acquire` clone 出来；而 `Connection` 没有 Clone。
    ///
    /// 返回后端点随作用域结束 drop、连接随之关闭，但测试只读 `id()` 与 `inflight`：
    /// `Handle::id()` 是无锁的字段读取、也不返回 Result
    /// （s2n-quic-transport/src/connection/connection_container.rs:319-321），
    /// 所以连接死掉之后读 id 依然有效——注册表测试不依赖连接可用性。
    async fn test_connection() -> s2n_quic::connection::Handle {
        // 本测试直接构建 rustls 配置（绕过 tls 构造函数）→ 自己确保 provider 已装。
        proto::crypto::provider();

        // 服务端：自签证书；ALPN 两端必须一致，否则握手协商不上
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

        let mut stls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        stls.alpn_protocols = vec![proto::ALPN.to_vec()];

        let mut server = s2n_quic::Server::builder()
            .with_tls(s2n_quic::provider::tls::rustls::Server::from(Arc::new(
                stls,
            )))
            .unwrap()
            .with_io("127.0.0.1:0")
            .unwrap()
            .start()
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        // 必须驱动服务端 accept，否则 QUIC 握手永远无法完成；
        // 握完把两半句柄挂在 pending 上——返回会 drop 句柄、立刻关掉连接。
        tokio::spawn(async move {
            if let Some(conn) = server.accept().await {
                let (_handle, _acceptor) = conn.split();
                std::future::pending::<()>().await;
            }
        });

        // 客户端：信任自签证书（无 mTLS），ALPN 与服务端一致
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let mut ctls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        ctls.alpn_protocols = vec![proto::ALPN.to_vec()];

        let client = s2n_quic::Client::builder()
            .with_tls(s2n_quic::provider::tls::rustls::Client::from(Arc::new(
                ctls,
            )))
            .unwrap()
            .with_io("0.0.0.0:0")
            .unwrap()
            .start()
            .unwrap();

        let conn = client
            .connect(s2n_quic::client::Connect::new(server_addr).with_server_name("localhost"))
            .await
            .unwrap();
        let (handle, _acceptor) = conn.split();
        handle
    }

    /// 规格（评估 §7 步骤 6 的结转项 A / registry 评估 M2）：**表锁中毒后注册与选路
    /// 不能全挂**。
    ///
    /// 表只是内存映射，守卫内 panic 不会写坏它；而 `.read().unwrap()` 会把一次 panic
    /// 放大成"之后每个请求都无法选路"——进程活着、指标还在跑，但全站 503。
    #[tokio::test]
    async fn a_poisoned_registry_lock_does_not_take_routing_down() {
        let reg = Registry::default();
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = reg.inner.write().unwrap();
            panic!("poison the registry table");
        }));
        assert!(poisoned.is_err(), "前提：panic 发生了");
        assert!(reg.inner.is_poisoned(), "前提：锁中毒了");

        let conn = test_connection().await;
        reg.register("home-1".into(), vec!["m".into()], 2, conn);
        assert_eq!(reg.len(), 1, "中毒后仍应能注册");
        let (_entry, _slot) = reg
            .try_acquire(Duration::from_secs(10), "m")
            .expect("中毒后仍应能选路");
    }

    /// 规格（评估 §8 passB）：选路规则的**次序**——精确声明 > `*` 通配，同级负载轻者优先；
    /// 排除/过期各自把候选滤空时要给出正确的那一种错误。
    ///
    /// 规则现在是纯函数 [`pick`]，所以这条测试直接用条目断言，不必再绕 `try_acquire` 的占位副作用
    /// （要造的负载直接用条目上的原子量写，测试与 `Entry` 同模块）。
    #[tokio::test]
    async fn pick_orders_exact_over_wildcard_then_lightest() {
        let reg = Registry::default();
        let stale = Duration::from_secs(10);
        reg.register("wild".into(), vec!["*".into()], 8, test_connection().await);
        let exact = reg.register("exact".into(), vec!["m".into()], 8, test_connection().await);
        let busy = reg.register(
            "exact-busy".into(),
            vec!["m".into()],
            8,
            test_connection().await,
        );

        // 直接给"忙"那条写负载：两条精确里它更重，所以应排在 exact 之后
        let inner = reg.inner.read().unwrap();
        inner
            .values()
            .find(|e| e.stable_id == busy)
            .unwrap()
            .inflight
            .store(2, Ordering::Relaxed);

        let ordered: Vec<&str> = pick(inner.values(), now_millis(), stale, "m", &[])
            .unwrap()
            .iter()
            .map(|e| e.agent_id.as_str())
            .collect();
        assert_eq!(
            ordered,
            vec!["exact", "exact-busy", "wild"],
            "精确声明必须排在通配之前，同级负载轻者优先；实际 {ordered:?}"
        );

        // 排掉两条精确的 → 只剩通配
        let only_wild = pick(inner.values(), now_millis(), stale, "m", &[exact, busy]).unwrap();
        assert_eq!(
            only_wild
                .iter()
                .map(|e| e.agent_id.as_str())
                .collect::<Vec<_>>(),
            vec!["wild"]
        );

        // 全部过期 → NoAgent（没人可用）
        assert!(matches!(
            pick(inner.values(), now_millis(), Duration::ZERO, "m", &[]),
            Err(AcquireError::NoAgent)
        ));
    }

    /// 规格：**有人但没有一个声明这个模型** → `NoModel`（调用方据此回 404/400 而不是 503）。
    ///
    /// 单独一条测试是刻意的：`NoModel` 需要一份**没有 `*` 通配者**的表（通配者在，任何模型
    /// 都能被服务），而 `pick` 的读锁不能跨 `await`（clippy `await_holding_lock`），
    /// 混在选路次序那条测试里会既难读又踩 lint。
    #[tokio::test]
    async fn pick_reports_no_model_when_none_declares_it() {
        let reg = Registry::default();
        reg.register(
            "only-m".into(),
            vec!["m".into()],
            8,
            test_connection().await,
        );
        let inner = reg.inner.read().unwrap();
        assert!(matches!(
            pick(
                inner.values(),
                now_millis(),
                Duration::from_secs(10),
                "other",
                &[]
            ),
            Err(AcquireError::NoModel)
        ));
    }

    #[tokio::test]
    async fn register_duplicate_replaces_and_len() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let id1 = reg.register("home-1".into(), vec!["m".into()], 2, c1.clone());
        assert_eq!(reg.len(), 1);
        // 同名重复注册：旧连接被关闭，条目替换为新连接，长度仍为 1
        let c2 = test_connection().await;
        let id2 = reg.register("home-1".into(), vec!["m".into()], 2, c2.clone());
        assert_eq!(reg.len(), 1);
        let entry = reg.inner.read().unwrap().get("home-1").cloned().unwrap();
        assert_ne!(id1, id2, "每次注册都必须拿到新的 stable_id");
        assert_eq!(entry.stable_id, id2, "条目应属于后注册的那条连接");
    }

    #[tokio::test]
    async fn remove_if_same_guards_stable_id() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        let id1 = reg.register("x".into(), vec![], 4, c1.clone());
        let id2 = reg.register("x".into(), vec![], 4, c2.clone()); // 条目换成 c2，c1 被关
                                                                   // 用旧连接的 stable_id 移除 → 不删除（条目现在属于 c2）
        reg.remove_if_same("x", id1);
        assert_eq!(reg.len(), 1);
        // 用当前连接的 stable_id 移除 → 删除
        reg.remove_if_same("x", id2);
        assert_eq!(reg.len(), 0);
        // 对不存在的 agent 移除 → 无害
        reg.remove_if_same("ghost", id2);
    }

    /// 契约：**摘除时若还有别的在途请求，不得立刻关闭连接**。
    ///
    /// 那些请求已经把请求帧完整送达 agent、模型正在生成——它们不满足"建立阶段失败"
    /// 的重试条件，被打断就是纯损失（客户花了算力还拿不到结果）。所以摘除只做
    /// "移出路由"，连接等 drain 完（或过宽限期）再关。
    ///
    /// 反过来，若只剩当前这一个失败请求占槽位，立刻关闭是安全的——而且要立刻关，
    /// 好让 agent 察觉并重连，别变回僵尸。
    #[tokio::test]
    async fn eviction_defers_close_while_other_requests_are_in_flight() {
        let stale = Duration::from_secs(10);

        // 情形一：还有别的在途请求（这里手工把 inflight 顶到 3）
        let reg = Registry::default();
        let conn = test_connection().await;
        let id = reg.register("busy".into(), vec!["*".into()], 8, conn.clone());
        let (_e, g1) = reg.try_acquire(stale, "m").unwrap();
        let (_e2, g2) = reg.try_acquire(stale, "m").unwrap();
        let (_e3, g3) = reg.try_acquire(stale, "m").unwrap();
        assert_eq!(
            reg.evict(id, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::BelowThreshold { consecutive: 1 }
        );
        assert_eq!(
            reg.evict(id, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::BelowThreshold { consecutive: 2 }
        );
        match reg.evict(id, EvictCause::OpenTimeout, GRACE) {
            EvictOutcome::RemovedClosedLater { inflight } => {
                assert!(inflight >= 3, "应报出当时的在途数，实际 {inflight}")
            }
            other => panic!("还有在途请求时不应立即关闭连接，实际 {other:?}"),
        }
        assert_eq!(reg.len(), 0, "无论是否延迟关闭，条目都必须先移出路由");
        drop((g1, g2, g3));

        // 情形二：只剩当前请求 → 立即关闭
        let reg2 = Registry::default();
        let conn2 = test_connection().await;
        let id2 = reg2.register("idle".into(), vec!["*".into()], 8, conn2.clone());
        let (_e4, _g4) = reg2.try_acquire(stale, "m").unwrap();
        assert!(matches!(
            reg2.evict(id2, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::BelowThreshold { .. }
        ));
        assert!(matches!(
            reg2.evict(id2, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::BelowThreshold { .. }
        ));
        assert_eq!(
            reg2.evict(id2, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::RemovedClosed
        );
    }

    /// 契约：**换 agent 重试时必须排除刚失败的那条连接**。
    ///
    /// 否则"重试"会再次选中同一条坏连接，等于没重试——这在生产表现为"重试了但还是
    /// 502"，而日志里看不出原因。
    #[tokio::test]
    async fn try_acquire_excluding_skips_the_failed_connection() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        let id1 = reg.register("a".into(), vec!["*".into()], 4, c1.clone());
        let id2 = reg.register("b".into(), vec!["*".into()], 4, c2.clone());
        let stale = Duration::from_secs(10);

        // 不排除任何连接：两次选取都会命中某个候选（不关心是哪个）
        assert!(reg.try_acquire(stale, "m").is_ok());

        // 排除 a → 只能选到 b
        let (e, _g) = reg.try_acquire_excluding(stale, "m", &[id1]).unwrap();
        assert_eq!(e.stable_id, id2, "排除 a 后应选中 b");

        // 排除 b → 只能选到 a
        let (e, _g) = reg.try_acquire_excluding(stale, "m", &[id2]).unwrap();
        assert_eq!(e.stable_id, id1, "排除 b 后应选中 a");

        // 两条都排除 → 没有候选（这正是"没有别的 agent 可重试"那条分支）
        assert!(matches!(
            reg.try_acquire_excluding(stale, "m", &[id1, id2]),
            Err(AcquireError::NoAgent)
        ));
    }

    /// 契约：**单次隧道操作超时不得摘除条目**（高并发下那是排队假象），
    /// 连续超时达阈值才摘除；任何一次成功都要清零计数。
    ///
    /// 实测背景：768 并发下第一次超时就把条目摘掉，而连接完好、agent 不知情，
    /// 于是注册表里没有它、请求全部 503（占 92.6%），agent 因为心跳仍能通而永远
    /// 不重连 —— "僵尸"态。
    #[tokio::test]
    async fn tunnel_timeouts_evict_only_after_consecutive_failures() {
        let reg = Registry::default();
        let conn = test_connection().await;
        let id = reg.register("t".into(), vec!["*".into()], 4, conn.clone());

        // 前两次超时：条目保留
        assert!(matches!(
            reg.evict(id, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::BelowThreshold { consecutive: 1 }
        ));
        assert_eq!(reg.len(), 1);
        assert!(matches!(
            reg.evict(id, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::BelowThreshold { consecutive: 2 }
        ));
        assert_eq!(reg.len(), 1);
        // 中途一次成功 → 计数清零，重新从头累计
        reg.note_tunnel_op_ok(id);
        assert!(matches!(
            reg.evict(id, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::BelowThreshold { consecutive: 1 }
        ));
        assert_eq!(reg.len(), 1);
        // 再来两次（累计到 3）→ 摘除；此时只有本请求占槽位 → 立即关闭
        assert!(matches!(
            reg.evict(id, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::BelowThreshold { .. }
        ));
        assert!(matches!(
            reg.evict(id, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::RemovedClosed
        ));
        assert_eq!(reg.len(), 0);
        // 已摘除后再调用：无害
        assert_eq!(
            reg.evict(id, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::NotFound
        );
    }

    /// 规格：**每一种失败原因各有自己的"连续"计数**。
    ///
    /// 计数混在一起时，三种**不同**的轻微失败会凑满同一个阈值，把一条其实健康的连接摘掉；
    /// 而且任何一种失败达到阈值后，另一种失败的"连续"语义就被无声地改写了。云端实测里
    /// "开流超时"与"响应头超时"是两条独立的事故线（`routing.rs:122-125`、
    /// `head_timeout.rs:3-9`），它们的阈值不能互相充值。
    #[tokio::test]
    async fn strike_counters_are_independent_per_cause() {
        let reg = Registry::default();
        let conn = test_connection().await;
        let id = reg.register("t".into(), vec!["*".into()], 4, conn.clone());

        // 两种失败各记两次：各自都还差一次，谁都不该摘除
        for expected in 1..=2 {
            assert!(
                matches!(
                    reg.evict(id, EvictCause::OpenTimeout, GRACE),
                    EvictOutcome::BelowThreshold { consecutive } if consecutive == expected
                ),
                "开流超时应独立计数到 {expected}"
            );
            assert!(
                matches!(
                    reg.evict(id, EvictCause::HeadTimeout, GRACE),
                    EvictOutcome::BelowThreshold { consecutive } if consecutive == expected
                ),
                "响应头超时应独立计数到 {expected}"
            );
        }
        assert_eq!(
            reg.len(),
            1,
            "2 次开流 + 2 次响应头 = 4 次失败，但没有任何**一种**达到阈值"
        );

        // 第三种原因也从 1 开始，不受前两种影响
        assert!(matches!(
            reg.evict(id, EvictCause::TunnelWriteFailed, GRACE),
            EvictOutcome::BelowThreshold { consecutive: 1 }
        ));

        // 只有某一种真正连续到阈值才摘除
        assert_eq!(
            reg.evict(id, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::RemovedClosed
        );
        assert_eq!(reg.len(), 0);
    }

    /// 可观测性契约：**注册条目数**与**可路由数**必须能分开看。
    ///
    /// 失联 agent 的条目要等连接真正关闭才摘除，所以 `len()` 会把它算作"在线"，
    /// 而 `try_acquire` 会把它过滤掉。两者混为一谈时，"所有请求 503"会被误读成
    /// "agent 掉了"——线上排查正是卡在这里（/metrics 显示 2 个 agent，实际全部 stale）。
    #[tokio::test]
    async fn healthy_count_separates_registered_from_routable() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        reg.register("fresh".into(), vec!["*".into()], 4, c1.clone());
        reg.register("stale".into(), vec!["*".into()], 4, c2.clone());

        let stale_after = Duration::from_millis(30);
        tokio::time::sleep(Duration::from_millis(50)).await;
        // 两条都过期
        assert_eq!(reg.len(), 2, "条目仍在注册表里（连接没关）");
        assert_eq!(reg.healthy_count(stale_after), 0, "但没有一条可路由");
        let st = reg.status(stale_after);
        assert_eq!((st.registered, st.healthy), (2, 0));
        assert!(st.oldest_last_seen_ago.unwrap() >= Duration::from_millis(50));
        assert!(matches!(
            reg.try_acquire(stale_after, "qwen2.5"),
            Err(AcquireError::NoAgent)
        ));

        // 一条心跳恢复 → 只有它可路由
        reg.heartbeat("fresh");
        assert_eq!(reg.len(), 2);
        assert_eq!(reg.healthy_count(stale_after), 1);
        assert_eq!(reg.status(stale_after).healthy, 1);
        assert!(reg.try_acquire(stale_after, "qwen2.5").is_ok());

        // 空注册表：两个数都是 0，且没有 last_seen 可报
        let empty = Registry::default();
        assert_eq!(empty.healthy_count(stale_after), 0);
        assert_eq!(empty.status(stale_after).registered, 0);
        assert!(empty.status(stale_after).oldest_last_seen_ago.is_none());
    }

    #[tokio::test]
    async fn heartbeat_refreshes_stale_entry() {
        let reg = Registry::default();
        let conn = test_connection().await;
        reg.register("h".into(), vec!["*".into()], 4, conn.clone());
        // 30ms 后仍按 10ms 判定失联
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(matches!(
            reg.try_acquire(Duration::from_millis(10), "qwen2.5"),
            Err(AcquireError::NoAgent)
        ));
        // 心跳刷新 last_seen → 恢复可用
        reg.heartbeat("h");
        assert!(reg
            .try_acquire(Duration::from_millis(100), "qwen2.5")
            .is_ok());
        // 对不存在的 agent 心跳 → 无害
        reg.heartbeat("ghost");
    }

    #[tokio::test]
    async fn try_acquire_spreads_load_and_capacity() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        reg.register("a".into(), vec!["*".into()], 1, c1.clone());
        reg.register("b".into(), vec!["*".into()], 1, c2.clone());

        // 两个容量各 1 的 agent：连续两个请求应命中不同 agent
        let (e1, s1) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        let (e2, s2) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        assert_ne!(e1.stable_id, e2.stable_id);
        // 全满 → AtCapacity
        assert!(matches!(
            reg.try_acquire(Duration::from_secs(10), "qwen2.5"),
            Err(AcquireError::AtCapacity)
        ));
        drop(s1);
        drop(s2);
        // 槽位释放后恢复
        assert!(reg.try_acquire(Duration::from_secs(10), "qwen2.5").is_ok());
    }

    /// 规格：`max_concurrency == 0` = 不限（永远拿得到槽位），但**计数仍然必须真实**。
    ///
    /// `0` 只关掉"准入上限"这一件事；`inflight` 同时还是另外三处的输入：
    /// 开流超时的忙/死（[`Entry::open_timeout_is_fatal`]）、摘除时"是否还有别人在途"
    /// （[`Registry::evict`] 的 `inflight <= 1`）、以及负载排序（`try_acquire_excluding`
    /// 的 `sort_by_key`）。只减不加会让 `AtomicU32` **下溢回绕成 4294967295**：开流判据
    /// 永久失效、每次摘除都白等满宽限期、这台 agent 永远排最后、`/admin/agents` 显示天文数字
    /// （已记录：`docs/PROJECT_SCAN.md` P1-3）。
    #[tokio::test]
    async fn max_concurrency_zero_always_acquires_and_still_counts_inflight() {
        let reg = Registry::default();
        let conn = test_connection().await;
        reg.register("z".into(), vec!["*".into()], 0, conn.clone()); // 0 = 不限

        // ① 只减不加 → 下溢：拿 5 次再**全部归还**，计数必须回到 0。
        //    在未修的实现里这里会读到 4294967295（`AtomicU32` 回绕），正是 P1-3 记录的形态。
        {
            let mut slots = Vec::new();
            for _ in 0..5 {
                let (_entry, slot) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
                slots.push(slot);
            }
            drop(slots);
        }
        assert_eq!(
            reg.snapshot()[0].inflight,
            0,
            "拿 5 次再全部归还后必须回到 0；只减不加会下溢成 4294967295"
        );

        // ② 而且过程里必须如实累加：不限并发不等于不计数
        let mut slots = Vec::new();
        for expected in 1..=5u32 {
            let (entry, slot) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
            slots.push(slot);
            assert_eq!(
                entry.inflight.load(Ordering::Relaxed),
                expected,
                "不限并发也必须如实计数：开流判据、摘除判据、负载排序都读这个数"
            );
        }
        assert_eq!(reg.snapshot()[0].inflight, 5, "运维看到的在途数同样要真实");

        drop(slots);
        assert_eq!(
            reg.snapshot()[0].inflight,
            0,
            "最后一次释放后必须回到 0；下溢会变成 4294967295"
        );
    }

    #[tokio::test]
    async fn try_acquire_filters_by_model() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        let c3 = test_connection().await;
        reg.register(
            "qwen-edge".into(),
            vec!["qwen2.5".into()],
            1, // 容量 1：打满后验证回落通配
            c1.clone(),
        );
        reg.register("llama-edge".into(), vec!["llama3".into()], 4, c2.clone());
        // 通配 edge：任何模型都可路由到它
        reg.register("wildcard-edge".into(), vec!["*".into()], 4, c3.clone());

        // qwen2.5 → 精确声明的 qwen-edge 优先于仅通配的 wildcard-edge，
        // 绝不能是 llama-edge
        let (e, s) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        let id = {
            let inner = reg.inner.read().unwrap();
            inner
                .iter()
                .find(|(_, v)| v.stable_id == e.stable_id)
                .map(|(id, _)| id.clone())
                .unwrap()
        };
        assert_eq!(id, "qwen-edge", "exact model match must win over wildcard");
        drop(s);

        // llama3 → 精确声明的 llama-edge 优先
        let (e, s) = reg.try_acquire(Duration::from_secs(10), "llama3").unwrap();
        let id = {
            let inner = reg.inner.read().unwrap();
            inner
                .iter()
                .find(|(_, v)| v.stable_id == e.stable_id)
                .map(|(id, _)| id.clone())
                .unwrap()
        };
        assert_eq!(id, "llama-edge", "exact model match must win over wildcard");
        drop(s);

        // 精确 edge 容量打满后，请求回落到通配 edge
        let (e1, s1) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        let (e2, s2) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        assert_ne!(
            e1.stable_id, e2.stable_id,
            "second qwen2.5 request should fall back to wildcard edge"
        );
        drop(s1);
        drop(s2);
    }

    #[tokio::test]
    async fn try_acquire_returns_no_model_when_none_match() {
        let reg = Registry::default();
        // 无通配 agent：所有健康 agent 都无法服务 mistral-7b
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        reg.register("qwen-edge".into(), vec!["qwen2.5".into()], 4, c1.clone());
        reg.register("llama-edge".into(), vec!["llama3".into()], 4, c2.clone());
        assert!(matches!(
            reg.try_acquire(Duration::from_secs(10), "mistral-7b"),
            Err(AcquireError::NoModel)
        ));
    }

    #[tokio::test]
    async fn healthy_models_aggregates_and_excludes_wildcard() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        reg.register(
            "edge-a".into(),
            vec!["qwen2.5".into(), "llama3".into()],
            4,
            c1.clone(),
        );
        reg.register(
            "edge-b".into(),
            vec!["llama3".into(), "*".into()],
            4,
            c2.clone(),
        );
        // 去重、排序、排除 "*"
        assert_eq!(
            reg.healthy_models(Duration::from_secs(10)),
            vec!["llama3", "qwen2.5"]
        );
        // 失联 agent 的模型不聚合
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(reg.healthy_models(Duration::from_millis(10)).is_empty());
    }

    #[tokio::test]
    async fn snapshot_reports_agent_details() {
        let reg = Registry::default();
        let conn = test_connection().await;
        reg.register(
            "home-1".into(),
            vec!["qwen2.5".into(), "llama3".into()],
            2,
            conn.clone(),
        );
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].agent_id, "home-1");
        assert_eq!(
            snap[0].models,
            vec!["qwen2.5".to_string(), "llama3".to_string()]
        );
        assert_eq!(snap[0].max_concurrency, 2);
        assert_eq!(snap[0].inflight, 0);
        assert!(snap[0].last_seen_secs_ago < 1, "freshly registered agent");

        // 按 agent_id 排序、空注册表为空
        let conn2 = test_connection().await;
        reg.register("agent-a".into(), vec![], 4, conn2.clone());
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].agent_id, "agent-a");
        assert_eq!(snap[1].agent_id, "home-1");
        assert!(Registry::default().snapshot().is_empty());
    }

    /// 规格：**"开流超时"不等于"连接已死"**。
    ///
    /// `open_bidirectional_stream()` 在连接级流额度排满时会排队等回收，所以超时有两种
    /// 成因：对端死了（该摘除），或对端忙、在途已经顶到承载上限（正常背压，摘除就是
    /// 把局部过载放大成全站不可用）。
    ///
    /// 云端实测的代价（2026-09-17，4 agent、768 并发）：一律摘除 → `tunnel open timed out`
    /// 9345 次、健康 agent 被关掉重连 → 单次 30s 压测 `registry-empty` +6835 → 全量 503。
    #[tokio::test]
    async fn open_timeout_is_fatal_only_when_the_connection_is_not_at_capacity() {
        let reg = Registry::default();
        let conn = test_connection().await;
        reg.register("busy".into(), vec!["*".into()], 1, conn.clone());
        let (entry, guard) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();

        // 在途 1 > 0：没到这条连接的上限（max_concurrency = 1 时 1 就是满）
        entry.inflight.store(0, Ordering::Relaxed);
        assert!(
            entry.open_timeout_is_fatal(1024),
            "没有任何在途请求却开不出流 = 连接确实坏了，必须摘除"
        );

        // 在途 1 = max_concurrency：额度排满后的排队超时是背压，不是死亡
        entry.inflight.store(1, Ordering::Relaxed);
        assert!(
            !entry.open_timeout_is_fatal(1024),
            "在途已达声明的 max_concurrency → 超时是排队等额度，不能摘除健康连接"
        );
        drop(guard);

        // 声明不限并发（max_concurrency = 0）时，上限就是端点流额度
        let conn2 = test_connection().await;
        reg.register("unbounded".into(), vec!["*".into()], 0, conn2);
        let (entry2, _g2) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        assert_eq!(entry2.agent_id, "unbounded");
        entry2.inflight.store(3, Ordering::Relaxed);
        assert!(
            entry2.open_timeout_is_fatal(4),
            "在途 3 < 额度 4 → 还有额度却开不出流 = 坏连接"
        );
        entry2.inflight.store(4, Ordering::Relaxed);
        assert!(
            !entry2.open_timeout_is_fatal(4),
            "在途 = 额度 → 超时是额度排队，不是死亡"
        );

        // 配置不一致（agent 声明 256 > 端点额度 100）：以更小的那个为准，
        // 否则"忙"会被判成"死"，又回到摘除健康 agent 的老路。
        let conn3 = test_connection().await;
        reg.register("over-declared".into(), vec!["*".into()], 256, conn3);
        let (entry3, _g3) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        assert_eq!(entry3.agent_id, "over-declared");
        entry3.inflight.store(99, Ordering::Relaxed);
        assert!(entry3.open_timeout_is_fatal(100));
        entry3.inflight.store(100, Ordering::Relaxed);
        assert!(
            !entry3.open_timeout_is_fatal(100),
            "额度先于容量耗尽时，超时同样是背压（这正是要告警的配置不一致）"
        );
    }
    /// 规格：**响应头超时要能区分"最近还在干活"与"真的没有了"**（判据第一层）。
    ///
    /// 这条判据是"链路被堵住 → 健康 agent 被摘除 → 全量 503"的唯一出口：窗口内有过成功响应头
    /// 就只是慢（不摘除），窗口内一次都没有才算死。窗口本身由 `4 × head_timeout` 派生（见 `state.rs`）。
    /// 第二层（对端还活着时的延长）在下面那条用例里。
    ///
    /// ⚠️ 时间基准 `epoch()` 是**首次使用时才创建**的，所以测试进程刚起来时 `now_millis()`
    /// 接近 0——不能用"把时间戳减去 10 秒"来伪造沉默（会被 saturating 压到 0）。这里改为
    /// 真实小睡几毫秒、再把窗口压到 1ms 来跨过边界，避免依赖时间基准的起点。
    #[tokio::test]
    async fn head_timeout_is_fatal_only_after_a_window_of_total_silence() {
        let reg = Registry::default();
        let conn = test_connection().await;
        reg.register("alive".into(), vec!["*".into()], 4, conn);
        let (entry, _guard) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        // 本用例只考第一层：`stuck_after` 给 0（对端活着也延长不了），对端也**从未心跳**。
        let only_window = |window: Duration| HeadSilence {
            window,
            peer_alive_window: Duration::from_secs(15),
            stuck_after: Duration::ZERO,
        };

        // ① 刚注册但**从未回过响应头** → 没有"只是慢"的证据 → 判死
        //    （否则注册后从不回包的坏隧道会被宽限一个窗口才摘除）
        assert!(
            entry.head_timeout_is_fatal(only_window(Duration::from_secs(60))),
            "从未收到过响应头时不该被当成「只是慢」"
        );

        // ② 收到过响应头 → 仍在窗口内 → 只是慢（这条是判据最该避免的误判）
        reg.note_tunnel_op_ok(entry.stable_id());
        assert!(
            !entry.head_timeout_is_fatal(only_window(Duration::from_secs(60))),
            "刚刚回过响应头的隧道被判定为死"
        );

        // ③ 沉默 50ms 之后：窗口 1ms → 判死；窗口 60s → 仍只是慢。
        //    同一次沉默、只改窗口就翻转结论，说明判据确实由"沉默时长 vs 窗口"决定。
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            entry.head_timeout_is_fatal(only_window(Duration::from_millis(1))),
            "沉默 50ms > 窗口 1ms → 必须判死（否则坏连接永远摘不掉）"
        );
        assert!(
            !entry.head_timeout_is_fatal(only_window(Duration::from_secs(60))),
            "沉默 50ms < 窗口 60s → 只是慢，不能判死"
        );

        // ④ 期间只要再成功收到一次响应头，窗口重新开始计时
        reg.note_tunnel_op_ok(entry.stable_id());
        assert!(
            !entry.head_timeout_is_fatal(only_window(Duration::from_millis(1))),
            "刚回过响应头就该立刻回到「只是慢」，否则连续计数的语义不成立"
        );
    }

    /// 规格（判据第二层，评估 §5 H2）：**对端还在说话时，窗口过了也不判死**——
    /// 均匀慢流量（所有请求都慢过 `head_timeout`）不能摘掉一条活着的 agent。
    ///
    /// 为什么必须单独钉：`last_head_ok` 的唯一刷新点就是成功响应头，所以"所有请求都慢"时
    /// 没有任何一次成功能刷新它，第一层必然走到"判死"。这一层用"收到过心跳"作为对端活着的
    /// 证据把容忍度延长到 `stuck_after`（一条请求的寿命）。
    #[tokio::test]
    async fn head_silence_is_tolerated_while_the_peer_keeps_heartbeating() {
        let reg = Registry::default();
        let conn = test_connection().await;
        reg.register("slow-but-alive".into(), vec!["*".into()], 4, conn);
        let (entry, _guard) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();

        // 先让它"回过一次响应头"，然后沉默 50ms（把窗口压到 1ms 来跨过边界，同上面的技巧）。
        reg.note_tunnel_op_ok(entry.stable_id());
        tokio::time::sleep(Duration::from_millis(50)).await;

        // ① 对端**从未心跳** → 只有第一层 → 判死（这就是既有 e2e 钉的"裸 agent"形态）
        assert!(
            entry.head_timeout_is_fatal(HeadSilence {
                window: Duration::from_millis(1),
                peer_alive_window: Duration::from_secs(15),
                stuck_after: Duration::from_secs(120),
            }),
            "对端从未说过话时不该获得延长"
        );

        // ② 收到心跳 → 对端还活着 → 沉默没超过 stuck_after → **不判死**（H2 要的就是这一格）
        reg.heartbeat("slow-but-alive");
        let alive = HeadSilence {
            window: Duration::from_millis(1),
            peer_alive_window: Duration::from_secs(15),
            stuck_after: Duration::from_secs(120),
        };
        assert!(
            !entry.head_timeout_is_fatal(alive),
            "对端还在心跳、沉默也远没到一条请求的寿命，不该判死（均匀慢流量误摘）"
        );

        // ③ 但静默超过 stuck_after 就判死：心跳正常、数据面却长时间一声不响 = 卡死，
        //    不能让它永远留在路由里（否则每个请求都白等一次 head_timeout）。
        assert!(
            entry.head_timeout_is_fatal(HeadSilence {
                stuck_after: Duration::from_millis(1),
                ..alive
            }),
            "沉默超过一条请求的寿命后必须判死，否则数据面卡死的连接永远摘不掉"
        );

        // ④ 心跳也停了 → 回到"只看窗口"。
        //    用 `peer_alive_window = 0` 表示"心跳一律不算新鲜"，比"压到 1ms 再睡几毫秒"确定：
        //    刚发出的心跳在同一个毫秒里 `since == 0`，1ms 的窗口仍然算新鲜（这里踩过一次）。
        assert!(
            entry.head_timeout_is_fatal(HeadSilence {
                peer_alive_window: Duration::ZERO,
                ..alive
            }),
            "心跳过期后不该再享有延长"
        );
    }
}
