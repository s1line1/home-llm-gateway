//! 摘除一条连接之后：**什么时候真正关掉它**。
//!
//! 这是 `Registry::evict` 的后半段。移出路由那一步留在 `registry` 里（那要对 map 加写锁），
//! 本模块只管"这条已经被判死的连接还能活多久"，以及那个期限到了以后的动作。
//!
//! **为什么不能立刻关**：这一条连接上往往还有别的在途请求，它们在 `inflight` 里有两类，
//! 两类都不该被连带打断——
//!   · 已经把请求完整送达 agent、模型正在生成的：早过了响应头那一关，不属于"建立阶段可重试"
//!     的范围，打断就是纯损失（客户白花钱，还拿不到结果）；
//!   · **还在等响应头的**：槽位从 `try_acquire` 取得、一直持有到响应结束，所以它们也在
//!     `inflight` 里；它们并没有出错，只是还没轮到回包。
//!
//! **为什么必须有截止时刻**：连接迟迟不关，agent 侧就看不出自己被摘除了——心跳照通、连接照开，
//! 而请求永远路由不到它（"自认为在线的僵尸"）。所以宽限期是"别打断在途"与"别造出僵尸"
//! 之间的那个上界。它的值由 `Options::evict_close_grace` 注入；**默认 5s 短于 `head_timeout`
//! (15s)、更远短于 `request_timeout`(120s)，这是一个已知取舍**，不是笔误：保住多久＝宽限期
//! 有多长。两个 e2e（`evict_close.rs` 里的 A/B 组）把这条契约钉在测试里。
//!
//! **本模块的任务为什么不登记进 `Gateway::tasks`**（评估 H8，这里是明确取舍而非遗漏）：
//! 登记要把网关的任务集反向注入注册表，而收益接近于零——宽限期最长只有几秒，
//! 网关关闭时进程随后就退出，连接随进程一起消失。真需要时扩展点就在这里：整个仓库只有
//! 本模块 `spawn` 这个任务。

use std::{
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use tracing::warn;

/// 等在途请求收尾（或超过 `grace`）再关闭连接。
///
/// 参数**恰好**是它需要的那三样：连接句柄、在途计数、日志用的 agent_id。
/// 故意不接收 `registry::Entry`：`Entry` 的字段是私有的（见它的文档），
/// 为一个模块开后门等于把"关掉任意一条连接"的能力扩散出去。
pub(crate) fn defer_close(
    conn: s2n_quic::connection::Handle,
    inflight: Arc<AtomicU32>,
    agent_id: &str,
    grace: Duration,
) {
    let agent_id = agent_id.to_string();
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + grace;
        loop {
            if inflight.load(Ordering::Relaxed) == 0 {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    agent = %agent_id,
                    inflight = inflight.load(Ordering::Relaxed),
                    "evicted connection still had in-flight requests at the grace deadline; closing anyway"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        conn.close(0u32.into());
    });
}
