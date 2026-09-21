//! 隧道帧 IO：打开流 / 写帧 / 发取消帧，**每个都带超时**。
//!
//! 三个超时都不是可选项：健康隧道上这些操作是微秒到毫秒级（本机实测端到端固定开销
//! ≈56ms），一旦超时就只有一个解释——这条连接坏了。没有它们，隧道坏掉时这些 await 可能
//! 长时间不返回，请求会一直占着连接、并发槽位与缓冲区，而客户端早已断开也发现不了。
//!
//! 与 `registry` 的分工：**判定**"这次超时到底是忙还是死"
//! （[`crate::registry::Entry::open_timeout_is_fatal`]）是注册表的策略；本模块只负责
//! "带超时地做这件事"，并把失败如实报告成**两类**（[`OpenFailure`] / [`WriteFailure`]）——
//! "超时"与"直接错误"处置完全不同，绝不能在超时那一层就合并。
//!
//! 可见性是 `pub(super)` 而不是 `pub(crate)`：只有父模块 `proxy` 用它。

use std::time::Duration;

use proto::{io::write_frame, Frame};
use tracing::error;

/// 打开一条隧道流失败的两类原因。**必须分开**：它们的处置完全不同
/// （超时可能是"忙"，错误一定是"坏"）。
pub(super) enum OpenFailure {
    /// 在 `op_timeout` 内没能开出流。可能是对端死了，也可能只是**流额度排满在排队**
    /// ——后者由调用方用 [`crate::registry::Entry::open_timeout_is_fatal`] 判定。
    TimedOut,
    /// 开流直接返回错误：连接确已不可用。
    Failed(String),
}

impl OpenFailure {
    pub(super) fn message(&self) -> String {
        match self {
            OpenFailure::TimedOut => "tunnel open timed out".into(),
            OpenFailure::Failed(e) => e.clone(),
        }
    }
}

/// 往隧道写一个帧失败的两类原因。**必须分开**：超时是连接级背压，错误才是"连接确已不可用"。
///
/// 与 [`OpenFailure`] 的区别值得写下来：开流超时能用"在途是否已达承载上限"区分忙/死
/// （[`crate::registry::Entry::open_timeout_is_fatal`]），而**写**超时不能用同一个代理——
/// 同一条连接上的所有流共享发送缓冲与 UDP socket，一条流就能把缓冲填满。所以写超时一律算
/// 背压，不摘除；死亡检出交给"写直接返回错误"与开流/响应头两条判据。
pub(super) enum WriteFailure {
    /// 在 `op_timeout` 内没能把帧刷出去：连接级背压，不是隧道死亡。**不得据此摘除**。
    TimedOut,
    /// 写直接返回错误：连接确已不可用。
    Failed(String),
}

impl WriteFailure {
    pub(super) fn message(&self) -> String {
        match self {
            WriteFailure::TimedOut => "tunnel write timed out".into(),
            WriteFailure::Failed(e) => e.clone(),
        }
    }

    /// 只有"写直接失败"才可能是坏隧道；超时一律算背压。
    pub(super) fn is_tunnel_broken(&self) -> bool {
        matches!(self, WriteFailure::Failed(_))
    }
}

/// 打开一条隧道流（带超时）。
///
/// **为什么必须有超时**：健康隧道这一步是毫秒级（本机实测端到端固定开销 F≈56ms），
/// 但隧道坏掉时开流/写帧可能长时间不返回——请求就一直挂在那里，占着连接、并发槽位和
/// 缓冲区，客户端早已断开也发现不了。超时即判定连接已死，交给调用方摘除条目。
///
/// 实测补充：真正长时间卡住的是**等响应头**（见 [`proxy`] 里的 `head_timeout`）；
/// s2n-quic 在连接已被判定关闭后，写会较快返回错误。两个超时都保留——两者互为兜底，
/// 且触发时都必须摘除坏连接，否则后续请求会继续选中它。
pub(super) async fn open_tunnel(
    entry: &mut crate::registry::Entry,
    op_timeout: Duration,
) -> Result<s2n_quic::stream::BidirectionalStream, OpenFailure> {
    match tokio::time::timeout(op_timeout, entry.conn.open_bidirectional_stream()).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(OpenFailure::Failed(format!("tunnel open failed: {e}"))),
        Err(_) => Err(OpenFailure::TimedOut),
    }
}

/// 往隧道写一个帧（带超时）。失败分"超时（背压）"与"直接错误（坏连接）"两类。
///
/// 一个几 KB 的帧在健康隧道上是微秒级，但**连接级背压**（同一条连接上的流共享发送缓冲与
/// UDP socket）会让写暂时刷不出去——所以超时**不能**判成"隧道已死"（见 [`WriteFailure`]）。
pub(super) async fn tunnel_write(
    send: &mut s2n_quic::stream::SendStream,
    frame: &Frame,
    op_timeout: Duration,
    request_id: u64,
    agent_id: &str,
) -> Result<(), WriteFailure> {
    match tokio::time::timeout(op_timeout, write_frame(send, frame)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(WriteFailure::Failed(format!("tunnel write failed: {e}"))),
        Err(_) => {
            error!(
                request_id,
                agent = %agent_id,
                timeout_ms = op_timeout.as_millis(),
                "tunnel write timed out; treating it as backpressure, not evicting"
            );
            Err(WriteFailure::TimedOut)
        }
    }
}

/// 尽力发一个取消帧：**失败就算了**，绝不在这里阻塞（它本身可能就是卡住的那条路）。
pub(super) async fn tunnel_cancel(
    send: &mut s2n_quic::stream::SendStream,
    request_id: u64,
    op_timeout: Duration,
) {
    let cancel = Frame::Cancel { request_id };
    let _ = tokio::time::timeout(op_timeout, write_frame(send, &cancel)).await;
}

#[cfg(test)]
mod tests {
    use super::WriteFailure;

    /// 规格：**写帧超时是背压，不是坏隧道**。
    ///
    /// 与开流超时对称（见 [`crate::registry::Entry::open_timeout_is_fatal`]）：写不出去既可能
    /// 是对端死了，也可能只是连接级背压（agent 侧发送缓冲/UDP socket 被同一条连接上的其它
    /// 流占满）。区别在于写超时这一层**没有**可靠的"忙/死"证据——在途流数在连接级背压下不是
    /// 有效代理（一条流也能把共享发送缓冲填满）——所以一律算背压、不摘除；死亡检出交给
    /// "写直接返回错误"以及开流/响应头两条判据。
    #[test]
    fn write_timeout_is_backpressure_not_a_broken_tunnel() {
        assert!(
            !WriteFailure::TimedOut.is_tunnel_broken(),
            "写超时不得被当成坏隧道（否则健康但拥塞的 agent 会被摘除）"
        );
        assert!(
            WriteFailure::Failed("connection closed".into()).is_tunnel_broken(),
            "写直接返回错误才是坏隧道"
        );
    }
}
