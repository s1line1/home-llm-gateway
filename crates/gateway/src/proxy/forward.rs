//! 响应转发：把上游的帧流转成客户端的响应体，并在任一端消失时取消另一端。
//!
//! 这是整个网关并发语义最密的一段，所以它自成一格：
//!
//! - **客户端断开 / 停滞** → 向上游发 `Cancel`，别让边缘继续烧 token；
//! - **上游结束 / 断流 / 空闲超时** → 结束响应体，并结算已转发部分的用量；
//! - **agent 槽位** → `slot` 随本任务结束释放（HTTP 准入票据是另一条：它挂在响应体上）。
//!
//! **不变量（P3-3）**：本模块每一处 `send.finish()` 若是在**放弃一个还活着的请求**，它前面就必须
//! 有一次 `tunnel_cancel(...)`。不需要取消的是"请求已经结束 / 流已经不再可用"那几类：
//! `ProxyResponseEnd`（正常结束）、`UpstreamError`（agent 已回错误帧）、`UpstreamClosed`
//! （对端关了流）、`TunnelError`（读已经坏了）——**这几条是类别，不是"唯一例外"**（2026-09-23
//! 审计订正：原文只写了 `ProxyResponseEnd`，与实际三分支不符）。
//! 别把它改成"半关就等于取消"——agent 只是**兜底**把请求方向的 EOF 当取消，并且会用 warn
//! 记录那种情况（`agent/src/stream.rs` 的监听任务）。
//!
//! 三条超时语义各不相同且都不能省：`idle_timeout` 是**逐帧空闲**（SSE 长流靠"有帧就不
//! 超时"活着）、`client_stall` 是客户端**停滞**、`op_timeout` 只用于 Cancel 帧的写——
//! 最后一处尤其：隧道坏掉时连 Cancel 都可能写不出去，在那里阻塞正是"客户端已断开却
//! 发现不了"的死角。

use std::time::Duration;

use axum::body::Bytes;
use proto::{io::FrameReader, Frame};
use tokio::sync::{mpsc, watch};
use tracing::warn;

use crate::state::ShutdownPhase;

use super::tunnel::tunnel_cancel;
use super::usage::UsageCollector;

/// 往客户端方向送一块的结果。几种情况处置完全不同，必须分开。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SendOutcome {
    /// 客户端取走了。
    Delivered,
    /// 接收端已被丢弃 = 客户端断开/连接结束 → 取消上游（现状语义）。
    ClientGone,
    /// 通道满且 `stall` 内一直没人取 = 客户端**还连着但不再消费**响应体。
    ///
    /// 这一档以前不存在（`tx.send().await` 没有超时），正是"在途请求永久占住准入槽位"
    /// 的另一半原因：通道容量 32，客户端一停，发送端就在这里永久 park，
    /// 而准入票据（`Admission`）随 response body 一起挂在同一个任务上。
    Stalled,
    /// 网关进入 `Terminating`，发送被主动叫停（见 [`send_to_client_or_shutdown`]）。
    ///
    /// 与 [`SendOutcome::Stalled`] 分开：那一档要记 `client_stalls`（客户端有问题），
    /// 这一档是**我们自己在关停**，不是客户端的锅；数据也不再重要（响应体接下来会被
    /// 明确标成"不完整"）。
    ShuttingDown,
}

/// 关停时"不完整"事件的写入上限。
///
/// 比 `client_stall`（默认 60s）小得多：**正常读取**的客户端微秒级就收下了，这个上限存在的
/// 意义只是别让"不读的客户端"把关停拖住——那时任务会一直持有 agent 槽位与 QUIC 流，
/// `Gateway::shutdown` 早返回了（并集报告 H5）。
const SHUTDOWN_EVENT_WRITE_TIMEOUT: Duration = Duration::from_millis(250);

/// 响应转发结束的方式。**九个出口各自的处置不同**，以前它们只是散落的 `return`——
/// 日志能看出差别，返回值看不出来。显式化之后：调用方拿到一个可匹配的结论，
/// 而第 9 步要修的那个缺口（客户端断开却因上游静默而未察觉）就落在 `ClientGone` 上。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ForwardEnd {
    /// 上游正常结束（收到 `ProxyResponseEnd`）。
    UpstreamEnd,
    /// 上游自己报错（`Frame::Error`），已把错误送给客户端。
    UpstreamError,
    /// 上游未发 End 就关了流。
    UpstreamClosed,
    /// 隧道读失败。
    TunnelError,
    /// 逐帧空闲超时：`idle_timeout` 内上游一个帧都没发。
    IdleTimeout,
    /// 客户端断开（通道接收端被丢弃）→ 已向上游发 Cancel。
    ClientGone,
    /// 客户端连着但不再消费响应体（通道满且 `stall` 内无人取）→ 已发 Cancel。
    ClientStalled,
    /// 网关关闭（`Terminating`）：已给客户端一个"不完整"事件、取消上游并结算。
    GatewayShutdown,
    /// agent 违反了隧道协议（目前只有"响应块超过 `MAX_RESPONSE_CHUNK`"）：已把错误送给客户端、
    /// 取消上游并结算。与 [`ForwardEnd::UpstreamError`] 分开：这**不是上游的错误**——上游内容没问题，
    /// 是 agent 没按约定切块（记录 R9）。
    ProtocolViolation,
}

impl ForwardEnd {
    /// 指标标签用的稳定名字（`hlmg_forward_ends_total{kind=...}`）。
    ///
    /// 为什么值得单独当指标（记录 P2-14）：这里面**大多数出口发生时状态码已经写出去了**
    /// （200 已发给客户端，只是响应体半截/超时/被截断），访问日志只记状态码 ⇒ 这类失败在生产上
    /// 本来完全不可观测。穷尽匹配：新增变体时编译器会在这里提醒。
    pub(super) fn label(&self) -> &'static str {
        match self {
            ForwardEnd::UpstreamEnd => "upstream_end",
            ForwardEnd::UpstreamError => "upstream_error",
            ForwardEnd::UpstreamClosed => "upstream_closed",
            ForwardEnd::TunnelError => "tunnel_error",
            ForwardEnd::IdleTimeout => "idle_timeout",
            ForwardEnd::ClientGone => "client_gone",
            ForwardEnd::ClientStalled => "client_stalled",
            ForwardEnd::GatewayShutdown => "gateway_shutdown",
            ForwardEnd::ProtocolViolation => "protocol_violation",
        }
    }
}

/// 转发任务的收尾守卫（复扫 B3）。
///
/// **为什么需要一个 Drop 守卫**：`forward_body` 有九个**返回**出口，而 panic 是第十个——它不走
/// 任何一条返回路径。`tx` 会随栈展开被 drop，于是 `rx` 干净地结束，客户端拿到一份**看似完整的
/// 200 截断体**（HTTP 层看不出少了东西），而 `record_forward_end` 只在正常返回后调用 ⇒ 指标里
/// 连一个样本都没有，排查时完全没有痕迹。
///
/// panic 展开时唯一还会执行的是 Drop，所以收尾挂在这里——与 `SlotGuard` / `Admission` /
/// `AgentConnectionGuard` 同一个理由（那三处的注释写着同一句话："panic 展开时末尾那句不执行"）。
///
/// 正常路径调 [`Self::finish`] 记下出口标签并解除守卫，此后 Drop 是空操作。
pub(super) struct ForwardGuard {
    tx: mpsc::Sender<Result<Bytes, String>>,
    metrics: crate::metrics::Metrics,
    request_id: u64,
    armed: bool,
}

impl ForwardGuard {
    /// 需要在 `forward_body` **之前**建好：守卫必须活到任务结束（含 unwind）。
    pub(super) fn new(
        tx: mpsc::Sender<Result<Bytes, String>>,
        metrics: crate::metrics::Metrics,
        request_id: u64,
    ) -> Self {
        Self {
            tx,
            metrics,
            request_id,
            armed: true,
        }
    }

    /// 正常收尾：记下这次出口并解除守卫。
    pub(super) fn finish(&mut self, end: ForwardEnd) {
        // 记录 P2-14：这条 `debug!` 是**唯一**消费 ForwardEnd 的地方，于是七条以上的
        // "状态码已是 200 的失败"在指标上完全不可见；现在每个出口都留一个计数。
        self.metrics.record_forward_end(end.label());
        tracing::debug!(self.request_id, end = ?end, "response forwarding finished");
        self.armed = false;
    }
}

impl Drop for ForwardGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // 走到这里 = 任务在 `finish` 之前就 unwind 了。
        self.metrics.record_forward_end("panicked");
        tracing::error!(
            request_id = self.request_id,
            "response forwarding task panicked; aborting the client response so a truncated body \
             is not mistaken for a complete one"
        );
        // 推一个**错误项**：`Body::from_stream` 见到错误项会掐断响应（连接中断），而不是正常收尾
        // ——这正是"截断体不许看起来完整"所需要的信号，与其它九个出口用的是同一个通道。
        //
        // 用 `try_send`：Drop 里不能 await。通道满 = 客户端不读，那种情形另有 `client_stalled`
        // 与 `io_stall` 兜底，这里塞不进去不算丢信号。
        let _ = self.tx.try_send(Err(
            "internal error: the gateway's forwarding task panicked; this response is incomplete"
                .into(),
        ));
    }
}

/// 关闭时写给在途 SSE 的终止事件。
///
/// **必须与正常完成可区分**：`data: [DONE]` 是 OpenAI 的"正常结束"标记，用它收尾等于
/// 谎报"模型答完了"——客户端会把残缺结果当完整结果记账/计费。所以这里发一个明确的 error 事件。
const SHUTDOWN_SSE_EVENT: &[u8] = b"event: error\ndata: {\"error\":{\"message\":\"gateway is shutting down; this response is incomplete\",\"type\":\"server_error\"}}\n\n";

/// 带停滞超时地往客户端送一块。
///
/// 语义与请求体侧一致（见 `read_body_with_stall`）：**有进展就不超时**。客户端只要还在
/// 消费，通道就不会满，超时永远不会触发；只有"连着但一个字节都不取"才判定僵住。
pub(super) async fn send_to_client(
    tx: &mpsc::Sender<Result<Bytes, String>>,
    item: Result<Bytes, String>,
    stall: Duration,
) -> SendOutcome {
    match tokio::time::timeout(stall, tx.send(item)).await {
        Ok(Ok(())) => SendOutcome::Delivered,
        Ok(Err(_)) => SendOutcome::ClientGone,
        Err(_) => SendOutcome::Stalled,
    }
}

/// [`send_to_client`] + **盯着 `Terminating`**：任务被卡在"客户端不读"上时也要能被叫停。
///
/// 为什么需要它（并集报告 H5）：`forward_body` 只在**循环顶部**看 `shutdown_terminating`，
/// 而它可以 park 在 `tx.send` 上直到 `client_stall`（默认 60s）。`Gateway::shutdown` 的收尾
/// 窗口只有 1s，于是它返回时这个游离任务还持有 agent 槽位（`SlotGuard`）与 QUIC 流。
///
/// `Draining` **不**叫停：那个阶段只停 accept，在途响应必须继续正常跑完（见 [`ShutdownPhase`]
/// 的文档）——所以这是**重试发送**而不是丢数据；只有 `Terminating`（或发送端消失）才放弃。
async fn send_to_client_or_shutdown(
    tx: &mpsc::Sender<Result<Bytes, String>>,
    item: Result<Bytes, String>,
    stall: Duration,
    shutdown: &mut watch::Receiver<ShutdownPhase>,
) -> SendOutcome {
    loop {
        tokio::select! {
            outcome = send_to_client(tx, item.clone(), stall) => return outcome,
            res = shutdown.changed() => {
                if res.is_err() || shutdown_terminating(shutdown) {
                    return SendOutcome::ShuttingDown;
                }
                // `Draining`：继续尝试发这一块，一块都不能丢。
            }
        }
    }
}

/// 把响应体帧流转发到通道；任一端关闭时向对端发 Cancel。
/// `slot` 持有期间占用 agent 并发槽位，随任务结束释放。
///
/// `idle_timeout` 是**逐帧空闲**超时（响应阶段，SSE 长流靠"有帧就不超时"活着）；
/// `op_timeout` 只用于取消帧的写——隧道坏掉时连 Cancel 都可能写不出去，绝不能在这里
/// 阻塞（这正是"客户端已断开却发现不了"的死角）。
///
/// 参数确实多（流的两半、通道、三个超时、票据、指标、用量记账、请求元信息），但它们都是
/// 这个后台任务**必须独占持有**的资源；打包成 struct 只是把同一张清单换个地方写，不会让
/// 这个函数更难懂。
/// `Terminating` 阶段，或发送端已消失（`Gateway` 被 drop）→ 该收尾了。
///
/// 判据是**阶段**而不是"是否变过"：`changed()` 只保证"变过"，而 `Draining` 阶段只停接新
/// 请求，绝不该打断在途响应。
fn shutdown_terminating(rx: &watch::Receiver<ShutdownPhase>) -> bool {
    *rx.borrow() == ShutdownPhase::Terminating || rx.has_changed().is_err()
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn forward_body<R>(
    reader: &mut FrameReader<R>,
    send: &mut s2n_quic::stream::SendStream,
    request_id: u64,
    tx: mpsc::Sender<Result<Bytes, String>>,
    idle_timeout: Duration,
    client_stall: Duration,
    op_timeout: Duration,
    _slot: crate::registry::SlotGuard,
    metrics: crate::metrics::Metrics,
    key_store: crate::storage::KeyStore,
    key_id: String,
    key_name: String,
    prompt_est: u64,
    is_stream: bool,
    mut shutdown: watch::Receiver<ShutdownPhase>,
) -> ForwardEnd
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut usage = UsageCollector::new(key_store, key_id, key_name, prompt_est, is_stream);
    // reader 由调用方（`proxy::mod` 的响应编排）创建并**贯穿响应头与响应体两个阶段**
    // （记录 R3）：所以下面这个 `select!` 里 `shutdown.changed()` 分支的 `continue`
    // （复用同一条流）不会丢半帧，`Draining` 阶段"在途响应照常跑完"的承诺也靠它。
    loop {
        // 同时等"上游来帧"与"客户端走人"。
        //
        // 为什么必须 select：以前只在 `tx.send` 失败时才发现客户端断开——断开后上游若恰好
        // 不产帧（LLM 正在思考、首 token 之前的静默期），任务就停在读帧上，
        // `tx.send` 永不被调用 → Cancel 不发、agent 槽位要等满 `idle_timeout`（默认 120s）
        // 才释放。而"看到卡顿就取消"正是最常见的交互形态（登记见 REBUILD §4.7：
        // 后果是"上游明明空闲、新请求却 429 at capacity"）。
        //
        // **取消安全性**：读的是可取消安全的 `FrameReader`（记录 R3/P3-26）——而且是从响应头
        // 阶段一路带过来的**同一个** reader，所以任何一条 `select!` 分支落败都不丢字节：
        // `tx.closed()` / 关停分支放弃这条流时半读进度无所谓，`shutdown.changed()` 分支
        // `continue` 复用同一条流时则**必须**靠它（这正是一次真实缺陷的形状）。
        // 网关进入 `Terminating`：给客户端一个明确事件，然后干净收尾。**不能**指望 abort 去切：
        // 实测 drop `s2n_quic::Server` 并不会掐断已建立的 agent 连接。
        if shutdown_terminating(&shutdown) {
            if is_stream {
                // 明确告知"不完整"；**绝不能**用 `[DONE]`（那等于谎报正常完成）。
                match send_to_client(
                    &tx,
                    Ok(Bytes::from_static(SHUTDOWN_SSE_EVENT)),
                    // 关停路径专用上限：正常读取的客户端微秒级就收下，不读的不能拖住关停（H5）
                    client_stall.min(SHUTDOWN_EVENT_WRITE_TIMEOUT),
                )
                .await
                {
                    SendOutcome::Delivered => {}
                    // 这一档走的是**不带 shutdown 的** `send_to_client`，所以它不会返回
                    // `ShuttingDown`；与 `ClientGone` 合并只是让 match 穷尽，处置相同
                    // （接收端没了 → 发不出去，照常取消上游）。
                    SendOutcome::ShuttingDown | SendOutcome::ClientGone => {
                        warn!(
                            request_id,
                            "client gone while announcing shutdown; cancelling upstream"
                        )
                    }
                    SendOutcome::Stalled => {
                        metrics.record_client_stall("response-body");
                        warn!(
                            request_id,
                            "client stopped reading while announcing shutdown; cancelling upstream"
                        );
                    }
                }
            }
            tunnel_cancel(send, request_id, op_timeout).await;
            let _ = send.finish();
            usage.finish();
            return ForwardEnd::GatewayShutdown;
        }
        let frame = tokio::select! {
            r = tokio::time::timeout(idle_timeout, reader.next()) => r,
            _ = tx.closed() => {
                warn!(
                    request_id,
                    "client disconnected while the upstream was silent; cancelling upstream"
                );
                tunnel_cancel(send, request_id, op_timeout).await;
                let _ = send.finish();
                usage.finish();
                return ForwardEnd::ClientGone;
            }
            changed = shutdown.changed() => {
                // 阶段变化或发送端消失：回到循环顶部统一判定。`changed()` 只报告"变过"，
                // 所以 `Draining` 时顶部不会收尾，继续正常转发。
                let _ = changed;
                continue;
            }
        };
        match frame {
            Ok(Ok(Some(Frame::ProxyResponseBody { chunk, .. }))) => {
                // 内存边界（记录 R9）：通道按**条数**有界（32），所以单块大小决定上界。
                // agent 侧负责切块；这里是**纵深防御**——坏/旧 agent 不该让网关堆下 GB 级内存。
                if chunk.len() > proto::frame::MAX_RESPONSE_CHUNK {
                    warn!(
                        request_id,
                        len = chunk.len(),
                        limit = proto::frame::MAX_RESPONSE_CHUNK,
                        "agent sent an oversized response chunk; refusing the response"
                    );
                    let _ = send_to_client_or_shutdown(
                        &tx,
                        Err("upstream sent an oversized response chunk".into()),
                        client_stall,
                        &mut shutdown,
                    )
                    .await;
                    tunnel_cancel(send, request_id, op_timeout).await;
                    let _ = send.finish();
                    usage.finish();
                    return ForwardEnd::ProtocolViolation;
                }
                match send_to_client_or_shutdown(
                    &tx,
                    Ok(chunk.clone()),
                    client_stall,
                    &mut shutdown,
                )
                .await
                {
                    SendOutcome::Delivered => {}
                    SendOutcome::ShuttingDown => {
                        // 网关要求收尾：这一块不再送（响应体接下来会被明确标成"不完整"），
                        // 但上游已经产出了它 → 照记用量，然后回到循环顶走收尾分支。
                        usage.observe(&chunk);
                        continue;
                    }
                    SendOutcome::ClientGone => {
                        // 客户端已断开 → 取消上游；仍结算已转发部分
                        warn!(request_id, "client disconnected, cancelling upstream");
                        usage.observe(&chunk);
                        tunnel_cancel(send, request_id, op_timeout).await;
                        let _ = send.finish();
                        usage.finish();
                        return ForwardEnd::ClientGone;
                    }
                    SendOutcome::Stalled => {
                        // 客户端还在连接上、但不再消费响应体：以前这里会永久 park，
                        // 于是准入票据永不释放（实测云端沉淀 8 个僵尸槽位，只能重启）。
                        // 现在主动放弃：取消上游（别让 agent 继续烧 token）、结束响应体
                        // （丢掉 tx → 客户端看到流被截断/连接关闭，这是诚实的失败信号）。
                        metrics.record_client_stall("response-body");
                        warn!(
                            request_id,
                            stall_ms = client_stall.as_millis(),
                            "client stopped consuming the response body; cancelling upstream and releasing the slot"
                        );
                        usage.observe(&chunk);
                        tunnel_cancel(send, request_id, op_timeout).await;
                        let _ = send.finish();
                        usage.finish();
                        return ForwardEnd::ClientStalled;
                    }
                }
                usage.observe(&chunk);
                metrics.add_bytes_out(chunk.len());
            }
            Ok(Ok(Some(Frame::ProxyResponseEnd { .. }))) => {
                let _ = send.finish();
                usage.finish();
                return ForwardEnd::UpstreamEnd;
            }
            Ok(Ok(Some(Frame::Error { code, message, .. }))) => {
                let _ = send_to_client_or_shutdown(
                    &tx,
                    Err(format!("upstream error {code}: {message}")),
                    client_stall,
                    &mut shutdown,
                )
                .await;
                let _ = send.finish();
                usage.finish();
                return ForwardEnd::UpstreamError;
            }
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) => {
                let _ = send_to_client_or_shutdown(
                    &tx,
                    Err("upstream closed the stream early".into()),
                    client_stall,
                    &mut shutdown,
                )
                .await;
                usage.finish();
                return ForwardEnd::UpstreamClosed;
            }
            Ok(Err(e)) => {
                let _ = send_to_client_or_shutdown(
                    &tx,
                    Err(format!("tunnel read failed: {e}")),
                    client_stall,
                    &mut shutdown,
                )
                .await;
                usage.finish();
                return ForwardEnd::TunnelError;
            }
            Err(_) => {
                // 空闲超时 → 取消上游；结算已转发部分
                warn!(request_id, "upstream idle timeout, cancelling");
                let _ = send_to_client_or_shutdown(
                    &tx,
                    Err("upstream idle timeout".into()),
                    client_stall,
                    &mut shutdown,
                )
                .await;
                tunnel_cancel(send, request_id, op_timeout).await;
                let _ = send.finish();
                usage.finish();
                return ForwardEnd::IdleTimeout;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    /// 规格（复扫 B3）：**转发任务 panic 必须留下痕迹、并且掐断响应**。
    ///
    /// 修复前：`tx` 随栈展开 drop ⇒ `rx` 干净结束 ⇒ 客户端拿到"看似完整的 200 截断体"，
    /// 而指标里连一个样本都没有。现在收尾挂在 `ForwardGuard` 的 Drop 上。
    #[tokio::test]
    async fn a_panicking_forward_task_records_it_and_aborts_the_body() {
        let (tx, mut rx) = mpsc::channel::<Result<Bytes, String>>(4);
        let metrics = crate::metrics::Metrics::default();

        // 让它在**真的 unwind** 里 drop 守卫（不是正常返回），证明那条路确实会执行。
        // 顺便静音 panic hook，免得测试输出里混进一段看起来像失败的回溯。
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let joined = tokio::spawn({
            let metrics = metrics.clone();
            async move {
                let _guard = ForwardGuard::new(tx, metrics, 7);
                panic!("boom");
            }
        })
        .await;
        std::panic::set_hook(prev);

        assert!(joined.is_err(), "前提：任务确实 panic 了");
        assert!(
            rx.recv().await.expect("panic 之后必须还有一项").is_err(),
            "必须推一个**错误项**：`Body::from_stream` 见到它才会掐断响应，而不是干净收尾"
        );
        let text = metrics.render(0, 0, 0, 0);
        assert!(
            text.contains("hlmg_forward_ends_total{kind=\"panicked\"} 1"),
            "panic 必须留一个指标样本：\n{text}"
        );
    }

    /// 对照：正常收尾记的是**那个出口的标签**，既不打 `panicked`、也不往流里塞错误项。
    #[test]
    fn a_finished_forward_task_records_its_exit_and_leaves_the_body_alone() {
        let (tx, mut rx) = mpsc::channel::<Result<Bytes, String>>(4);
        let metrics = crate::metrics::Metrics::default();
        let mut guard = ForwardGuard::new(tx, metrics.clone(), 7);
        guard.finish(ForwardEnd::UpstreamEnd);
        assert!(rx.try_recv().is_err(), "正常收尾不该往流里塞东西");
        let text = metrics.render(0, 0, 0, 0);
        assert!(
            text.contains("hlmg_forward_ends_total{kind=\"upstream_end\"} 1"),
            "{text}"
        );
        assert!(
            !text.contains("kind=\"panicked\""),
            "正常收尾不该记 panicked：\n{text}"
        );
    }

    /// 规格（记录 P2-14）：**每条退出路径都要有自己的指标标签**，且互不相同。
    ///
    /// 标签就是 `hlmg_forward_ends_total{kind=...}` 的取值，混在一起就分不出"客户端走了"
    /// 与"上游没发 End 就关了"——而这两者的处置完全相反。
    #[test]
    fn every_forward_end_has_its_own_label() {
        let all = [
            ForwardEnd::UpstreamEnd,
            ForwardEnd::UpstreamError,
            ForwardEnd::UpstreamClosed,
            ForwardEnd::TunnelError,
            ForwardEnd::IdleTimeout,
            ForwardEnd::ClientGone,
            ForwardEnd::ClientStalled,
            ForwardEnd::GatewayShutdown,
            ForwardEnd::ProtocolViolation,
        ];
        let labels: Vec<&str> = all.iter().map(|e| e.label()).collect();
        assert!(
            labels
                .iter()
                .all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_lowercase() || c == '_')),
            "标签应当是稳定的 snake_case（指标标签基数有界、可 grep）：{labels:?}"
        );
        let mut unique = labels.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), labels.len(), "标签必须互不相同：{labels:?}");
    }

    /// 规格（并集报告 H5）：**`Terminating` 必须叫停卡在"客户端不读"上的发送**。
    ///
    /// 修复前这里会 park 到 `stall`（测试里给 60s）——`Gateway::shutdown` 的收尾窗口只有 1s，
    /// 于是它返回时这个游离任务还持有 agent 槽位与 QUIC 流。
    ///
    /// 同时钉住**`Draining` 不许叫停**：那个阶段只停 accept，在途响应必须继续跑完，
    /// 在这里丢掉一块就是数据丢失。
    #[tokio::test]
    async fn terminating_interrupts_a_stalled_send_but_draining_does_not() {
        // 容量 1 且占满 → 下一次 send 一定 park
        let (tx, rx) = mpsc::channel::<Result<Bytes, String>>(1);
        tx.send(Ok(Bytes::from_static(b"filler"))).await.unwrap();
        let (phase_tx, mut phase_rx) = watch::channel(ShutdownPhase::Running);

        let started = Instant::now();
        let task = tokio::spawn(async move {
            send_to_client_or_shutdown(
                &tx,
                Ok(Bytes::from_static(b"blocked")),
                Duration::from_secs(60),
                &mut phase_rx,
            )
            .await
        });

        // 先让它卡住，再发 `Draining`：不许结束、也不许丢块
        tokio::time::sleep(Duration::from_millis(50)).await;
        phase_tx.send(ShutdownPhase::Draining).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !task.is_finished(),
            "`Draining` 只停 accept，不该打断在途响应的发送（丢了就是数据丢失）"
        );

        // 再发 `Terminating`：必须立刻结束，而不是等满 60s 的停滞上限
        phase_tx.send(ShutdownPhase::Terminating).unwrap();
        let outcome = tokio::time::timeout(Duration::from_millis(500), task)
            .await
            .expect("`Terminating` 必须叫停停滞的发送（H5：否则关停后任务还活着）")
            .expect("任务不该 panic");
        assert!(
            matches!(outcome, SendOutcome::ShuttingDown),
            "应当是主动叫停（ShuttingDown），实际 {outcome:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "必须是立刻叫停，而不是等满停滞上限；实测 {:?}",
            started.elapsed()
        );
        drop(rx);

        // 阶段发送端被 drop（`Gateway` 已析构）也算"该收尾了"：`changed()` 报 Err。
        // 注意接收端要留着——否则 `send` 立刻返回 `ClientGone`，测的就不是这条路径了。
        let (tx2, _rx2) = mpsc::channel::<Result<Bytes, String>>(1);
        tx2.send(Ok(Bytes::from_static(b"filler"))).await.unwrap();
        let (phase_tx2, mut phase_rx2) = watch::channel(ShutdownPhase::Running);
        drop(phase_tx2);
        let outcome = tokio::time::timeout(
            Duration::from_millis(500),
            send_to_client_or_shutdown(
                &tx2,
                Ok(Bytes::from_static(b"blocked")),
                Duration::from_secs(60),
                &mut phase_rx2,
            ),
        )
        .await
        .expect("发送端消失也必须叫停");
        assert!(matches!(outcome, SendOutcome::ShuttingDown));
    }

    /// 规格：没有关停信号时，停滞判定维持原样（`Stalled`，由调用方记 `client_stalls`）。
    #[tokio::test]
    async fn a_stalled_send_still_reports_stalled_without_a_shutdown() {
        let (tx, rx) = mpsc::channel::<Result<Bytes, String>>(1);
        tx.send(Ok(Bytes::from_static(b"filler"))).await.unwrap();
        let (_phase_tx, mut phase_rx) = watch::channel(ShutdownPhase::Running);

        let outcome = send_to_client_or_shutdown(
            &tx,
            Ok(Bytes::from_static(b"blocked")),
            Duration::from_millis(50),
            &mut phase_rx,
        )
        .await;
        assert!(
            matches!(outcome, SendOutcome::Stalled),
            "没有关停时应按停滞处置，实际 {outcome:?}"
        );
        drop(rx);
    }
}
