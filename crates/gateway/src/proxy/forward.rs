//! 响应转发：把上游的帧流转成客户端的响应体，并在任一端消失时取消另一端。
//!
//! 这是整个网关并发语义最密的一段，所以它自成一格：
//!
//! - **客户端断开 / 停滞** → 向上游发 `Cancel`，别让边缘继续烧 token；
//! - **上游结束 / 断流 / 空闲超时** → 结束响应体，并结算已转发部分的用量；
//! - **agent 槽位** → `slot` 随本任务结束释放（HTTP 准入票据是另一条：它挂在响应体上）。
//!
//! 三条超时语义各不相同且都不能省：`idle_timeout` 是**逐帧空闲**（SSE 长流靠"有帧就不
//! 超时"活着）、`client_stall` 是客户端**停滞**、`op_timeout` 只用于 Cancel 帧的写——
//! 最后一处尤其：隧道坏掉时连 Cancel 都可能写不出去，在那里阻塞正是"客户端已断开却
//! 发现不了"的死角。

use std::time::Duration;

use axum::body::Bytes;
use proto::{io::read_frame, Frame};
use tokio::sync::{mpsc, watch};
use tracing::warn;

use crate::state::ShutdownPhase;

use super::tunnel::tunnel_cancel;
use super::usage::UsageCollector;

/// 往客户端方向送一块的结果。三种情况处置完全不同，必须分开。
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
}

/// 响应转发结束的方式。**八个出口各自的处置不同**，以前它们只是散落的 `return`——
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
pub(super) async fn forward_body(
    recv: &mut s2n_quic::stream::ReceiveStream,
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
) -> ForwardEnd {
    let mut usage = UsageCollector::new(key_store, key_id, key_name, prompt_est, is_stream);
    loop {
        // 同时等"上游来帧"与"客户端走人"。
        //
        // 为什么必须 select：以前只在 `tx.send` 失败时才发现客户端断开——断开后上游若恰好
        // 不产帧（LLM 正在思考、首 token 之前的静默期），任务就停在 `read_frame` 上，
        // `tx.send` 永不被调用 → Cancel 不发、agent 槽位要等满 `idle_timeout`（默认 120s）
        // 才释放。而"看到卡顿就取消"正是最常见的交互形态（登记见 REBUILD §4.7：
        // 后果是"上游明明空闲、新请求却 429 at capacity"）。
        //
        // **取消安全性**：`read_frame` 不是可取消安全的（REBUILD §R3 登记过），但这条分支与
        // 下面的空闲超时一样——取消后立刻 `finish()` 并彻底放弃这条流、不再读它，所以丢掉
        // 半读的帧无害。
        // 网关进入 `Terminating`：给客户端一个明确事件，然后干净收尾。**不能**指望 abort 去切：
        // 实测 drop `s2n_quic::Server` 并不会掐断已建立的 agent 连接。
        if shutdown_terminating(&shutdown) {
            if is_stream {
                // 明确告知"不完整"；**绝不能**用 `[DONE]`（那等于谎报正常完成）。
                match send_to_client(
                    &tx,
                    Ok(Bytes::from_static(SHUTDOWN_SSE_EVENT)),
                    client_stall,
                )
                .await
                {
                    SendOutcome::Delivered => {}
                    SendOutcome::ClientGone => {
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
            r = tokio::time::timeout(idle_timeout, read_frame(recv)) => r,
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
                match send_to_client(&tx, Ok(chunk.clone()), client_stall).await {
                    SendOutcome::Delivered => {}
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
                let _ = send_to_client(
                    &tx,
                    Err(format!("upstream error {code}: {message}")),
                    client_stall,
                )
                .await;
                let _ = send.finish();
                usage.finish();
                return ForwardEnd::UpstreamError;
            }
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) => {
                let _ = send_to_client(
                    &tx,
                    Err("upstream closed the stream early".into()),
                    client_stall,
                )
                .await;
                usage.finish();
                return ForwardEnd::UpstreamClosed;
            }
            Ok(Err(e)) => {
                let _ = send_to_client(&tx, Err(format!("tunnel read failed: {e}")), client_stall)
                    .await;
                usage.finish();
                return ForwardEnd::TunnelError;
            }
            Err(_) => {
                // 空闲超时 → 取消上游；结算已转发部分
                warn!(request_id, "upstream idle timeout, cancelling");
                let _ =
                    send_to_client(&tx, Err("upstream idle timeout".into()), client_stall).await;
                tunnel_cancel(send, request_id, op_timeout).await;
                let _ = send.finish();
                usage.finish();
                return ForwardEnd::IdleTimeout;
            }
        }
    }
}
