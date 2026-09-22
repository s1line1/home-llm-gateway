//! 上游**响应头**的等待与失败渲染：等 `head_timeout`，把"慢/死"判定交给注册表，并把结果
//! 映射成对外契约（状态码 / 指标标签 / 日志 / Cancel 帧）。
//!
//! 为什么单独成模块（并集评估 §2 的 S2）：输入（`recv` / `send` / `entry` / `request_id`
//! 加 `AppState` 里的四个窗口）与输出（`(status, headers)` 或 [`RouteFailure`]）**已经是一条
//! 边界**，而它只有一个改动理由——上游响应头的契约。搬出来之后 `proxy/mod.rs` 只剩编排。
//!
//! **判据不在这里**：`Disposition` 由 [`crate::registry::Registry::report_head_timeout`] 给出，
//! 本模块只负责"按它渲染"——与 `routing.rs` 对开流超时做的事对称（那里的注释同理：
//! 判定与记账在注册表，状态码与文案是外部契约，留在调用侧）。

use axum::http::StatusCode;
use proto::{io::read_frame, Frame};
use tracing::warn;

use crate::registry::{Disposition, Entry, HeadSilence};
use crate::state::AppState;

use super::routing::RouteFailure;
use super::tunnel::tunnel_cancel;

/// 读到响应头，或读到"在给头之前就结束/出错"的信号。
enum HeadOutcome {
    Head(StatusCode, Vec<(String, String)>),
    Error(u16, String),
}

/// 读响应头帧（或错误帧），跳过其余帧。
async fn read_head(recv: &mut s2n_quic::stream::ReceiveStream) -> anyhow::Result<HeadOutcome> {
    loop {
        match read_frame(recv).await? {
            Some(Frame::ProxyResponseHead {
                status: s,
                headers: h,
                ..
            }) => {
                return Ok(HeadOutcome::Head(
                    StatusCode::from_u16(s).unwrap_or(StatusCode::BAD_GATEWAY),
                    h,
                ));
            }
            Some(Frame::Error { code, message, .. }) => {
                return Ok(HeadOutcome::Error(code, message));
            }
            Some(Frame::ProxyResponseEnd { .. }) => {
                return Ok(HeadOutcome::Error(502, "empty upstream response".into()));
            }
            Some(_) => {}
            None => {
                return Ok(HeadOutcome::Error(
                    502,
                    "upstream closed before responding".into(),
                ));
            }
        }
    }
}

/// 等上游响应头；失败时返回**要渲染成响应的** [`RouteFailure`]（调用方 `error_response`）。
///
/// 用 `head_timeout` 而不是 `request_timeout`：以前这里用 `state.timeout`（默认 120s），
/// agent 一旦卡住（注册着但什么都不回），每个请求都要把连接、并发槽位和缓冲区占满两分钟；
/// 客户端早就超时断开，而网关还停在读上，连"客户端已断开"都发现不了
/// （实测 40 并发 → 620MB 内存被钉住、日志停更）。也不能用 `tunnel_op_timeout`（2s）：
/// 上游"思考"是合法的，本地模型 1–3s 很常见。
pub(super) async fn await_head(
    state: &AppState,
    recv: &mut s2n_quic::stream::ReceiveStream,
    send: &mut s2n_quic::stream::SendStream,
    entry: &Entry,
    request_id: u64,
) -> Result<(StatusCode, Vec<(String, String)>), RouteFailure> {
    let head = tokio::time::timeout(state.head_timeout, read_head(recv)).await;
    match head {
        Ok(Ok(HeadOutcome::Head(s, h))) => {
            // 对端真的回了响应头 = 这条隧道是活的 → 清掉连续超时计数。
            // （开流成功不能作为判据：agent 卡死时流照样能开，只是永远不回帧。）
            state.registry.note_tunnel_op_ok(entry.stable_id());
            Ok((s, h))
        }
        Ok(Ok(HeadOutcome::Error(code, message))) => {
            let _ = send.finish();
            Err(RouteFailure {
                status: StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY),
                message,
            })
        }
        Ok(Err(e)) => {
            let _ = send.finish();
            Err(RouteFailure {
                status: StatusCode::BAD_GATEWAY,
                message: format!("tunnel read failed: {e}"),
            })
        }
        Err(_) => {
            // 响应头超时：请求已经发出去了、对端却什么都没回。**两种情况必须分开**：
            //
            //   慢：这条隧道最近还在正常回响应头（`head_alive_window` 内），说明它只是被链路/
            //       上游堵住了 → 只回 504、**不计连续超时、不摘除**。把"慢"当"死"的代价实测过：
            //       出口带宽饱和时一个响应头都收不到，连续计数必然爬到阈值 → 摘除健康 agent →
            //       重连期间注册表为空 → **全量 503**（一次压测 1 026 次 head timeout、
            //       `registry-empty` +3 753）。局部超载不该变成全站不可用。
            //   死：窗口内一次都没回过 → 没有任何"只是慢"的理由，走原来的连续 3 次摘除。
            //
            // 这条判据由注册表给出（判定与记账、摘除在同一处），本模块只把它映射成
            // 指标标签与日志文案——那些是外部契约，留在原处。
            //
            // 判据有**两层**（第二层见评估 §5 H2）：窗口内有过成功响应头 → 只是慢；
            // 窗口过了但**对端还在说话**（心跳新鲜）且静默没超过 `head_silent_grace` → 仍算慢。
            // 第二层不可省：`last_head_ok` 的唯一刷新点就是成功响应头，所以当**所有**请求都慢过
            // `head_timeout` 时没有任何一次成功能刷新它，只按第一层就会误摘活着的 agent。
            let disposition = state.registry.report_head_timeout(
                entry,
                HeadSilence {
                    window: state.head_alive_window,
                    peer_alive_window: state.agent_stale_after,
                    stuck_after: state.head_silent_grace,
                },
                state.evict_close_grace,
            );
            let last_head_ago_secs = entry.last_head_ago().map_or(0, |d| d.as_secs());
            if matches!(disposition, Disposition::Fatal) {
                state.metrics.record_head_timeout("silent");
                warn!(
                    request_id,
                    agent = %entry.agent_id(),
                    last_head_ago_secs,
                    window_secs = state.head_alive_window.as_secs(),
                    "upstream head timeout and the agent has been silent; evicting agent"
                );
            } else {
                state.metrics.record_head_timeout("slow");
                warn!(
                    request_id,
                    agent = %entry.agent_id(),
                    last_head_ago_secs,
                    "upstream head timeout while the agent is still answering; not evicting"
                );
            }
            tunnel_cancel(send, request_id, state.tunnel_op_timeout).await;
            let _ = send.finish();
            Err(RouteFailure {
                status: StatusCode::GATEWAY_TIMEOUT,
                message: "upstream timed out".to_string(),
            })
        }
    }
}
