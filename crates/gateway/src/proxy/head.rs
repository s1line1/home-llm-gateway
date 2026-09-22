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
#[derive(Debug)]
enum HeadOutcome {
    Head(StatusCode, Vec<(String, String)>),
    Error(u16, String),
}

/// 读响应头帧（或错误帧）。
///
/// **头之前的响应体：按既有契约忽略，但不再无声**（记录 P3-15 的复核结果）。
///
/// 原本这里所有别的帧都走 `Some(_) => {}`——一个"头之前先发了一块 body"的 agent 会让那一块
/// **无声消失**：客户端拿到 200、内容却少了一段，日志里一句话都没有。
///
/// ⚠️ 但把它改成 502 协议错误是**改契约**，不是修 bug：`tests/e2e/https.rs` 的
/// `e2e_proxy_protocol_edge_cases` 场景 2 明确钉住"head 前的 body 应被忽略 → 200 + hello"，
/// 那是项目作者写下的**容忍**决定（代理对帧序更宽容）。所以这里保留忽略，只把"无声"去掉；
/// 要不要收紧成协议错误属于产品决定，见 P3-15 的登记。
///
/// 其余帧（心跳等）同样容忍：跳过并记一行**只有帧名**的日志。为什么不打 `{frame:?}`——
/// `Debug` 会连 `Bytes` 载荷一起打，一个坏 agent 发来的大帧就是一行巨大日志（见
/// [`Frame::kind`]）。兼容性也要求容忍：新旧版本两端可能多出对方不认识的帧。
///
/// 泛型只为可测：生产传 `s2n_quic::stream::ReceiveStream`，测试传一段线上字节。
async fn read_head<R>(recv: &mut R, request_id: u64) -> anyhow::Result<HeadOutcome>
where
    R: tokio::io::AsyncRead + Unpin,
{
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
            Some(Frame::ProxyResponseBody { chunk, .. }) => {
                // 忽略是契约；但"这一块再也补不回来"至少要留在日志里
                warn!(
                    request_id,
                    len = chunk.len(),
                    "ignoring a response body received before the response head \
                     (the chunk cannot be put back in order)"
                );
            }
            Some(other) => {
                warn!(
                    request_id,
                    frame = other.kind(),
                    "ignoring an unexpected frame while waiting for the response head"
                );
            }
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
    let head = tokio::time::timeout(state.head_timeout, read_head(recv, request_id)).await;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 把若干帧拼成一段线上字节（与真实隧道同格式，走生产代码的 `write_frame`）。
    async fn wire(frames: &[Frame]) -> Vec<u8> {
        let mut buf = Vec::new();
        for frame in frames {
            proto::io::write_frame(&mut buf, frame).await.unwrap();
        }
        buf
    }

    fn head_200() -> Frame {
        Frame::ProxyResponseHead {
            request_id: 1,
            status: 200,
            headers: vec![("content-type".into(), "text/plain".into())],
        }
    }

    /// 规格（记录 P3-15 的复核结论）：头之前的响应体**仍然被忽略**——这是**已钉住的契约**，
    /// 不是待修的 bug。
    ///
    /// `tests/e2e/https.rs::e2e_proxy_protocol_edge_cases` 场景 2 就是这条：先 Body("ignored")
    /// 再 Head(200) 再 Body("hello") + End ⇒ 客户端拿到 200 + `"hello"`。所以"改成 502 协议
    /// 错误"属于**改契约**，得先有人拍板；本测试把现状钉在这里，免得它被顺手改掉。
    ///
    /// 本次真正修掉的是**无声**这一半：那一块内容补不回来，至少要在日志里出现（代码里的
    /// `warn!`）。日志本身不在这里断言——仓库没有 tracing 捕获依赖，不为一条日志新增依赖。
    #[tokio::test]
    async fn a_body_before_the_head_is_still_ignored_per_the_pinned_contract() {
        let bytes = wire(&[
            Frame::ProxyResponseBody {
                request_id: 1,
                chunk: b"ignored\n".to_vec().into(),
            },
            head_200(),
            Frame::ProxyResponseBody {
                request_id: 1,
                chunk: b"hello\n".to_vec().into(),
            },
        ])
        .await;
        let mut reader = bytes.as_slice();

        match read_head(&mut reader, 7).await.unwrap() {
            HeadOutcome::Head(status, headers) => {
                assert_eq!(status, 200, "头本身照旧决定响应");
                assert_eq!(headers.len(), 1);
            }
            other => panic!("头之前的 body 按契约应被忽略，实际：{other:?}"),
        }

        // 被忽略的那一块确实**读掉了**（不是留在流里再被当成别的帧）：下一帧应当就是"头之后"
        // 的那块 hello——这条同时说明"忽略"的代价（数据真的没了），别把它当成无损操作。
        let next = proto::io::read_frame(&mut reader).await.unwrap();
        match next {
            Some(Frame::ProxyResponseBody { chunk, .. }) => {
                assert_eq!(&chunk[..], b"hello\n", "被忽略的那一块不会补回来");
            }
            other => panic!("头之后应当是第二块，实际：{other:?}"),
        }
    }

    /// 对照：**头之后的**响应体不归本函数管（它由 `forward_body` 转发），本函数在拿到头时
    /// 就必须返回，不能顺手把后面的块也读掉——否则那些字节就丢了。
    #[tokio::test]
    async fn a_body_after_the_head_is_left_in_the_stream() {
        let bytes = wire(&[
            head_200(),
            Frame::ProxyResponseBody {
                request_id: 1,
                chunk: b"first\n".to_vec().into(),
            },
        ])
        .await;
        let mut reader = bytes.as_slice();

        match read_head(&mut reader, 7).await.unwrap() {
            HeadOutcome::Head(status, headers) => {
                assert_eq!(status, 200);
                assert_eq!(headers.len(), 1);
            }
            other => panic!("第一个帧就是响应头，应当直接返回，实际：{other:?}"),
        }

        // 剩下的字节必须仍在流里：`read_frame` 一次只消费一帧（对比 `FrameReader` 会预读）
        let next = proto::io::read_frame(&mut reader).await.unwrap();
        assert!(
            matches!(next, Some(Frame::ProxyResponseBody { .. })),
            "响应头之后的块必须留在流里，实际：{next:?}"
        );
    }

    /// 规格：不认识的帧**容忍**（新旧版本两端可能多出对方不认识的帧），但必须记日志；
    /// 日志只带帧名，不带载荷。
    #[tokio::test]
    async fn an_unexpected_frame_is_skipped_and_the_head_is_still_found() {
        let bytes = wire(&[
            Frame::Heartbeat {
                agent_id: "a".into(),
                inflight: 0,
            },
            head_200(),
        ])
        .await;

        match read_head(&mut bytes.as_slice(), 7).await.unwrap() {
            HeadOutcome::Head(status, _) => assert_eq!(status, 200),
            other => panic!("心跳应当被跳过、继续等响应头，实际：{other:?}"),
        }
    }

    /// 对照：头之前就结束 / 对端报错，两条既有出口不许被这次改动碰坏。
    #[tokio::test]
    async fn closed_stream_and_error_frames_keep_their_own_outcomes() {
        // 一字节都没有 = 干净关闭
        match read_head(&mut (&[][..]), 7).await.unwrap() {
            HeadOutcome::Error(502, message) => {
                assert!(message.contains("closed before responding"), "{message}")
            }
            other => panic!("空流应当是 502，实际：{other:?}"),
        }

        // 上游显式报错：原样透出 code/message
        let bytes = wire(&[Frame::Error {
            request_id: Some(1),
            code: 429,
            message: "slow down".into(),
        }])
        .await;
        match read_head(&mut bytes.as_slice(), 7).await.unwrap() {
            HeadOutcome::Error(429, message) => assert_eq!(message, "slow down"),
            other => panic!("错误帧应当原样透出，实际：{other:?}"),
        }

        // 头都没给就结束：502 "empty upstream response"
        let bytes = wire(&[Frame::ProxyResponseEnd {
            request_id: 1,
            ok: true,
        }])
        .await;
        match read_head(&mut bytes.as_slice(), 7).await.unwrap() {
            HeadOutcome::Error(502, message) => {
                assert!(message.contains("empty upstream response"), "{message}")
            }
            other => panic!("先结束应当是 502，实际：{other:?}"),
        }
    }
}
