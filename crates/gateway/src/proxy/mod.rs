//! 代理转发：认证 → 限流 → 编码为隧道帧转发（从 http.rs 拆分，保持路由层精简）。

mod tunnel;
mod usage;

use std::time::Duration;

use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::Response,
};
use proto::{io::read_frame, Frame};

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

use crate::auth::authenticate;
use crate::body::{read_body_with_stall, BodyRead, MAX_REQUEST_BODY};
use crate::openai::error_response;
use crate::registry::AcquireError;
use crate::state::AppState;
use tunnel::{open_tunnel, tunnel_cancel, tunnel_write, OpenFailure};
use usage::UsageCollector;

static NEXT_REQUEST_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// 从请求 body 提取路由所需模型：顶层 `model` 字段（OpenAI 兼容语义，必填）。
/// 缺失 / 非字符串 / 空串 → Err（调用方返回 400）。
fn extract_model(body: &[u8]) -> Result<String, ()> {
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| ())?;
    match value.get("model") {
        Some(serde_json::Value::String(s)) if !s.is_empty() => Ok(s.clone()),
        _ => Err(()),
    }
}

pub async fn proxy(State(state): State<AppState>, req: Request) -> Response {
    // 先取 method/uri/headers，body 留到**认证之后再读**：
    // 以前 `Bytes` 是提取器，于是未认证的请求也能让网关先缓冲 16MB（认证在 handler 里，
    // 比提取器晚一步）。现在认证在最前，读 body 在后，顺带把这个放大面收掉。
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("req-"))
        .and_then(|n| n.parse::<u64>().ok())
        .unwrap_or_else(|| NEXT_REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed));

    // 认证 + 限流（per-key 令牌桶）：拿不到身份的唯一出路就是把它还给客户端。
    let key = match authenticate(&state, &headers).await {
        Ok(key) => key,
        Err(rejection) => return rejection.into_response(),
    };

    // 读请求体：停滞/超限/读失败各自有明确状态码，且**都会归还准入票据**（随本函数返回而
    // Drop）——这正是修掉"槽位永久泄漏"的地方。
    let body =
        match read_body_with_stall(req.into_body(), state.client_stall, MAX_REQUEST_BODY).await {
            BodyRead::Body(b) => b,
            BodyRead::Stalled => {
                state.metrics.record_client_stall("request-body");
                warn!(
                request_id,
                stall_ms = state.client_stall.as_millis(),
                "client stalled while sending the request body; dropping the request and its slot"
            );
                return error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    "client stalled while sending the request body",
                );
            }
            BodyRead::TooLarge => {
                return error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large")
            }
            BodyRead::Failed(e) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    format!("request body read failed: {e}"),
                )
            }
        };
    // 路由需要模型：按请求 model 挑选能服务它的 agent（见 MODEL_ROUTING.md）
    let model = match extract_model(&body) {
        Ok(m) => m,
        Err(()) => {
            return error_response(StatusCode::BAD_REQUEST, "model is required in request body")
        }
    };
    // 保留原始完整路径（如 /v1/chat/completions），原样转发给上游
    let path = match uri.query() {
        Some(q) => format!("{}?{q}", uri.path()),
        None => uri.path().to_string(),
    };
    // request_id 在函数最开头就算好了（因为它要出现在"读 body 停滞"这类早期日志里）
    // 隧道 request_id 复用 HTTP 层 x-request-id 的数字部分（metrics_middleware 注入，
    // 格式 req-{n}）——HTTP 日志 / 隧道帧 / 响应头三方对账一致；无该头时自增兜底。
    // 请求帧在选路之前就构造好：重试换的是连接，请求内容不变（body 已整包在手，可重放）。
    let request = Frame::ProxyRequest {
        request_id,
        method: method.to_string(),
        path,
        headers: filter_headers(&headers),
        body: body.to_vec(),
    };

    // 隧道建立阶段允许**换一个 agent 重试**。
    //
    // 只有"开流 / 写请求帧"失败才重试：那时**请求帧从未送达 agent**，换一条连接重放
    // 是安全的（body 已整包在手，可重放）。**响应头超时（504）不在其中**——请求可能
    // 已在模型侧执行，重试会重复计费、重复生成，所以那条仍然直接把错误返回客户端：
    // 宁可报错，也不做不安全的重复。
    //
    // 实测（云端 2 vCPU、4 agent、768 并发）失败**全部**是 502（开流/写帧超时）、
    // 504 为 0，所以这条重试正好覆盖实际发生的失败。
    const MAX_TUNNEL_ATTEMPTS: usize = 2;
    let mut tried: Vec<usize> = Vec::with_capacity(MAX_TUNNEL_ATTEMPTS);
    let mut last_failure: Option<String> = None;

    let (entry, slot, mut recv, mut send) = loop {
        let acquired =
            state
                .registry
                .try_acquire_excluding(state.agent_stale_after, &model, &tried);
        let (mut entry, slot) = match acquired {
            Ok(x) => x,
            // 三种拒绝**必须分开记录**：它们的运维含义完全不同，而客户端看到的
            // 503/404/429 不足以区分。尤其"NoAgent"有两种成因——注册表空，或注册表里
            // 有人但全部心跳超时（stale）——只看状态码会把后者误判成"agent 掉了"。
            Err(
                reason @ (AcquireError::NoAgent | AcquireError::NoModel | AcquireError::AtCapacity),
            ) => {
                let st = state.registry.status(state.agent_stale_after);
                let why = match reason {
                    AcquireError::NoAgent if st.registered == 0 => "registry-empty",
                    AcquireError::NoAgent => "all-candidates-stale",
                    AcquireError::NoModel => "no-agent-serves-model",
                    _ => "all-candidates-at-capacity",
                };
                state.metrics.record_agent_rejection(why);
                warn!(
                    model = %model,
                    reason = why,
                    registered = st.registered,
                    healthy = st.healthy,
                    stale_after_secs = state.agent_stale_after.as_secs(),
                    oldest_last_seen_secs = st.oldest_last_seen_ago.map(|d| d.as_secs()),
                    "no agent to route to"
                );
                // 已经试过连接却挑不出下一条 → 把**真正的失败原因**（隧道错误）报给客户端，
                // 而不是报一个会误导的 503/404。
                if let Some(err) = last_failure {
                    state.metrics.record_tunnel_retry("no-alternative");
                    return error_response(
                        StatusCode::BAD_GATEWAY,
                        format!("{err}; no other agent available to retry"),
                    );
                }
                return match reason {
                    AcquireError::NoAgent => {
                        error_response(StatusCode::SERVICE_UNAVAILABLE, "no edge available")
                    }
                    AcquireError::NoModel => {
                        error_response(StatusCode::NOT_FOUND, "model not found on any agent")
                    }
                    AcquireError::AtCapacity => {
                        error_response(StatusCode::TOO_MANY_REQUESTS, "agent at capacity")
                    }
                };
            }
        };

        // 记下本次选中的连接：重试时不会再选它（否则重试没有意义）。
        tried.push(entry.stable_id);

        let stream = match open_tunnel(&mut entry, state.tunnel_op_timeout).await {
            Ok(s) => s,
            Err(failure) => {
                // 开流超时有两种成因，**不能用同一个动作处置**：
                //
                //   忙：这条连接的在途请求已经顶到它的承载上限（声明的 max_concurrency
                //       与端点流额度取小），开流是在排队等额度回收 → 排队超时是正常背压。
                //       此时摘除等于把"局部过载"升级成"整台 agent 下线"：连接被关 →
                //       agent 重连 → 注册表瞬间为空 → 期间所有请求 503。实测过一次
                //       30s 压测 +6835 次 registry-empty，根因就在这里。
                //   死：并没到承载上限却开不出流 → 没有任何排队理由，这才是坏连接。
                //
                // 所以只有"死"才摘除；"忙"只记指标 + 换下一条连接（重试逻辑与下面共用）。
                let busy = matches!(failure, OpenFailure::TimedOut)
                    && !entry.open_timeout_is_fatal(state.max_open_tunnel_streams);
                let err = failure.message();
                if busy {
                    state.metrics.record_tunnel_open_timeout("busy");
                    warn!(
                        request_id,
                        agent = %entry.agent_id,
                        inflight = entry.inflight.load(std::sync::atomic::Ordering::Relaxed),
                        max_concurrency = entry.max_concurrency,
                        stream_ceiling = state.max_open_tunnel_streams,
                        timeout_ms = state.tunnel_op_timeout.as_millis(),
                        "tunnel open timed out while agent is at capacity; not evicting, trying another agent"
                    );
                } else {
                    state.metrics.record_tunnel_open_timeout("dead");
                    warn!(
                        agent = %entry.agent_id,
                        timeout_ms = state.tunnel_op_timeout.as_millis(),
                        "tunnel open timed out; evicting agent"
                    );
                    // 打不开流 = 这条连接已经死了 → 摘掉条目（连续超时足够才会真摘），
                    // 然后换个 agent 重试；没有别的候选时把错误报给客户端。
                    state.registry.evict(entry.stable_id);
                }
                if tried.len() >= MAX_TUNNEL_ATTEMPTS {
                    state.metrics.record_tunnel_retry("failed");
                    return error_response(
                        if busy {
                            StatusCode::TOO_MANY_REQUESTS
                        } else {
                            StatusCode::BAD_GATEWAY
                        },
                        if busy {
                            "agent at capacity".to_string()
                        } else {
                            err
                        },
                    );
                }
                warn!(
                    request_id,
                    agent = %entry.agent_id,
                    error = %err,
                    "tunnel open failed; retrying on another agent"
                ); // "忙"不算隧道故障：不写进 last_failure，这样即使最后挑不出别的 agent，
                   // 客户端拿到的是"容量不足（429）"而不是误导性的"隧道坏了（502）"。
                   //
                   // 也**不**在这里记 agent_rejections——那个计数器统计的是"最终没被服务的请求"
                   // （按原因分）。这次重试可能成功，提前记会虚增容量告警；真正挑不出候选时，
                   // 下一轮 `try_acquire_excluding` 会自己记 `all-candidates-at-capacity`。
                if !busy {
                    last_failure = Some(err);
                }
                continue;
            }
        };
        let (recv, mut send) = stream.split();

        if let Err(e) = tunnel_write(
            &mut send,
            &request,
            state.tunnel_op_timeout,
            request_id,
            &entry.agent_id,
        )
        .await
        {
            state.registry.evict(entry.stable_id);
            if tried.len() >= MAX_TUNNEL_ATTEMPTS {
                state.metrics.record_tunnel_retry("failed");
                return error_response(StatusCode::BAD_GATEWAY, e);
            }
            warn!(
                request_id,
                agent = %entry.agent_id,
                error = %e,
                "request frame write failed; retrying on another agent"
            );
            last_failure = Some(e);
            continue;
        }

        if tried.len() > 1 {
            // 这次是重试成功的：对客户端是一次不可见的自愈。
            state.metrics.record_tunnel_retry("ok");
        }
        break (entry, slot, recv, send);
    };

    debug!(request_id, "proxying request to agent");

    // 读取响应头（用 head_timeout，不是 request_timeout）。
    //
    // 以前这里用 `state.timeout`（默认 120s）：agent 一旦卡住（注册着但什么都不回），
    // 每个请求都要把连接、并发槽位和缓冲区占满两分钟；客户端早就超时断开，而网关还停在
    // 读上，连"客户端已断开"都发现不了（实测 40 并发 → 620MB 内存被钉住、日志停更）。
    // 也不能用 `tunnel_op_timeout`（2s）：上游"思考"是合法的，本地模型 1–3s 很常见。
    let head = tokio::time::timeout(state.head_timeout, read_head(&mut recv)).await;
    let (status, mut out_headers) = match head {
        Ok(Ok(HeadOutcome::Head(s, h))) => {
            // 对端真的回了响应头 = 这条隧道是活的 → 清掉连续超时计数。
            // （开流成功不能作为判据：agent 卡死时流照样能开，只是永远不回帧。）
            state.registry.note_tunnel_op_ok(entry.stable_id);
            (s, h)
        }
        Ok(Ok(HeadOutcome::Error(code, message))) => {
            let _ = send.finish();
            return error_response(
                StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY),
                message,
            );
        }
        Ok(Err(e)) => {
            let _ = send.finish();
            return error_response(StatusCode::BAD_GATEWAY, format!("tunnel read failed: {e}"));
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
            let fatal = entry.head_timeout_is_fatal(state.head_alive_window);
            let last_head_ago_secs = (crate::registry::now_millis().saturating_sub(
                entry
                    .last_head_ok
                    .load(std::sync::atomic::Ordering::Relaxed),
            )) / 1000;
            if fatal {
                state.metrics.record_head_timeout("silent");
                warn!(
                    request_id,
                    agent = %entry.agent_id,
                    last_head_ago_secs,
                    window_secs = state.head_alive_window.as_secs(),
                    "upstream head timeout and the agent has been silent; evicting agent"
                );
                state.registry.evict(entry.stable_id);
            } else {
                state.metrics.record_head_timeout("slow");
                warn!(
                    request_id,
                    agent = %entry.agent_id,
                    last_head_ago_secs,
                    "upstream head timeout while the agent is still answering; not evicting"
                );
            }
            tunnel_cancel(&mut send, request_id, state.tunnel_op_timeout).await;
            let _ = send.finish();
            return error_response(StatusCode::GATEWAY_TIMEOUT, "upstream timed out");
        }
    };
    out_headers.retain(|(k, _)| !proto::headers::is_hop_by_hop(k.as_str()));

    // 流式回写响应体：后台任务把响应帧转进通道，HTTP 客户端从通道逐块读取。
    // 客户端断开（通道接收端被丢弃）→ 自动向 agent 发 Cancel，避免白算 token。
    // slot 守卫随任务结束释放，期间该请求计入 agent 在途并发。
    // usage 收集：提取上游 usage；无 usage（估算/取消/断流）→ 估算降级。
    let (tx, rx) = mpsc::channel::<Result<Bytes, String>>(32);
    let idle = state.timeout;
    let op_timeout = state.tunnel_op_timeout;
    let state_client_stall = state.client_stall;
    let metrics = state.metrics.clone();
    let key_store = state.key_store.clone();
    // 请求 body 的 prompt 估算（仅在无 usage 时使用）
    let prompt_est = crate::usage_meter::estimate_prompt_tokens(&body);
    // SSE 响应是流式（usage 在每个 chunk 尾部，逐块预过滤）；非 SSE 为整包 JSON
    let is_stream = out_headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.contains("text/event-stream"));
    tokio::spawn(async move {
        forward_body(
            &mut recv,
            &mut send,
            request_id,
            tx,
            idle,
            state_client_stall,
            op_timeout,
            slot,
            metrics,
            key_store,
            key.key_id,
            key.key_name,
            prompt_est,
            is_stream,
        )
        .await;
    });

    let mut builder = Response::builder().status(status);
    for (k, v) in out_headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(&v),
        ) {
            builder = builder.header(name, value);
        }
    }
    match builder.body(Body::from_stream(ReceiverStream::new(rx))) {
        Ok(resp) => resp,
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

enum HeadOutcome {
    Head(StatusCode, Vec<(String, String)>),
    Error(u16, String),
}

/// 读取响应头帧（或错误帧）。
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

/// 往客户端方向送一块的结果。三种情况处置完全不同，必须分开。
enum SendOutcome {
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

/// 带停滞超时地往客户端送一块。
///
/// 语义与请求体侧一致（见 `read_body_with_stall`）：**有进展就不超时**。客户端只要还在
/// 消费，通道就不会满，超时永远不会触发；只有"连着但一个字节都不取"才判定僵住。
async fn send_to_client(
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
#[allow(clippy::too_many_arguments)]
async fn forward_body(
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
) {
    let mut usage = UsageCollector::new(key_store, key_id, key_name, prompt_est, is_stream);
    loop {
        let frame = tokio::time::timeout(idle_timeout, read_frame(recv)).await;
        match frame {
            Ok(Ok(Some(Frame::ProxyResponseBody { chunk, .. }))) => {
                match send_to_client(&tx, Ok(Bytes::from(chunk.clone())), client_stall).await {
                    SendOutcome::Delivered => {}
                    SendOutcome::ClientGone => {
                        // 客户端已断开 → 取消上游；仍结算已转发部分
                        warn!(request_id, "client disconnected, cancelling upstream");
                        usage.observe(&chunk);
                        tunnel_cancel(send, request_id, op_timeout).await;
                        let _ = send.finish();
                        usage.finish();
                        return;
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
                        return;
                    }
                }
                usage.observe(&chunk);
                metrics.add_bytes_out(chunk.len());
            }
            Ok(Ok(Some(Frame::ProxyResponseEnd { .. }))) => {
                let _ = send.finish();
                usage.finish();
                return;
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
                return;
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
                return;
            }
            Ok(Err(e)) => {
                let _ = send_to_client(&tx, Err(format!("tunnel read failed: {e}")), client_stall)
                    .await;
                usage.finish();
                return;
            }
            Err(_) => {
                // 空闲超时 → 取消上游；结算已转发部分
                warn!(request_id, "upstream idle timeout, cancelling");
                let _ =
                    send_to_client(&tx, Err("upstream idle timeout".into()), client_stall).await;
                tunnel_cancel(send, request_id, op_timeout).await;
                let _ = send.finish();
                usage.finish();
                return;
            }
        }
    }
}

/// 过滤要放进隧道帧的头：剔除逐跳头**与调用方凭据**。
///
/// 凭据（`authorization` / `cookie`）只在「客户端 ↔ 网关」这一跳有意义：客户端持有的是
/// **网关签发**的 API key（对全部模型有效、能打公网网关），而 edge 与上游属于另一个信任域，
/// 三种上游（Ollama/vLLM/llama.cpp）又都不认证——透传零收益、纯风险：edge 一旦被攻破，
/// 攻击者白得一把可用的公网凭据，edge / 上游日志里还会留下吊销不掉的副本。
/// 上游确实需要认证时，应在 **agent 侧**配置上游自己的凭据。
///
/// 注意凭据**不是**逐跳头（RFC 语义上端到端），因此这里用两条独立规则，
/// 规则常量见 `proto::headers`。
fn filter_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(k, _)| {
            let name = k.as_str();
            !proto::headers::is_hop_by_hop(name) && !proto::headers::is_client_credential(name)
        })
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_headers_strips_hop_by_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        headers.insert("connection", HeaderValue::from_static("keep-alive"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("content-length", HeaderValue::from_static("42"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let out = filter_headers(&headers);
        let names: Vec<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"content-type"));
        for hop in proto::headers::HOP_BY_HOP {
            assert!(!names.contains(hop), "hop-by-hop header leaked: {hop}");
        }
    }

    /// 规格：调用方的凭据**不得**随隧道帧离开网关。
    ///
    /// 客户端用的是**网关签发**的 API key（对全部模型有效、能打公网网关），而 edge 与上游
    /// 属于另一个信任域：三种上游（Ollama/vLLM/llama.cpp）都不认证，透传零收益纯风险——
    /// edge 一旦被攻破，攻击者就白得一把可用的公网凭据；而且 edge / 上游日志里会留下
    /// 一份吊销不掉的副本。上游确实需要认证时，应在 agent 侧配置上游自己的凭据。
    #[test]
    fn filter_headers_never_forwards_client_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer sk-secret"),
        );
        headers.insert("cookie", HeaderValue::from_static("session=topsecret"));

        let out = filter_headers(&headers);
        let names: Vec<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"content-type"), "普通头照旧转发: {names:?}");
        assert!(
            !names.contains(&"authorization"),
            "网关自己的 API key 不得进入隧道帧: {names:?}"
        );
        assert!(
            !names.contains(&"cookie"),
            "客户端 cookie 同样不得进入隧道帧: {names:?}"
        );
        // 值也不得出现在帧里（防「改了头名但仍漏出」）
        let joined: String = out
            .iter()
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
            .join("|");
        assert!(
            !joined.contains("sk-secret") && !joined.contains("topsecret"),
            "凭据值不得出现在隧道帧里: {joined}"
        );
    }

    #[test]
    fn extract_model_reads_top_level_field() {
        // 正常：字符串 model
        assert_eq!(
            extract_model(br#"{"model":"qwen2.5","messages":[]}"#).unwrap(),
            "qwen2.5"
        );
        // model 是嵌套路径中的字段（不应误取）
        assert!(extract_model(br#"{"messages":[{"role":"user","content":"model?"}]}"#).is_err());
        // 缺失 model → Err（调用方返回 400）
        assert!(extract_model(br#"{"messages":[]}"#).is_err());
        // model 非字符串 → Err
        assert!(extract_model(br#"{"model":123}"#).is_err());
        // 空串 → Err
        assert!(extract_model(br#"{"model":""}"#).is_err());
        // 非法 JSON → Err
        assert!(extract_model(b"not json").is_err());
    }
}
