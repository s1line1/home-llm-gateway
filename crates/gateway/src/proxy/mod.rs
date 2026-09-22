//! 代理转发：认证 → 限流 → 编码为隧道帧转发（从 `http` 模块拆出，保持路由层精简）。

mod forward;
mod routing;
mod tunnel;
mod usage;

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

use crate::body::{read_body_with_stall, BodyRead, MAX_REQUEST_BODY};
use crate::openai::error_response;
use crate::{auth::authenticate, state::AppState};
use forward::forward_body;
use tunnel::tunnel_cancel;

/// 从请求 body 提取路由所需模型：顶层 `model` 字段（OpenAI 兼容语义，必填）。
/// 缺失 / 非字符串 / 空串 → Err（调用方返回 400）。
fn extract_model(body: &[u8]) -> Result<String, ()> {
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| ())?;
    match value.get("model") {
        Some(serde_json::Value::String(s)) if !s.is_empty() => Ok(s.clone()),
        _ => Err(()),
    }
}

/// 入站路径是否可以**原样转发给上游**；不安全 → `None`（调用方回 400）。
///
/// 为什么必须自己判：`uri.path()` 是**原样**的（HTTP/1.1 与 h2 都不做点段归一），而 agent
/// 把它拼到上游 base 之后才交给 URL 解析器——WHATWG 归一的那一刻，`/v1/../api/delete`
/// 就变成 `/api/delete`。**持 key 者因此能驱动上游任意端点**（Ollama 的 `/api/delete`
/// 直接删模型），`PROJECT_SCAN` P1-2 记录了这一条；修复前 e2e 实测网关确实把该路径转发
/// 了出去（上游回 404，因为归一后是它不认识的 `/api/delete`）。
///
/// 判据是**保守拒绝**，而不是"归一后转发"：归一等于替客户端改写语义，而且拦不住
/// `%2e%2e` / `%2f` 这类**由上游解码**的形态（URL 归一不解码百分号编码，上游却可能解码）。
/// 拒绝：不以 `/v1/` 开头、任一段为空 / `.` / `..`、路径含 `\`（WHATWG 在 http 下把 `\`
/// 当 `/`）或 `%2e`/`%2f`/`%5c`（大小写不敏感）。
///
/// 只判**路径**、不判 query：点段放不进 query，而 query 里合法地出现 `%2e` 是可能的。
fn safe_upstream_path(path: &str) -> Option<&str> {
    if !path.starts_with("/v1/") {
        return None;
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains('\\')
        || lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return None;
    }
    if path
        .split('/')
        .skip(1)
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return None;
    }
    Some(path)
}

pub async fn proxy(State(state): State<AppState>, req: Request) -> Response {
    // 先取 method/uri/headers，body 留到**认证之后再读**：
    // 以前 `Bytes` 是提取器，于是未认证的请求也能让网关先缓冲 16MB（认证在 handler 里，
    // 比提取器晚一步）。现在认证在最前，读 body 在后，顺带把这个放大面收掉。
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    // 隧道 id 与 HTTP 层同源（crate::request_id）：middleware 已把规范化的 req-{n}
    // 写回入站 headers，UUID 客户端也不例外，于是两边不会再各自计数、周期性撞号。
    let request_id = crate::request_id::tunnel_id_from_headers(&headers);

    // 认证 + 限流（per-key 令牌桶）：拿不到身份的唯一出路就是把它还给客户端。
    let key = match authenticate(&state, &headers).await {
        Ok(key) => key,
        Err(rejection) => return rejection.into_response(),
    };

    // 路径守卫：**认证之后、读 body 之前**。放在这里有两个理由：① 未认证的探测拿不到
    // 路径校验的信息（先 401）；② 越权路径不必先让我们读进 16MiB 的 body。
    // 详见 [`safe_upstream_path`] 与 `PROJECT_SCAN` P1-2。
    let Some(guarded_path) = safe_upstream_path(uri.path()) else {
        warn!(
            request_id,
            path = %uri.path(),
            "rejecting request: path cannot be forwarded safely (dot segment, backslash or encoded separator)"
        );
        return error_response(StatusCode::BAD_REQUEST, "invalid request path");
    };
    // 通过守卫之后才拼 query：原样转发（query 不参与点段判定）
    let path = match uri.query() {
        Some(q) => format!("{guarded_path}?{q}"),
        None => guarded_path.to_string(),
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
    // request_id 在函数最开头就算好了（因为它要出现在"读 body 停滞"这类早期日志里）。
    // 隧道 request_id 与 HTTP 层 x-request-id 同源（crate::request_id）：
    // middleware 注入规范化的 req-{n}，本函数沿用它，响应头/日志/隧道帧三方同一个数字。
    // 请求帧在选路之前就构造好：重试换的是连接，请求内容不变（body 已整包在手，可重放）。
    let request = Frame::ProxyRequest {
        request_id,
        method: method.to_string(),
        path,
        headers: filter_headers(&headers),
        body: body.to_vec(),
    };

    let (entry, slot, mut recv, mut send) =
        match routing::open_and_send(&state, &model, &request, request_id).await {
            Ok(routed) => routed,
            Err(failure) => return error_response(failure.status, failure.message),
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
            state.registry.note_tunnel_op_ok(entry.stable_id());
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
            //
            // 这条判据由注册表给出（判定与记账、摘除在同一处），本模块只把它映射成
            // 指标标签与日志文案——那些是外部契约，留在原处。
            //
            // 判据有**两层**（第二层见评估 §5 H2）：窗口内有过成功响应头 → 只是慢；
            // 窗口过了但**对端还在说话**（心跳新鲜）且静默没超过 `head_silent_grace` → 仍算慢。
            // 第二层不可省：`last_head_ok` 的唯一刷新点就是成功响应头，所以当**所有**请求都慢过
            // `head_timeout` 时没有任何一次成功能刷新它，只按第一层就会误摘活着的 agent。
            let disposition = state.registry.report_head_timeout(
                &entry,
                crate::registry::HeadSilence {
                    window: state.head_alive_window,
                    peer_alive_window: state.agent_stale_after,
                    stuck_after: state.head_silent_grace,
                },
                state.evict_close_grace,
            );
            let last_head_ago_secs = entry.last_head_ago().map_or(0, |d| d.as_secs());
            if matches!(disposition, crate::registry::Disposition::Fatal) {
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
    // 关闭阶段的接收端：`Terminating` 时这条流要带一个明确事件收尾（见 `forward.rs`）。
    let shutdown = state.subscribe_shutdown();
    // 请求 body 的 prompt 估算（仅在无 usage 时使用）
    let prompt_est = crate::usage_meter::estimate_prompt_tokens(&body);
    // SSE 响应是流式（usage 在每个 chunk 尾部，逐块预过滤）；非 SSE 为整包 JSON
    let is_stream = out_headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.contains("text/event-stream"));
    tokio::spawn(async move {
        let end = forward_body(
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
            shutdown,
        )
        .await;
        debug!(request_id, end = ?end, "response forwarding finished");
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

    /// 规格（`PROJECT_SCAN` P1-2）：只有"原样转发不会越权"的路径才放行。
    ///
    /// 拒绝面比"含 `..`"宽：`%2e`/`%2f`/`%5c` 由上游解码才成点段/分隔符，`\` 在 WHATWG
    /// 的 http 下本身就被当成 `/`——这几种都能构造出同一类越权，所以一起拒。
    #[test]
    fn safe_upstream_path_allows_only_verbatim_forwardable_paths() {
        for ok in [
            "/v1/chat/completions",
            "/v1/models",
            "/v1/embeddings",
            "/v1/a/b-c_d.e",
            "/v1/..hidden", // 以点开头但不是点段
        ] {
            assert_eq!(safe_upstream_path(ok), Some(ok), "{ok} 应当放行");
        }
        for bad in [
            "/v1/../api/delete", // e2e 里实测被转发过的 PoC
            "/v1/../../etc/passwd",
            "/v1/./models",
            "/v1//models",
            "/v1/",
            "/v1",          // 不在 `/v1/` 之下（前缀判定）
            "/api/delete",  // 越出 `/v1/`
            "/v2/chat",     // 邻近前缀不算
            "/v1/%2e%2e/x", // 上游解码后是 `..`
            "/v1/%2E%2E/x", // 大小写
            "/v1/%2fapi",   // 上游解码后是分隔符
            "/v1/a%5Cb",    // 编码的反斜杠
            "/v1/a\\..\\b", // WHATWG 在 http 下把 `\` 当 `/`
        ] {
            assert!(safe_upstream_path(bad).is_none(), "{bad} 必须被拒");
        }
    }
}
