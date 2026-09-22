//! 代理转发：认证 → 限流 → 编码为隧道帧转发（从 `http` 模块拆出，保持路由层精简）。

mod forward;
mod head;
mod routing;
mod tunnel;
mod usage;

use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::Response,
};
use proto::Frame;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

use crate::body::{read_body_with_stall, BodyRead, MAX_REQUEST_BODY};
use crate::openai::error_response;
use crate::{auth::authenticate, state::AppState};
use forward::forward_body;

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
    //
    // 判据本身在 `proto::path::safe_upstream_path`——**与 agent 侧共享同一份实现**：同一条
    // 规则的两道防线（这里拒一次、agent 拼上游 URL 前再拒一次），两份实现会漂移，而漂移的
    // 方向恰好会是"后面那道更松"，纵深防御就静默失效了。网关这一步管的是**越权请求的
    // 状态码**（客户端拿 400），agent 那一步管的是**隧道另一端不再受信时的兜底**。
    // 详见 `PROJECT_SCAN` P1-2。
    let Some(guarded_path) = proto::path::safe_upstream_path(uri.path()) else {
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

    // 读取响应头：超时窗口、慢/死判据的渲染、Cancel 与 finish 全在 `head` 模块里
    // （一处改动理由 = 上游响应头契约），这里只把失败渲染成响应。
    let (status, mut out_headers) =
        match head::await_head(&state, &mut recv, &mut send, &entry, request_id).await {
            Ok(v) => v,
            Err(failure) => return error_response(failure.status, failure.message),
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
