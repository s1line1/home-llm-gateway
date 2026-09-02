//! 代理转发：认证 → 限流 → 编码为隧道帧转发（从 http.rs 拆分，保持路由层精简）。

use std::time::Duration;

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use proto::{
    io::{read_frame, write_frame},
    Frame,
};
use serde_json::json;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

use crate::http::AppState;
use crate::keystore::UsageDelta;
use crate::registry::AcquireError;

static NEXT_REQUEST_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({ "error": { "message": message.into(), "type": "gateway_error" } })),
    )
        .into_response()
}

/// 校验 Bearer API Key（静态或动态 key）；通过时返回 (key_id, key_name, token)。
/// key_id 用于用量计量；token 用作限流 key。
fn api_key<'a>(state: &AppState, headers: &'a HeaderMap) -> Option<(&'a str, String, String)> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?;
    let token = value.to_str().ok()?.strip_prefix("Bearer ")?;
    let record = state.key_store.authorize_record(token)?;
    Some((token, record.id, record.name))
}

/// 认证 + 限流（/v1/* 统一入口，含 /v1/models 聚合路由）。
/// 认证失败 → Some(401)；限流失败 → Some(429)；通过 → None。
pub fn auth_and_rate_limit(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    let Some((token, _id, _name)) = api_key(state, headers) else {
        return Some(error_response(
            StatusCode::UNAUTHORIZED,
            "invalid or missing API key",
        ));
    };
    if let Some(rl) = &state.rate_limiter {
        if !rl.try_acquire(token) {
            return Some(error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded",
            ));
        }
    }
    None
}

/// 从请求 body 提取路由所需模型：顶层 `model` 字段（OpenAI 兼容语义，必填）。
/// 缺失 / 非字符串 / 空串 → Err（调用方返回 400）。
fn extract_model(body: &[u8]) -> Result<String, ()> {
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| ())?;
    match value.get("model") {
        Some(serde_json::Value::String(s)) if !s.is_empty() => Ok(s.clone()),
        _ => Err(()),
    }
}

pub async fn proxy(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // 认证：同时拿到 key_id/key_name（用量计量）与 token（限流）
    let Some((token, key_id, key_name)) = api_key(&state, &headers) else {
        return error_response(StatusCode::UNAUTHORIZED, "invalid or missing API key");
    };
    if let Some(rl) = &state.rate_limiter {
        if !rl.try_acquire(token) {
            return error_response(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
        }
    }
    // 路由需要模型：按请求 model 挑选能服务它的 agent（见 MODEL_ROUTING.md）
    let model = match extract_model(&body) {
        Ok(m) => m,
        Err(()) => {
            return error_response(StatusCode::BAD_REQUEST, "model is required in request body")
        }
    };
    let (entry, slot) = match state.registry.try_acquire(state.agent_stale_after, &model) {
        Ok(x) => x,
        Err(AcquireError::NoAgent) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "no edge available");
        }
        Err(AcquireError::NoModel) => {
            return error_response(StatusCode::NOT_FOUND, "model not found on any agent");
        }
        Err(AcquireError::AtCapacity) => {
            return error_response(StatusCode::TOO_MANY_REQUESTS, "agent at capacity");
        }
    };

    // 保留原始完整路径（如 /v1/chat/completions），原样转发给上游
    let path = match uri.query() {
        Some(q) => format!("{}?{q}", uri.path()),
        None => uri.path().to_string(),
    };
    let request_id = NEXT_REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let (mut send, mut recv) = match entry.conn.open_bi().await {
        Ok(s) => s,
        Err(e) => {
            return error_response(StatusCode::BAD_GATEWAY, format!("tunnel open failed: {e}"))
        }
    };
    let request = Frame::ProxyRequest {
        request_id,
        method: method.to_string(),
        path,
        headers: filter_headers(&headers),
        body: body.to_vec(),
    };
    if let Err(e) = write_frame(&mut send, &request).await {
        return error_response(StatusCode::BAD_GATEWAY, format!("tunnel write failed: {e}"));
    }
    debug!(request_id, "proxying request to agent");

    // 读取响应头（带空闲超时）
    let head = tokio::time::timeout(state.timeout, read_head(&mut recv)).await;
    let (status, mut out_headers) = match head {
        Ok(Ok(HeadOutcome::Head(s, h))) => (s, h),
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
            warn!(request_id, "upstream head timeout, sending cancel");
            let _ = write_frame(&mut send, &Frame::Cancel { request_id }).await;
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
    let metrics = state.metrics.clone();
    let key_store = state.key_store.clone();
    // 请求 body 的 prompt 估算（仅在无 usage 时使用）
    let prompt_est = crate::usage::estimate_prompt_tokens(&body);
    // SSE 响应是流式（usage 在每个 chunk 尾部，逐块预过滤）；非 SSE 为整包 JSON
    let is_stream = out_headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.contains("text/event-stream"));
    tokio::spawn(async move {
        forward_body(
            &mut recv, &mut send, request_id, tx, idle, slot, metrics, key_store, key_id, key_name,
            prompt_est, is_stream,
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
async fn read_head(recv: &mut quinn::RecvStream) -> anyhow::Result<HeadOutcome> {
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

/// 请求级 usage 收集：SSE 流式逐块预过滤提取；非流式缓冲到 End 后整包解析；
/// 均拿不到 usage（上游未提供 / 取消 / 断流）→ 估算并标记。
struct UsageCollector {
    key_store: crate::keystore::KeyStore,
    key_id: String,
    key_name: String,
    /// 请求 body 的 prompt 估算（无 usage 时的 prompt 降级）。
    prompt_est: u64,
    /// SSE（content-type: text/event-stream）。
    is_stream: bool,
    /// 已提取的 usage（精确来源；流式多次出现取最后一次）。
    extracted: Option<crate::usage::ExtractedUsage>,
    /// 非流式整包缓冲。
    buf: Vec<u8>,
    /// 已转发字节（估算 completion 用）。
    bytes_forwarded: u64,
    /// 是否已记录（防止提前返回路径重复记录）。
    recorded: bool,
}

impl UsageCollector {
    fn new(
        key_store: crate::keystore::KeyStore,
        key_id: String,
        key_name: String,
        prompt_est: u64,
        is_stream: bool,
    ) -> Self {
        Self {
            key_store,
            key_id,
            key_name,
            prompt_est,
            is_stream,
            extracted: None,
            buf: Vec::new(),
            bytes_forwarded: 0,
            recorded: false,
        }
    }

    /// 每块转发后调用：记录字节、尝试提取 usage。
    fn observe(&mut self, chunk: &[u8]) {
        self.bytes_forwarded += chunk.len() as u64;
        if self.is_stream {
            if let Some(d) = crate::usage::extract_usage(chunk) {
                self.extracted = Some(d);
            }
        } else if self.buf.len() < 32 * 1024 * 1024 {
            // 非流式：整包缓冲（End 后统一解析），避免 JSON 跨块时 usage 被切开。
            // 超 32MiB 停止缓冲（防御性；usage 通常尾随，丢失则估算降级）
            self.buf.extend_from_slice(chunk);
        }
    }

    /// 响应结束（End / 断流 / 超时 / 客户端断开）：结算用量并记录。
    fn finish(mut self) {
        if self.recorded {
            return;
        }
        self.recorded = true;
        let delta = self.resolve_delta();
        self.key_store
            .record_usage(&self.key_id, &self.key_name, &delta);
    }

    fn resolve_delta(&mut self) -> UsageDelta {
        // 非流式：整包缓冲，End 后统一解析（避免 JSON 跨块切到 usage 字段）
        if !self.is_stream {
            if let Some(d) = crate::usage::extract_usage(&self.buf) {
                self.extracted = Some(d);
            }
        }
        match &self.extracted {
            Some(d) => UsageDelta {
                prompt_tokens: d.prompt_tokens,
                completion_tokens: d.completion_tokens,
                estimated: false,
            },
            None => {
                // 估算降级（标记 estimated）：prompt 按请求体估算；
                // completion 按已转发字节 / 4（取消/断流/无 usage 上游均适用）
                let completion = self.bytes_forwarded.div_ceil(4);
                UsageDelta {
                    prompt_tokens: self.prompt_est,
                    completion_tokens: completion.max(1),
                    estimated: true,
                }
            }
        }
    }
}

/// 把响应体帧流转发到通道；任一端关闭时向对端发 Cancel。
/// `slot` 持有期间占用 agent 并发槽位，随任务结束释放。
#[allow(clippy::too_many_arguments)]
async fn forward_body(
    recv: &mut quinn::RecvStream,
    send: &mut quinn::SendStream,
    request_id: u64,
    tx: mpsc::Sender<Result<Bytes, String>>,
    idle_timeout: Duration,
    _slot: crate::registry::SlotGuard,
    metrics: crate::metrics::Metrics,
    key_store: crate::keystore::KeyStore,
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
                if tx.send(Ok(Bytes::from(chunk.clone()))).await.is_err() {
                    // 客户端已断开 → 取消上游；仍结算已转发部分
                    warn!(request_id, "client disconnected, cancelling upstream");
                    usage.observe(&chunk);
                    let _ = write_frame(send, &Frame::Cancel { request_id }).await;
                    let _ = send.finish();
                    usage.finish();
                    return;
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
                let _ = tx
                    .send(Err(format!("upstream error {code}: {message}")))
                    .await;
                let _ = send.finish();
                usage.finish();
                return;
            }
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) => {
                let _ = tx
                    .send(Err("upstream closed the stream early".into()))
                    .await;
                usage.finish();
                return;
            }
            Ok(Err(e)) => {
                let _ = tx.send(Err(format!("tunnel read failed: {e}"))).await;
                usage.finish();
                return;
            }
            Err(_) => {
                // 空闲超时 → 取消上游；结算已转发部分
                warn!(request_id, "upstream idle timeout, cancelling");
                let _ = tx.send(Err("upstream idle timeout".into())).await;
                let _ = write_frame(send, &Frame::Cancel { request_id }).await;
                let _ = send.finish();
                usage.finish();
                return;
            }
        }
    }
}

fn filter_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(k, _)| !proto::headers::is_hop_by_hop(k.as_str()))
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
        headers.insert("authorization", HeaderValue::from_static("Bearer sk-test"));

        let out = filter_headers(&headers);
        let names: Vec<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"content-type"));
        assert!(names.contains(&"authorization"));
        for hop in proto::headers::HOP_BY_HOP {
            assert!(!names.contains(hop), "hop-by-hop header leaked: {hop}");
        }
        // 值原样保留
        let auth = out.iter().find(|(k, _)| k == "authorization").unwrap();
        assert_eq!(auth.1, "Bearer sk-test");
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
