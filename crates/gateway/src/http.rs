//! 公网 HTTP 入口：认证 → 路由 → 编码为隧道帧转发。

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use proto::{io::{read_frame, write_frame}, Frame};
use serde_json::json;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

use crate::keystore::KeyStore;
use crate::metrics::Metrics;
use crate::ratelimit::RateLimiter;
use crate::registry::{AcquireError, Registry};

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// 逐跳头，转发时剔除。
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

#[derive(Clone)]
pub struct AppState {
    pub registry: Registry,
    pub key_store: KeyStore,
    /// Admin token（None 表示不启用 /admin/*）。
    pub admin_token: Option<String>,
    pub timeout: Duration,
    pub agent_stale_after: Duration,
    pub rate_limiter: Option<RateLimiter>,
    pub metrics: Metrics,
}

pub fn app(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/", get(crate::admin::admin_page))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics_route))
        .route(
            "/v1/{*rest}",
            get(proxy).post(proxy).put(proxy).delete(proxy).patch(proxy),
        );
    if state.admin_token.is_some() {
        let admin = Router::new()
            .route("/keys", get(crate::admin::list_keys).post(crate::admin::create_key))
            .route("/keys/{id}", axum::routing::delete(crate::admin::delete_key))
            .route_layer(middleware::from_fn_with_state(state.clone(), crate::admin::admin_auth));
        router = router.nest("/admin", admin);
    }
    router
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), metrics_middleware))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

/// Prometheus 文本格式指标。
async fn metrics_route(State(state): State<AppState>) -> String {
    state.metrics.render(state.registry.len())
}

/// 记录请求状态码与耗时（/metrics 自身不计入）。
async fn metrics_middleware(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if req.uri().path() == "/metrics" {
        return next.run(req).await;
    }
    let start = state.metrics.record_start();
    let resp = next.run(req).await;
    let status = resp.status().as_u16();
    state.metrics.record_end(start, status);
    resp
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({ "error": { "message": message.into(), "type": "gateway_error" } })),
    )
        .into_response()
}

/// 校验 Bearer API Key（静态或动态 key）；通过时返回原始 token（用作限流 key）。
fn api_key<'a>(state: &AppState, headers: &'a HeaderMap) -> Option<&'a str> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?;
    let token = value.to_str().ok()?.strip_prefix("Bearer ")?;
    state.key_store.authorize(token).then_some(token)
}

async fn proxy(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(token) = api_key(&state, &headers) else {
        return error_response(StatusCode::UNAUTHORIZED, "invalid or missing API key");
    };
    if let Some(rl) = &state.rate_limiter {
        if !rl.try_acquire(token) {
            return error_response(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
        }
    }
    let (entry, slot) = match state.registry.try_acquire(state.agent_stale_after) {
        Ok(x) => x,
        Err(AcquireError::NoAgent) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "no home agent available");
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
    let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);

    let (mut send, mut recv) = match entry.conn.open_bi().await {
        Ok(s) => s,
        Err(e) => return error_response(StatusCode::BAD_GATEWAY, format!("tunnel open failed: {e}")),
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
    out_headers.retain(|(k, _)| !HOP_BY_HOP.contains(&k.as_str()));

    // 流式回写响应体：后台任务把响应帧转进通道，HTTP 客户端从通道逐块读取。
    // 客户端断开（通道接收端被丢弃）→ 自动向 agent 发 Cancel，避免白算 token。
    // slot 守卫随任务结束释放，期间该请求计入 agent 在途并发。
    let (tx, rx) = mpsc::channel::<Result<Bytes, String>>(32);
    let idle = state.timeout;
    let metrics = state.metrics.clone();
    tokio::spawn(async move {
        forward_body(&mut recv, &mut send, request_id, tx, idle, slot, metrics).await;
    });

    let mut builder = Response::builder().status(status);
    for (k, v) in out_headers {
        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&v)) {
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
            Some(Frame::ProxyResponseHead { status: s, headers: h, .. }) => {
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
                return Ok(HeadOutcome::Error(502, "upstream closed before responding".into()));
            }
        }
    }
}

/// 把响应体帧流转发到通道；任一端关闭时向对端发 Cancel。
/// `_slot` 持有期间占用 agent 并发槽位，随任务结束释放。
async fn forward_body(
    recv: &mut quinn::RecvStream,
    send: &mut quinn::SendStream,
    request_id: u64,
    tx: mpsc::Sender<Result<Bytes, String>>,
    idle_timeout: Duration,
    _slot: crate::registry::SlotGuard,
    metrics: Metrics,
) {
    loop {
        let frame = tokio::time::timeout(idle_timeout, read_frame(recv)).await;
        match frame {
            Ok(Ok(Some(Frame::ProxyResponseBody { chunk, .. }))) => {
                if tx.send(Ok(Bytes::from(chunk.clone()))).await.is_err() {
                    // 客户端已断开 → 取消上游
                    warn!(request_id, "client disconnected, cancelling upstream");
                    let _ = write_frame(send, &Frame::Cancel { request_id }).await;
                    let _ = send.finish();
                    return;
                }
                metrics.add_bytes_out(chunk.len());
            }
            Ok(Ok(Some(Frame::ProxyResponseEnd { .. }))) => {
                let _ = send.finish();
                return;
            }
            Ok(Ok(Some(Frame::Error { code, message, .. }))) => {
                let _ = tx.send(Err(format!("upstream error {code}: {message}"))).await;
                let _ = send.finish();
                return;
            }
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) => {
                let _ = tx.send(Err("upstream closed the stream early".into())).await;
                return;
            }
            Ok(Err(e)) => {
                let _ = tx.send(Err(format!("tunnel read failed: {e}"))).await;
                return;
            }
            Err(_) => {
                // 空闲超时 → 取消上游
                warn!(request_id, "upstream idle timeout, cancelling");
                let _ = tx.send(Err("upstream idle timeout".into())).await;
                let _ = write_frame(send, &Frame::Cancel { request_id }).await;
                let _ = send.finish();
                return;
            }
        }
    }
}

fn filter_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(k, _)| !HOP_BY_HOP.contains(&k.as_str()))
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}
