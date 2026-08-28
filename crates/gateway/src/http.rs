//! 公网 HTTP 入口：认证 → 路由 → 编码为隧道帧转发。

use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use proto::{io::{read_frame, write_frame}, Frame};
use serde_json::json;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tower_http::services::{ServeDir, ServeFile};
use tracing::{debug, info, warn};

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
    /// React UI 静态目录（None = `/` 显示构建提示页）。
    pub ui: Option<PathBuf>,
}

pub fn app(state: AppState) -> Router {
    let mut router = Router::new()
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
    // React UI 静态托管：存在时 `/` 返回 Dashboard，未命中的路径（SPA 前端路由，
    // 如 /keys、/metrics 的浏览器直接访问/刷新）fallback 到 index.html。
    // API 路由（/v1/*、/admin/*、/healthz、/metrics）已在上方注册，优先级更高。
    match &state.ui {
        Some(dir) => {
            let ui = ServeDir::new(dir)
                .append_index_html_on_directories(true)
                .fallback(ServeFile::new(dir.join("index.html")));
            router = router.fallback_service(ui);
            info!(path = %dir.display(), "serving web UI from disk");
        }
        None => {
            router = router.route("/", get(ui_missing));
        }
    }
    router
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), metrics_middleware))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

/// UI 未构建（ui_dir 缺失）时的占位提示页——不再内嵌任何管理功能。
async fn ui_missing() -> Html<&'static str> {
    Html(UI_MISSING)
}

const UI_MISSING: &str = r#"<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Home LLM Gateway</title>
<style>
  body { font-family: system-ui, -apple-system, "PingFang SC", sans-serif; max-width: 640px; margin: 64px auto; padding: 0 16px; line-height: 1.6; color: #1f2937; }
  code { background: #f1f5f9; padding: 1px 6px; border-radius: 4px; }
</style>
</head>
<body>
<h1>Home LLM Gateway</h1>
<p>Web 管理面板尚未构建。构建前端后配置 <code>ui_dir</code> 并重启网关：</p>
<pre>cd web &amp;&amp; pnpm install &amp;&amp; pnpm build</pre>
<p>API 端点（<code>/v1/*</code>、<code>/admin/*</code>、<code>/metrics</code>、<code>/healthz</code>）不受影响。</p>
</body>
</html>"#;

async fn healthz() -> &'static str {
    "ok"
}

/// Prometheus 文本格式指标。
/// 浏览器直接访问/刷新（`Accept: text/html`）时返回 SPA 页面，让前端路由渲染指标页；
/// Prometheus 抓取与前端解析（`Accept: */*`）仍拿到文本。
async fn metrics_route(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let wants_html = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false);
    if wants_html {
        if let Some(dir) = &state.ui {
            if let Ok(html) = std::fs::read_to_string(dir.join("index.html")) {
                return Html(html).into_response();
            }
        }
    }
    state.metrics.render(state.registry.len()).into_response()
}

/// 记录请求状态码与耗时（/metrics 自身不计入）。
async fn metrics_middleware(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if req.uri().path() == "/metrics" {
        return next.run(req).await;
    }
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let start = state.metrics.record_start();
    let resp = next.run(req).await;
    let status = resp.status().as_u16();
    state.metrics.record_end(start, status);
    info!(
        method = %method,
        path = %path,
        status,
        duration_ms = start.elapsed().as_millis() as u64,
        "request handled"
    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    use crate::{
        keystore::KeyStore,
        metrics::Metrics,
        ratelimit::RateLimiter,
        registry::Registry,
    };

    fn test_state(ui: Option<PathBuf>) -> AppState {
        AppState {
            registry: Registry::default(),
            key_store: KeyStore::new(None),
            admin_token: None,
            timeout: Duration::from_secs(10),
            agent_stale_after: Duration::from_secs(10),
            rate_limiter: RateLimiter::new(0),
            metrics: Metrics::default(),
            ui,
        }
    }

    fn headers_with_accept(accept: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::ACCEPT, HeaderValue::from_str(accept).unwrap());
        h
    }

    async fn body_str(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        String::from_utf8_lossy(&bytes).to_string()
    }

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
        for hop in HOP_BY_HOP {
            assert!(!names.contains(hop), "hop-by-hop header leaked: {hop}");
        }
        // 值原样保留
        let auth = out.iter().find(|(k, _)| k == "authorization").unwrap();
        assert_eq!(auth.1, "Bearer sk-test");
    }

    #[tokio::test]
    async fn metrics_browser_request_serves_spa() {
        // 浏览器（Accept: text/html）直接访问 /metrics → SPA 页面
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<div id=\"root\">ui</div>").unwrap();
        let state = test_state(Some(dir.path().to_path_buf()));

        let resp = metrics_route(State(state.clone()), headers_with_accept("text/html")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_str(resp).await.contains("id=\"root\""), "browser should get the SPA");

        // 未配 ui_dir 时降级为 Prometheus 文本
        let state2 = test_state(None);
        let resp = metrics_route(State(state2.clone()), headers_with_accept("text/html")).await;
        assert!(body_str(resp).await.contains("hlmg_requests_total"));
    }

    #[tokio::test]
    async fn metrics_scraper_gets_prometheus_text() {
        // Prometheus 抓取 / 前端 fetch（Accept: */* 或无 Accept）→ 文本
        let state = test_state(None);
        let resp = metrics_route(State(state.clone()), headers_with_accept("*/*")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let text = body_str(resp).await;
        assert!(text.contains("# TYPE hlmg_requests_total counter"));
        assert!(text.contains("hlmg_agents"));
    }
}
