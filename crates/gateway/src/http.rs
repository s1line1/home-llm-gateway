//! 公网 HTTP 入口：认证 → 路由 → 编码为隧道帧转发。

use std::{path::PathBuf, time::Duration};

use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, StatusCode, Uri},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::json;
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};
use tracing::{info, warn};

use crate::keystore::KeyStore;
use crate::metrics::Metrics;
use crate::ratelimit::RateLimiter;
use crate::registry::Registry;

#[derive(Clone)]
pub struct AppState {
    pub registry: Registry,
    pub key_store: KeyStore,
    /// Admin token（None 表示不启用 /admin/*）。
    pub admin_token: Option<String>,
    pub timeout: Duration,
    pub agent_stale_after: Duration,
    pub rate_limiter: Option<RateLimiter>,
    /// HTTP 全局在途请求上限（0 = 不限；per-key 限流之外的总闸门）。
    pub max_concurrent_requests: u32,
    pub metrics: Metrics,
    /// React UI 静态目录（None = `/` 显示构建提示页）。
    pub ui: Option<PathBuf>,
}

pub fn app(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics_route))
        // /v1/models 是静态路径，优先于下方 /v1/{*rest}（matchit 规则）：
        // GET 由网关聚合回答，不再透传单台 agent。
        .route("/v1/models", get(models_route))
        .route(
            "/v1/{*rest}",
            get(crate::http_proxy::proxy)
                .post(crate::http_proxy::proxy)
                .put(crate::http_proxy::proxy)
                .delete(crate::http_proxy::proxy)
                .patch(crate::http_proxy::proxy),
        );
    if state.admin_token.is_some() {
        let admin = Router::new()
            .route(
                "/keys",
                get(crate::admin::list_keys).post(crate::admin::create_key),
            )
            .route(
                "/keys/{id}",
                axum::routing::delete(crate::admin::delete_key),
            )
            .route("/agents", get(crate::admin::list_agents))
            .route("/usage", get(crate::admin::usage_route))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                crate::admin::admin_auth,
            ));
        router = router.nest("/admin", admin);
    }
    // React UI 静态托管：存在时 `/` 返回 Dashboard，未命中的路径（SPA 前端路由，
    // 如 /keys、/metrics 的浏览器直接访问/刷新）fallback 到 index.html。
    // 注意：API 类未注册路径（无 Accept: text/html、无文件扩展名）返回真 404，
    //       不能被 SPA fallback 吞成 index.html（否则前端拿到的不是合法 JSON）。
    match &state.ui {
        Some(dir) => {
            router = router.fallback(ui_fallback);
            info!(path = %dir.display(), "serving web UI from disk");
        }
        None => {
            router = router.route("/", get(ui_missing));
        }
    }
    router
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            metrics_middleware,
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

/// SPA fallback：浏览器导航（Accept: text/html）→ index.html；静态资源
/// （带扩展名路径，如 /assets/*.js）→ 文件；其余（API 类未注册路径）→ 404。
async fn ui_fallback(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    // 仅在 ui_dir 配置时注册本 handler，故此处必然为 Some
    let dir = state
        .ui
        .as_ref()
        .expect("ui_fallback registered only when ui_dir is set");
    let wants_html = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false);
    let has_extension = uri
        .path()
        .rsplit('/')
        .next()
        .map(|seg| seg.contains('.'))
        .unwrap_or(false);
    if !wants_html && !has_extension {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "message": "not found", "type": "not_found" } })),
        )
            .into_response();
    }
    let req = axum::extract::Request::builder()
        .uri(uri)
        .body(axum::body::Body::empty())
        .unwrap();
    let service = ServeDir::new(dir)
        .append_index_html_on_directories(true)
        .fallback(ServeFile::new(dir.join("index.html")));
    match service.oneshot(req).await {
        Ok(resp) => {
            // ServeDir 的 body 是 UnsyncBoxBody，收集成 Bytes 后重包为 axum Body
            let (parts, body) = resp.into_parts();
            let bytes = http_body_util::BodyExt::collect(body)
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            Response::from_parts(parts, axum::body::Body::from(bytes))
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
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

/// OpenAI 兼容 `/v1/models`：聚合所有**健康** agent 显式声明的模型并集
/// （`["*"]` 全匹配的 agent 不贡献条目——它接受任意请求，但具体能跑什么
/// 只有上游知道，列出会误导客户端）。与代理入口同级的认证 + 限流。
async fn models_route(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(rejection) = crate::http_proxy::auth_and_rate_limit(&state, &headers) {
        return rejection;
    }
    let data: Vec<_> = state
        .registry
        .healthy_models(state.agent_stale_after)
        .into_iter()
        .map(|id| {
            json!({
                "id": id,
                "object": "model",
                "created": 0,
                "owned_by": "edge-agent",
            })
        })
        .collect();
    Json(json!({ "object": "list", "data": data })).into_response()
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

/// 记录请求状态码与耗时（/metrics 自身不计入），并为每个请求生成/透传
/// `x-request-id`（响应头 + 写进入站 headers 供 proxy 复用为隧道 request_id，
/// 使 HTTP 层、隧道层、日志三方对账一致）。
async fn metrics_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    if req.uri().path() == "/metrics" {
        return next.run(req).await;
    }
    // 客户端自带 x-request-id 则沿用（幂等重试对账），否则分配
    let request_id = match req.headers().get("x-request-id") {
        Some(v) => v.to_str().unwrap_or_default().to_string(),
        None => {
            let id = NEXT_REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let id = format!("req-{id}");
            if let Ok(v) = axum::http::HeaderValue::from_str(&id) {
                req.headers_mut().insert("x-request-id", v);
            }
            id
        }
    };
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let start = state.metrics.record_start();
    // HTTP 全局在途上限（0 = 不限）：超限立即 429，防多 key 总和压垮单实例
    let limit = state.max_concurrent_requests;
    if limit > 0 && state.metrics.active_count() > limit as u64 {
        state.metrics.record_end(start, 429);
        let mut resp = crate::http_proxy::error_response(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "too many concurrent requests, retry later",
        );
        if let Ok(v) = axum::http::HeaderValue::from_str(&request_id) {
            resp.headers_mut().insert("x-request-id", v);
        }
        warn!(
            request_id = %request_id,
            method = %method,
            path = %path,
            active = state.metrics.active_count(),
            limit,
            "concurrent request limit reached, rejecting 429"
        );
        return resp;
    }
    let mut resp = next.run(req).await;
    let status = resp.status().as_u16();
    state.metrics.record_end(start, status);
    if let Ok(v) = axum::http::HeaderValue::from_str(&request_id) {
        resp.headers_mut().insert("x-request-id", v);
    }
    info!(
        request_id = %request_id,
        method = %method,
        path = %path,
        status,
        duration_ms = start.elapsed().as_millis() as u64,
        "request handled"
    );
    resp
}

static NEXT_REQUEST_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    use crate::{keystore::KeyStore, metrics::Metrics, ratelimit::RateLimiter, registry::Registry};

    fn test_state(ui: Option<PathBuf>) -> AppState {
        AppState {
            registry: Registry::default(),
            key_store: KeyStore::new(None),
            admin_token: None,
            timeout: Duration::from_secs(10),
            agent_stale_after: Duration::from_secs(10),
            rate_limiter: RateLimiter::new(0),
            max_concurrent_requests: 0,
            metrics: Metrics::default(),
            ui,
        }
    }

    fn headers_with_accept(accept: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::ACCEPT,
            HeaderValue::from_str(accept).unwrap(),
        );
        h
    }

    async fn body_str(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        String::from_utf8_lossy(&bytes).to_string()
    }

    #[tokio::test]
    async fn metrics_browser_request_serves_spa() {
        // 浏览器（Accept: text/html）直接访问 /metrics → SPA 页面
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<div id=\"root\">ui</div>").unwrap();
        let state = test_state(Some(dir.path().to_path_buf()));

        let resp = metrics_route(State(state.clone()), headers_with_accept("text/html")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            body_str(resp).await.contains("id=\"root\""),
            "browser should get the SPA"
        );

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

    #[test]
    fn app_builds_with_ui_dir() {
        // ui_dir 存在时 app() 注册 ui_fallback（覆盖静态托管分支）
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<div id=\"root\">ui</div>").unwrap();
        let _router = app(test_state(Some(dir.path().to_path_buf())));
        // 未配 ui_dir 时走 ui_missing 占位页分支
        let _router2 = app(test_state(None));
    }

    #[tokio::test]
    async fn x_request_id_generated_and_echoed() {
        // /healthz 经 metrics_middleware：响应带 x-request-id；客户端自带则沿用
        let router = app(test_state(None));

        // 无自带 → 生成 req-N 并回显
        let resp = router
            .clone()
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let rid = resp
            .headers()
            .get("x-request-id")
            .expect("x-request-id set on response")
            .to_str()
            .unwrap()
            .to_string();
        assert!(rid.starts_with("req-"), "generated id format req-N: {rid}");

        // 客户端自带 → 沿用（幂等重试对账）
        let resp = router
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/healthz")
                    .header("x-request-id", "req-999")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.headers()
                .get("x-request-id")
                .unwrap()
                .to_str()
                .unwrap(),
            "req-999",
            "client-supplied id is echoed"
        );
    }

    #[tokio::test]
    async fn concurrent_request_limit_rejects_with_429() {
        // max_concurrent_requests=1：先人为占住 1 个在途 → 第二个请求 429
        let mut state = test_state(None);
        state.max_concurrent_requests = 1;
        let metrics = state.metrics.clone();
        let router = app(state);

        // 占住唯一的并发槽（record_start 模拟一个在途请求，不 record_end）
        metrics.record_start();
        let resp = router
            .clone()
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "second concurrent request over limit must be rejected"
        );
        assert_eq!(
            resp.headers().get(axum::http::header::RETRY_AFTER),
            Some(&axum::http::HeaderValue::from_static("60")),
            "429 carries Retry-After"
        );
        metrics.record_end(std::time::Instant::now(), 429); // 释放槽位

        // 槽位释放后恢复
        let resp = router
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn zero_limit_never_rejects() {
        // max_concurrent_requests=0（默认）→ 不限
        let router = app(test_state(None));
        let resp = router
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// 构造 ui_fallback 的请求并返回响应。
    async fn call_ui_fallback(state: AppState, path: &str, accept: Option<&str>) -> Response {
        let mut builder = axum::extract::Request::builder().uri(path);
        if let Some(a) = accept {
            builder = builder.header(axum::http::header::ACCEPT, a);
        }
        let req = builder.body(axum::body::Body::empty()).unwrap();
        // 从请求提取 headers 和 uri 后调用 handler
        let (parts, _) = req.into_parts();
        let headers = parts.headers.clone();
        let uri = parts.uri.clone();
        ui_fallback(State(state), headers, uri).await
    }

    #[tokio::test]
    async fn ui_fallback_serves_spa_to_browser_but_404_to_api() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<div id=\"root\">ui</div>").unwrap();
        std::fs::create_dir_all(dir.path().join("assets")).unwrap();
        std::fs::write(dir.path().join("assets/app.js"), "console.log(1)").unwrap();
        let state = test_state(Some(dir.path().to_path_buf()));

        // 浏览器导航（Accept: text/html）→ SPA index.html
        let resp = call_ui_fallback(state.clone(), "/keys", Some("text/html")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_str(resp).await.contains("id=\"root\""));

        // 静态资源（带扩展名，Accept: */*）→ 文件
        let resp = call_ui_fallback(state.clone(), "/assets/app.js", Some("*/*")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_str(resp).await.contains("console.log"));

        // API 类未注册路径（Accept: */*、无扩展名）→ 404，绝不能返回 index.html
        let resp = call_ui_fallback(state.clone(), "/admin/agents", Some("*/*")).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(
            !body_str(resp).await.contains("id=\"root\""),
            "API paths must not get SPA"
        );
    }
}
