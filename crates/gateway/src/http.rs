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
use tracing::info;

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
