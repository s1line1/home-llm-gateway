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
use tracing::{debug, error, info, warn};

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
    if let Some(rejection) = crate::http_proxy::auth_and_rate_limit(&state, &headers).await {
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
///
/// 访问日志分级（target `gateway::access`），避免每请求一条 info 淹没真正的
/// warn/error 日志：
///   - status < 400 → debug（正常流量；状态码/耗时已由 /metrics 覆盖）
///   - 400..=499     → info（客户端/路由类异常，代码多静默返回，仅此可见）
///   - status >= 500 → error（真实失败：tunnel/upstream/内部错误）
///
/// 需要临时恢复全量访问日志：`RUST_LOG=info,gateway::access=debug`
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
    // HTTP 全局在途上限（0 = 不限）：try_enter 原子占位（旧值判定，无竞态），
    // 超限返回 None → 立即 429，防多 key 总和压垮单实例。
    // 票据的释放完全由 Drop 负责，分两段：① 移交 body 之前（含客户端中断导致 future
    // 被 drop）→ 就地 Drop 归还；② 移交 body 之后 → 随 body 结束/丢弃归还。
    let limit = state.max_concurrent_requests;
    let Some(admission) = state.metrics.try_enter(limit) else {
        state.metrics.record_rejected(429);
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
    };
    let start = admission.started_at();
    let mut resp = next.run(req).await;
    let status = resp.status().as_u16();
    state.metrics.record_status(status);
    if let Ok(v) = axum::http::HeaderValue::from_str(&request_id) {
        resp.headers_mut().insert("x-request-id", v);
    }
    // 访问日志记的是"到首字节"的延迟（TTFB）；完整请求耗时的记账在准入票据里，
    // 它在 body 结束时才结算（见下方移交），故两者字段名区分开。
    let ttfb_ms = start.elapsed().as_millis() as u64;
    match status {
        400..=499 => info!(
            target: "gateway::access",
            request_id = %request_id,
            method = %method,
            path = %path,
            status,
            ttfb_ms,
            "request failed (client error)"
        ),
        s if s >= 500 => error!(
            target: "gateway::access",
            request_id = %request_id,
            method = %method,
            path = %path,
            status,
            ttfb_ms,
            "request failed (server error)"
        ),
        _ => debug!(
            target: "gateway::access",
            request_id = %request_id,
            method = %method,
            path = %path,
            status,
            ttfb_ms,
            "request handled"
        ),
    }

    // 把准入票据**移交**给 response body：槽位与耗时记账持有到 body 流结束、或中途
    // 被丢弃（客户端断开）为止。这样闸门才真正覆盖"整个请求"——LLM 的 SSE 长流恰恰
    // 是最需要被计入的场景；若在此处直接释放，闸门只能覆盖到首字节。
    let (parts, body) = resp.into_parts();
    let body = http_body_util::BodyExt::map_frame(body, move |frame| {
        let _held = &admission; // 仅为把票据生命周期绑定到 body 上，不改动任何帧
        frame
    });
    Response::from_parts(parts, axum::body::Body::new(body))
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

        // 占住唯一的并发槽（limit=0 = 不限，必进；票据持有到 drop 为止）
        let held = metrics
            .try_enter(0)
            .expect("limit=0 admits unconditionally");
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
        drop(held); // 票据 Drop → 释放槽位

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

    #[test]
    fn try_enter_is_atomic_under_concurrency() {
        // limit=1：8 个线程同时 try_enter → 恰 1 个成功（无 check-then-act 竞态）。
        // 这是 e2e 曾出现 [429,429] 双拒的根因回归测试。
        // 票据随返回值离开线程并在此持有，保证 8 次尝试真正并发竞争同一个槽位。
        let metrics = Metrics::default();
        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = metrics.clone();
            handles.push(std::thread::spawn(move || m.try_enter(1)));
        }
        let admissions: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let admitted = admissions.iter().filter(|a| a.is_some()).count();
        assert_eq!(admitted, 1, "exactly one concurrent entry admitted");
        // 占用未释放时后续仍拒；票据 Drop 后恢复
        assert!(metrics.try_enter(1).is_none());
        drop(admissions); // 释放占用的那个
        assert!(metrics.try_enter(1).is_some());
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

    /// 规格：API Key 校验（argon2，单次 10-30ms CPU）**不得阻塞 async worker**。
    ///
    /// 用默认的 current-thread runtime：worker 一旦被同步阻塞，其它任务（这里是 1ms
    /// 周期的计时任务）完全无法推进。把 argon2 放回请求路径上同步执行，本测试即红。
    #[tokio::test]
    async fn key_verification_does_not_block_the_runtime() {
        use std::sync::{
            atomic::{AtomicU32, Ordering},
            Arc,
        };

        // 真实 KeyStore（argon2 校验真的会跑）；key 在计时任务起跑前先建好
        let store = KeyStore::new(None);
        let created = store.create("blocking-test".into());
        let mut state = test_state(None);
        state.key_store = store;
        let router = app(state);

        // 1ms 周期的计时任务：只有 runtime 让出线程时才会推进
        let ticks = Arc::new(AtomicU32::new(0));
        let t = Arc::clone(&ticks);
        let ticker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(1)).await;
                t.fetch_add(1, Ordering::Relaxed);
            }
        });
        tokio::time::sleep(Duration::from_millis(5)).await;
        let before = ticks.load(Ordering::Relaxed);

        let resp = router
            .oneshot(
                axum::extract::Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header(
                        axum::http::header::AUTHORIZATION,
                        format!("Bearer {}", created.plaintext),
                    )
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(r#"{"model":"m","messages":[]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let ticks_during = ticks.load(Ordering::Relaxed) - before;
        ticker.abort();

        // 认证已通过（无 agent → 503），说明 argon2 确实被执行过
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "key should authenticate, then fail for lack of an agent"
        );
        assert!(
            ticks_during >= 5,
            "argon2 校验阻塞了 runtime：1ms 计时任务在整段校验期间只推进了 {ticks_during} 次\
             （校验本身 10-30ms，放到阻塞线程池后应推进几十次）"
        );
    }

    /// 客户端在 handler 返回前中断（请求 future 被 drop）**不得**泄漏全局并发槽位。
    ///
    /// 回归背景：释放原先只挂在中间件尾部（`next.run(req).await` 之后），而 hyper 会在
    /// 连接断开时直接 drop 在途 future → 尾部永不执行 → 槽位永久占住，此后**所有**请求
    /// （含 /healthz）被打成 429，只能重启网关。
    #[tokio::test]
    async fn aborted_request_does_not_leak_concurrency_slot() {
        let mut state = test_state(None);
        state.admin_token = Some("admin".into());
        state.max_concurrent_requests = 1;
        let router = app(state);

        // /admin/keys 的 handler 会 parked 在 spawn_blocking(argon2)（约 10-30ms），
        // 1ms 后放弃即落在窗口内。多次尝试确保至少一次落在窗口内：若全部正常返回，
        // 本测试会退化成空转（不会误报，但也拦不住回归）。
        for _ in 0..30 {
            let req = axum::extract::Request::builder()
                .method("POST")
                .uri("/admin/keys")
                .header(axum::http::header::AUTHORIZATION, "Bearer admin")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(r#"{"name":"probe"}"#))
                .unwrap();
            let _ =
                tokio::time::timeout(Duration::from_millis(1), router.clone().oneshot(req)).await;
        }

        // 用户可见契约：中断后槽位必须已释放，后续请求不得被 429
        let resp = router
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
            StatusCode::OK,
            "aborted in-flight request leaked the concurrency slot"
        );
    }
}
