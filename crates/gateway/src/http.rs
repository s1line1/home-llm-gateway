//! 公网 HTTP 入口：认证 → 路由 → 编码为隧道帧转发。

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, StatusCode, Uri},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio_rustls::TlsAcceptor;
use tower::{Service as TowerService, ServiceExt};
use tower_http::services::{ServeDir, ServeFile};
use tracing::{debug, error, info, warn};

use crate::gateway::Options;
use crate::io_stall;
use crate::metrics::Metrics;
use crate::ratelimit::RateLimiter;
use crate::registry::Registry;
use crate::storage::KeyStore;

#[derive(Clone)]
pub struct AppState {
    pub registry: Registry,
    pub key_store: KeyStore,
    /// Admin token（None 表示不启用 /admin/*）。
    pub admin_token: Option<String>,
    pub timeout: Duration,
    pub agent_stale_after: Duration,
    /// 隧道控制操作超时（打开流 / 发送请求头 / 取消帧）。见 [`crate::Options`] 的说明。
    pub tunnel_op_timeout: Duration,
    /// 等待上游响应头（首字节）的超时。见 [`crate::Options`] 的说明。
    pub head_timeout: Duration,
    /// 客户端停滞阈值：请求体/响应体两个方向"完全没动静"多久就放弃。
    /// 见 [`crate::Options::client_stall`]——没有它，在途请求会永久占住准入槽位。
    pub client_stall: Duration,
    /// 响应头超时的"忙/死"判据窗口：这么久内有过成功响应头，就只是"慢"。
    ///
    /// 由 `head_timeout` 派生（4 倍），不单独设配置项：它表达的是"连续 4 个响应头超时窗口
    /// 一次都没回过"——到这个程度就不再是"排队慢"了（见 `registry::Entry::head_timeout_is_fatal`）。
    pub head_alive_window: Duration,
    pub rate_limiter: Option<RateLimiter>,
    /// HTTP 全局在途请求上限（0 = 不限；per-key 限流之外的总闸门）。
    pub max_concurrent_requests: u32,
    /// 每条 agent 连接允许的同时在途隧道流数（QUIC 双向流额度）。
    ///
    /// 两个用途：① 建 QUIC 端点时作为双向流额度（见 `Gateway::start`）；
    /// ② 开流超时时用来区分"忙"（额度排满，排队超时）与"死"（见
    /// `registry::Entry::open_timeout_is_fatal`）。
    pub max_open_tunnel_streams: u32,
    pub metrics: Metrics,
    /// React UI 静态目录（None = `/` 显示构建提示页）。
    pub ui: Option<PathBuf>,
    /// `ui_dir` 不可用的具体原因（None = 没配 ui_dir，或配了且可用）。
    /// 由启动时 [`resolve_ui`] 判定后写入，占位页会把它显示出来——否则用户只看到白屏/通用文案。
    pub ui_problem: Option<String>,
}

impl AppState {
    /// 从 [`Options`] 组装请求处理状态：配置 → `AppState` 的映射与**派生只在这一处发生**。
    ///
    /// 两个派生量都不单独设旋钮：
    /// - `head_alive_window = head_timeout × 4`：连续四个窗口一次响应头都没回来，才算"不是慢，是死"；
    /// - `max_open_tunnel_streams = opts.stream_ceiling()`：0 → 默认值，与绑 QUIC 端点同一口径。
    ///
    /// `ui_dir` 的可用性判定（[`resolve_ui`]）也在这里：它是**非致命**的启动自检，
    /// 不通过就降级成占位页，并把原因交给页面自己显示。
    pub fn new(registry: Registry, key_store: KeyStore, metrics: Metrics, opts: &Options) -> Self {
        let (ui, ui_problem) = resolve_ui(opts.ui_dir.as_deref());
        Self {
            registry,
            key_store,
            admin_token: opts.admin_token.clone(),
            timeout: opts.request_timeout,
            agent_stale_after: opts.agent_stale_after,
            tunnel_op_timeout: opts.tunnel_op_timeout,
            head_timeout: opts.head_timeout,
            head_alive_window: opts.head_timeout * 4,
            client_stall: opts.client_stall,
            rate_limiter: RateLimiter::new(opts.rate_limit_per_min),
            max_concurrent_requests: opts.max_concurrent_requests,
            max_open_tunnel_streams: opts.stream_ceiling(),
            metrics,
            ui,
            ui_problem,
        }
    }
}

/// `ui_dir` 的启动期判定：返回（可托管的目录, 不可用的原因）。
///
/// 必须确认它是**一份能用的产物**，而不只是"有 index.html"——Vite 的源码目录同样有
/// index.html，托管出去只会让浏览器白屏（见 [`check_ui_dir`]）。判定不通过就降级到
/// 占位页，并把具体原因写进 `AppState`，让页面自己说清楚。
///
/// **非致命**：这里任何问题都不阻止网关启动（`ui_dir` 只是给人看的诊断面）。
pub fn resolve_ui(configured: Option<&Path>) -> (Option<PathBuf>, Option<String>) {
    let Some(p) = configured else {
        return (None, None);
    };
    match check_ui_dir(p) {
        UiDirCheck::Usable => (Some(p.to_path_buf()), None),
        // 还没构建：占位页自带的通用文案（"构建前端后配置 ui_dir"）正好适用
        UiDirCheck::NoIndex => {
            warn!(path = %p.display(), "ui_dir 下没有 index.html；GET / 显示构建提示页");
            (None, None)
        }
        UiDirCheck::SourceEntry => {
            let msg = format!(
                "ui_dir 指向的是前端**源码**目录，不是构建产物（默认 web/dist）：{}",
                p.display()
            );
            error!(path = %p.display(), "{msg}；浏览器只会白屏，GET / 已改显示本提示页");
            (None, Some(msg))
        }
        UiDirCheck::MissingAsset(asset) => {
            let msg =
                format!("index.html 引用的产物不存在：{asset}（构建过期，或 ui_dir 指向了别处）");
            warn!(path = %p.display(), missing = %asset, "{msg}；GET / 显示构建提示页");
            (None, Some(msg))
        }
    }
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
        // 上限常量与 `http_proxy` 手动读 body 时用的**是同一个**（那边要自己判，因为
        // 改成手动逐块读之后提取器层的限制不再生效）。
        .layer(DefaultBodyLimit::max(crate::http_proxy::MAX_REQUEST_BODY))
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

/// UI 未构建 / ui_dir 不可用时的占位提示页——不再内嵌任何管理功能。
/// `state.ui_problem` 有值时把具体原因一并显示：浏览器本身就是诊断面。
async fn ui_missing(State(state): State<AppState>) -> Html<String> {
    Html(render_ui_missing(state.ui_problem.as_deref()))
}

/// `ui_dir` 是否真的能拿来托管。
///
/// 原来的判断只问"目录里有 index.html 吗"，而前端**源码**目录同样有——Vite 的
/// `web/index.html` 里是 `<script type="module" src="/src/main.tsx">`，网关会把 TSX 当
/// `application/octet-stream` 发出去，浏览器执行不了 → 页面全白且**一条错误都没有**。
/// 所以这里问的是"这是一份能用的产物吗"。
#[derive(Debug, PartialEq, Eq)]
pub enum UiDirCheck {
    /// 可用：index.html 在，且它引用的本地资源都能在磁盘上找到。
    Usable,
    /// 目录里没有 index.html（还没构建）。
    NoIndex,
    /// index.html 是前端**源码**入口（引用 /src/*），浏览器必然白屏。
    SourceEntry,
    /// index.html 引用的产物文件不存在（构建过期或 ui_dir 指错）。附上是哪一个。
    MissingAsset(String),
}

/// 判定 `ui_dir` 是否是一份可托管的产物。放在 http.rs：只有这个模块知道
/// "一份前端产物长什么样、怎么被托管"，lib.rs 只负责在启动时按结果编排。
pub fn check_ui_dir(dir: &Path) -> UiDirCheck {
    let Ok(html) = std::fs::read_to_string(dir.join("index.html")) else {
        return UiDirCheck::NoIndex;
    };
    // Vite 的源码入口特征；换框架要跟着改（CRA 是 /static/js/…、Next export 是 /_next/…），
    // 真正框架无关的兜底是下面的产物存在性检查。
    if html.contains("src=\"/src/") || html.contains("src='/src/") {
        return UiDirCheck::SourceEntry;
    }
    for asset in local_asset_refs(&html) {
        if !dir.join(asset.trim_start_matches('/')).is_file() {
            return UiDirCheck::MissingAsset(asset);
        }
    }
    UiDirCheck::Usable
}

/// 抓 index.html 里 `src="/…"` / `href="/…"` 这类**本地静态资源**路径（去重、去掉 query/fragment）。
///
/// 只收"末段带扩展名"的引用，这条判据与 [`ui_fallback`] 的 `has_extension` 一致：
/// SPA 前端路由（`/keys`、`/metrics`）会 fallback 到 index.html，磁盘上本来就没有对应文件，
/// 误判成"缺失"会把一个**能用**的 UI 关掉——宁可漏报也不能误报。
/// 同样跳过 http(s)://、协议相对的 //cdn、data:：那些不归 ui_dir 管。
///
/// 手写扫描而非引 HTML parser：只为一次启动自检不值得加依赖（metrics.rs 同样是手写无依赖）。
fn local_asset_refs(html: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for attr in ["src=\"", "href=\"", "src='", "href='"] {
        let quote = attr.chars().last().expect("attr ends with a quote");
        let mut rest = html;
        while let Some(idx) = rest.find(attr) {
            rest = &rest[idx + attr.len()..];
            let Some(end) = rest.find(quote) else { break };
            let value = &rest[..end];
            rest = &rest[end + quote.len_utf8()..];
            if !value.starts_with('/') || value.starts_with("//") {
                continue;
            }
            let path = value.split(['?', '#']).next().unwrap_or(value);
            let looks_like_file = path.rsplit('/').next().is_some_and(|seg| seg.contains('.'));
            if !looks_like_file {
                continue;
            }
            if !out.iter().any(|p| p == path) {
                out.push(path.to_string());
            }
        }
    }
    out
}

/// 渲染占位页：`reason` 有值时插到最上面。
/// 用 `replace` 而不是 `format!`，省得给 HTML 里那堆 CSS 花括号做转义。
fn render_ui_missing(reason: Option<&str>) -> String {
    let reason = match reason {
        Some(r) => format!(
            "<p class=\"problem\"><strong>ui_dir 不可用：</strong>{}</p>",
            html_escape(r)
        ),
        None => String::new(),
    };
    UI_MISSING.replace("{reason}", &reason)
}

/// 原因串里含配置路径，属于外部输入，插进 HTML 前转义。
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
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
  .problem { background: #fef2f2; border-left: 4px solid #dc2626; padding: 8px 12px; }
</style>
</head>
<body>
<h1>Home LLM Gateway</h1>
{reason}
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
    // 已验证身份缓存的命中/未命中：命中多说明 argon2 复用良好（内存/CPU 都省）
    let (verify_hits, verify_misses) = state.key_store.verified_counters();
    // 注册条目数 与 真正可路由数必须分开暴露：前者含失联但连接未关的 agent，
    // 排查"全部请求 503"时只有后者能说明问题（见 `hlmg_agents_healthy` 的 HELP）。
    let healthy = state.registry.healthy_count(state.agent_stale_after);
    state
        .metrics
        .render(state.registry.len(), healthy, verify_hits, verify_misses)
        .into_response()
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

/// 起公网入口的 accept 循环（TLS 与明文共用一套服务实现），返回任务句柄。
///
/// rustls 配置由调用方（`Gateway::start`）**预先构建好**传入：证书材料有问题要在
/// 启动时就失败，而不是在这里默默结束、留下一个"看起来启动了"的空壳进程。
pub(crate) fn spawn_entry(
    listener: tokio::net::TcpListener,
    app: Router,
    https: Option<Arc<rustls::ServerConfig>>,
    client_stall: Duration,
) -> tokio::task::JoinHandle<()> {
    // 日志记**真实**监听地址：配置写 `:0` 时只有 `local_addr()` 知道内核给了哪个端口。
    match listener.local_addr() {
        Ok(addr) if https.is_some() => info!(addr = %addr, "https public entry enabled"),
        Ok(addr) => info!(addr = %addr, "http public entry enabled"),
        Err(e) => warn!("cannot read the public entry's local_addr: {e}"),
    }
    tokio::spawn(async move {
        let result = match https {
            Some(cfg) => serve_https(listener, app, cfg, client_stall).await,
            None => serve_plain(listener, app, client_stall).await,
        };
        if let Err(e) = result {
            warn!("public entry stopped: {e}");
        }
    })
}

/// 服务一条客户端连接（TLS 与明文共用）。
///
/// **写方向必须包 [`io_stall::WriteStall`]**：hyper 自己**没有写超时**，客户端读完响应头
/// 就不再读时，hyper 会永久阻塞在 `poll_write`，而准入票据绑在 response body 上——
/// body 不被丢弃，槽位就永不归还（实测云端沉淀 8 个僵尸槽位，只能重启）。
/// 应用层的响应体停滞超时修不掉这一半，因为数据已经在 hyper/socket 的缓冲里。
async fn serve_conn<I>(io: I, app: Router, peer: std::net::SocketAddr, client_stall: Duration)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(io_stall::WriteStall::new(io, client_stall));
    // 桥接 hyper(0.4 Service) 与 axum(tower 0.5 Service)
    let service = service_fn(move |req: hyper::Request<Incoming>| {
        let mut app = app.clone();
        async move { app.call(req).await }
    });
    if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
        warn!("http connection {peer} error: {e}");
    }
}

/// 基于 tokio-rustls 的 HTTPS accept 循环（每连接一个任务）。
async fn serve_https(
    listener: tokio::net::TcpListener,
    app: Router,
    server_config: Arc<rustls::ServerConfig>,
    client_stall: Duration,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(server_config);
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => serve_conn(tls_stream, app, peer, client_stall).await,
                Err(e) => warn!("tls handshake from {peer} failed: {e}"),
            }
        });
    }
}

/// 明文入口：与 [`serve_https`] 同一套服务实现（含写停滞超时）。
/// 以前这里直接用 `axum::serve`，它没有写超时，客户端不读响应体就会卡住一条连接并占住票据。
async fn serve_plain(
    listener: tokio::net::TcpListener,
    app: Router,
    client_stall: Duration,
) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let app = app.clone();
        tokio::spawn(async move { serve_conn(stream, app, peer, client_stall).await });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    use crate::{metrics::Metrics, registry::Registry, storage::KeyStore};

    fn test_state(ui: Option<PathBuf>) -> AppState {
        // 测试档位：只改这个文件真正关心的旋钮，其余取库默认（`Options::default()`）。
        let opts = Options {
            head_timeout: Duration::from_secs(5),
            ui_dir: ui,
            ..Options::default()
        };
        AppState::new(
            Registry::default(),
            KeyStore::new(None),
            Metrics::default(),
            &opts,
        )
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

    // ---- ui_dir 可用性判定 ----
    // 曾经的事故：ui_dir 配成前端**源码**目录，index.html 照样在，于是被当成"已构建"托管出去，
    // 浏览器拿到 application/octet-stream 的 TSX，页面全白且没有任何错误可查。

    #[test]
    fn check_ui_dir_reports_no_index() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(check_ui_dir(dir.path()), UiDirCheck::NoIndex);
    }

    #[test]
    fn check_ui_dir_detects_vite_source_entry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("index.html"),
            r#"<div id="root"></div><script type="module" src="/src/main.tsx"></script>"#,
        )
        .unwrap();
        assert_eq!(check_ui_dir(dir.path()), UiDirCheck::SourceEntry);
    }

    #[test]
    fn check_ui_dir_accepts_built_dist() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("assets")).unwrap();
        std::fs::write(dir.path().join("assets/index-abc.js"), "//built").unwrap();
        std::fs::write(dir.path().join("assets/index-abc.css"), "/*built*/").unwrap();
        std::fs::write(
            dir.path().join("index.html"),
            r#"<script type="module" crossorigin src="/assets/index-abc.js"></script>
<link rel="stylesheet" crossorigin href="/assets/index-abc.css">"#,
        )
        .unwrap();
        assert_eq!(check_ui_dir(dir.path()), UiDirCheck::Usable);
    }

    #[test]
    fn check_ui_dir_flags_missing_asset() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("index.html"),
            r#"<script type="module" src="/assets/index-abc.js"></script>"#,
        )
        .unwrap();
        // 构建过期 / 目录指错：产物文件不在
        assert_eq!(
            check_ui_dir(dir.path()),
            UiDirCheck::MissingAsset("/assets/index-abc.js".into())
        );
    }

    #[test]
    fn check_ui_dir_ignores_non_asset_refs() {
        // 外部资源（http://、//cdn、data:）和 SPA 前端路由（无扩展名）都不是"缺失的产物"，
        // 误判会把一个能用的 UI 关掉。
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("assets")).unwrap();
        std::fs::write(dir.path().join("assets/ok.css"), "/*x*/").unwrap();
        std::fs::write(dir.path().join("favicon.ico"), "x").unwrap();
        std::fs::write(
            dir.path().join("index.html"),
            r#"<link rel="stylesheet" href="/assets/ok.css">
<link rel="preconnect" href="https://fonts.example.com">
<link rel="icon" href="//cdn.example.com/favicon.ico">
<link rel="icon" href="/favicon.ico">
<img src="data:image/png;base64,AAAA">
<a href="/keys">keys</a>
<a href="/metrics">metrics</a>"#,
        )
        .unwrap();
        assert_eq!(check_ui_dir(dir.path()), UiDirCheck::Usable);
    }

    #[test]
    fn placeholder_page_shows_the_reason() {
        let reason = "ui_dir 指向的是前端**源码**目录，不是构建产物（默认 web/dist）：web";
        let html = render_ui_missing(Some(reason));
        assert!(html.contains(reason), "占位页必须写出具体原因");
        // 没原因时保持通用文案，且不残留占位符
        let plain = render_ui_missing(None);
        assert!(!plain.contains("{reason}"));
        assert!(plain.contains("Web 管理面板尚未构建"));
    }

    #[test]
    fn placeholder_page_escapes_the_reason() {
        // reason 里含配置路径，属于外部输入
        let html = render_ui_missing(Some("路径 <script>alert(1)</script>"));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[tokio::test]
    async fn ui_missing_route_serves_the_problem() {
        let mut state = test_state(None);
        state.ui_problem = Some("ui_dir 指向源码目录：web".into());
        let resp = app(state)
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("ui_dir 指向源码目录：web"),
            "浏览器打开 / 就该看到原因，而不是白屏/通用文案"
        );
    }
}
