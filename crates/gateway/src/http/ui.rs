//! React UI 的**服务**半边：SPA fallback、静态资源、占位提示页。
//!
//! 与顶层 [`crate::ui`] 分工：那边回答"这份目录能不能用"（判定 + 日志），本模块回答
//! "怎么把它服务出去"。判定在启动期做一次，服务在每个请求上做，两者变更理由不同。
//!
//! 一条容易踩的边界：API 类的未注册路径**不能**被 SPA fallback 吞成 index.html——
//! 否则前端拿到的就不是合法 JSON 了。所以这里按 `Accept: text/html` / 带扩展名 三分。

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
};
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

use crate::state::AppState;

/// SPA fallback：浏览器导航（Accept: text/html）→ index.html；静态资源
/// （带扩展名路径，如 /assets/*.js）→ 文件，**未命中就是 404**；其余（API 类未注册路径）→ 404。
pub(super) async fn ui_fallback(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
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
        // 统一错误格式：以前这里手搓的是 `type: "not_found"`，与 proxy 的
        // `not_found_error` 不是同一个语义名（同一个网关两种 404）
        return crate::openai::error_response(StatusCode::NOT_FOUND, "not found");
    }
    let req = || {
        axum::extract::Request::builder()
            .uri(uri.clone())
            .body(axum::body::Body::empty())
            .unwrap()
    };

    // **带扩展名 = 资源请求**：只认磁盘上的文件，**不能挂 SPA fallback** ——
    // `ServeDir` 的 fallback 在文件缺失时会被调用、且它返回的状态码不会被改写，于是
    // `/assets/missing.js` 会拿到 `200 + text/html` 的 index.html（浏览器把 HTML 当 JS/CSS
    // 解析：语法错误 + 一份看似成功、可缓存的 200），`/data.json` 这类带点号的未注册路径
    // 也拿不到真 404（重扫 A2，实测修复前两者都是 200 + text/html）。
    // SPA fallback 只服务"浏览器导航"（无扩展名 + Accept: text/html）那一种情形。
    if has_extension {
        let service = ServeDir::new(dir).append_index_html_on_directories(true);
        return match service.oneshot(req()).await {
            // 缺失资源也用全局唯一的错误形状（与上面 API 路径的 404 一致）
            Ok(resp) if resp.status() == StatusCode::NOT_FOUND => {
                crate::openai::error_response(StatusCode::NOT_FOUND, "not found")
            }
            Ok(resp) => {
                let (parts, body) = resp.into_parts();
                Response::from_parts(parts, axum::body::Body::new(body))
            }
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
    }

    let service = ServeDir::new(dir)
        .append_index_html_on_directories(true)
        .fallback(ServeFile::new(dir.join("index.html")));
    match service.oneshot(req()).await {
        Ok(resp) => {
            // 直接流式转发，不再先 collect 成 Bytes。
            //
            // 以前那一步（`BodyExt::collect`）把**整份**资源读进内存后才回第一个字节：
            // 并发加载资源时网关内存随"资源大小 × 并发数"增长，且没有任何上限——
            // 与 R9"内存有上界"冲突。`ServeDir` 的 body 是 `UnsyncBoxBody`（Send 但不
            // Sync），而 `axum::body::Body::new` 只要求 Send，所以本来就不需要那一步；
            // 改成流式后回压由客户端读取速度决定（配合 `io_stall::WriteStall` 兜住
            // "客户端不读"）。
            // parts 原样保留，故 content-type / content-length / last-modified 等
            // 由 tower-http 决定的头不变。
            let (parts, body) = resp.into_parts();
            Response::from_parts(parts, axum::body::Body::new(body))
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// UI 未构建 / ui_dir 不可用时的占位提示页——不再内嵌任何管理功能。
/// `state.ui_problem` 有值时把具体原因一并显示：浏览器本身就是诊断面。
pub(super) async fn ui_missing(State(state): State<AppState>) -> Html<String> {
    Html(render_ui_missing(state.ui_problem.as_deref()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::app;
    use crate::http::test_util::{body_str, test_state};

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
        // 错误体走 openai::error_response：type 是 `not_found_error`
        // （以前这里手搓 `not_found`，与 proxy 的 404 不是同一个语义名）
        let body = body_str(resp).await;
        let v: serde_json::Value = serde_json::from_str(&body).expect("404 body is JSON");
        assert_eq!(v["error"]["type"], "not_found_error");
        assert!(!body.contains("id=\"root\""), "API paths must not get SPA");
    }

    /// 规格（重扫 A2）：**不存在的资源必须是 404，不能被 SPA fallback 顶成 `200 + index.html`**。
    ///
    /// 修复前两个分支共用同一个挂了 `.fallback(ServeFile(index.html))` 的 `ServeDir`，而
    /// tower-http 在文件 NotFound 时会调用 fallback 并**原样返回它的状态码** ⇒
    /// `/assets/missing.js`、`/data.json` 都拿到 `200 + text/html` 的 index.html：
    /// 浏览器把 HTML 当 JS/CSS 解析（语法错误），而且这份 200 还可能被缓存；带点号的未注册
    /// 路径也拿不到真 404，与模块头声明的边界相反。
    ///
    /// 判据同时钉住**错误形状**：404 走 `openai::error_response`（全局唯一的错误形状），
    /// 而不是 tower-http 的空体 404 —— 静态缺失也要能被同一套客户端逻辑识别。
    #[tokio::test]
    async fn ui_fallback_returns_404_for_missing_assets_instead_of_index_html() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<div id=\"root\">ui</div>").unwrap();
        std::fs::create_dir_all(dir.path().join("assets")).unwrap();
        std::fs::write(dir.path().join("assets/app.js"), "console.log(1)").unwrap();
        let state = test_state(Some(dir.path().to_path_buf()));

        // 缺失的静态资源：浏览器可能带 `*/*`，也可能因为地址栏直接打开而带 `text/html`
        for accept in ["*/*", "text/html"] {
            let resp = call_ui_fallback(state.clone(), "/assets/missing.js", Some(accept)).await;
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "缺失资源必须 404（Accept: {accept}），绝不能拿 index.html 顶替"
            );
            let body = body_str(resp).await;
            assert!(
                !body.contains("id=\"root\""),
                "不能把 index.html 当资源返回"
            );
            let v: serde_json::Value = serde_json::from_str(&body).expect("404 body is JSON");
            assert_eq!(v["error"]["type"], "not_found_error");
        }

        // 带点号但未注册的路径同理（以前也是 200 + HTML）
        let resp = call_ui_fallback(state.clone(), "/data.json", Some("text/html")).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // 对照组一：真实存在的资源照旧按文件返回
        let resp = call_ui_fallback(state.clone(), "/assets/app.js", Some("*/*")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_str(resp).await.contains("console.log"));

        // 对照组二：浏览器导航（无扩展名 + text/html）照旧拿到 SPA
        let resp = call_ui_fallback(state, "/keys", Some("text/html")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_str(resp).await.contains("id=\"root\""));
    }

    /// 大资源：body 现在是**流式**转发（不再 collect 成 Bytes），本用例锁住"改流式没把
    /// 由 tower-http 决定的响应头弄丢"——`content-length` / `content-type` 都来自
    /// `parts`，丢了客户端就会当成 chunked 或类型未知。
    #[tokio::test]
    async fn ui_fallback_streams_large_assets_with_headers_intact() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("assets")).unwrap();
        let big = vec![b'x'; 3 * 1024 * 1024];
        std::fs::write(dir.path().join("assets/big.js"), &big).unwrap();
        // index.html 必须存在，否则 resolve_ui 判定目录不可用（ui_fallback 不会注册）
        std::fs::write(dir.path().join("index.html"), "<div id=\"root\">ui</div>").unwrap();
        let state = test_state(Some(dir.path().to_path_buf()));

        let resp = call_ui_fallback(state, "/assets/big.js", Some("*/*")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some("3145728"),
            "流式转发必须保留 content-length（它来自 parts，不是 body）"
        );
        let body = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(body.len(), big.len(), "整份内容仍要原样送达");
    }

    #[test]
    fn placeholder_page_shows_the_reason() {
        // 与 `ui.rs::resolve_ui` 里那条真实原因同形（这里只是要一段含路径的文字）
        let reason = "ui_dir 指向的是前端**源码**目录，不是构建产物（应指向打包产物目录）：web";
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
