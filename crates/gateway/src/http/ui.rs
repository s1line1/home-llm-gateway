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
    Json,
};
use serde_json::json;
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

use crate::state::AppState;

/// SPA fallback：浏览器导航（Accept: text/html）→ index.html；静态资源
/// （带扩展名路径，如 /assets/*.js）→ 文件；其余（API 类未注册路径）→ 404。
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
        assert!(
            !body_str(resp).await.contains("id=\"root\""),
            "API paths must not get SPA"
        );
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
