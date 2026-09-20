//! 网关**自己回答**的端点：`/healthz`、`/metrics`、`/v1/models`。
//!
//! 它们的共同点是不经隧道：健康探针、Prometheus 抓取、以及把"当前有哪些模型可用"
//! 聚合成 OpenAI 兼容的 `/v1/models`。判定与聚合的细节都留在这里，路由表只管挂载。
//!
//! `/metrics` 有一个双面行为：Prometheus 抓取（`Accept: */*`）拿文本，浏览器直接访问
//! （`Accept: text/html`）拿 SPA——这是为了让浏览器刷新指标页也能渲染，而不是看到一坨文本。

use axum::{
    extract::State,
    http::HeaderMap,
    response::{Html, IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::state::AppState;

pub(super) async fn healthz() -> &'static str {
    "ok"
}

/// OpenAI 兼容 `/v1/models`：聚合所有**健康** agent 显式声明的模型并集
/// （`["*"]` 全匹配的 agent 不贡献条目——它接受任意请求，但具体能跑什么
/// 只有上游知道，列出会误导客户端）。与代理入口同级的认证 + 限流。
pub(super) async fn models_route(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(rejection) = crate::auth::authenticate(&state, &headers).await {
        return rejection.into_response();
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
pub(super) async fn metrics_route(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let wants_html = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false);
    if wants_html {
        // 走 `AppState` 里的缓存读（按 mtime 校验）：以前这里每次请求同步
        // `std::fs::read_to_string`，是在 async 上下文里做阻塞 I/O。
        if let Some(index) = &state.ui_index {
            if let Some(html) = index.load().await {
                return Html(html.to_string()).into_response();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::test_util::{body_str, headers_with_accept, test_state};
    use axum::http::StatusCode;

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
}
