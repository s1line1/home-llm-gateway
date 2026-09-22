//! 公网 HTTP 入口：认证 → 路由 → 编码为隧道帧转发。

use axum::{extract::DefaultBodyLimit, middleware, routing::get, Router};
use tracing::info;

use crate::state::AppState;

mod admission;
mod api;
mod entry;
mod observability;
#[cfg(test)]
mod test_util;
mod ui;

use admission::admission_middleware;
use api::{healthz, metrics_route, models_route};
pub(crate) use entry::spawn_entry;
use observability::request_id_middleware;
use ui::{ui_fallback, ui_missing};

pub fn app(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics_route))
        // /v1/models 是静态路径，优先于下方 /v1/{*rest}（matchit 规则）：
        // GET 由网关聚合回答，不再透传单台 agent。
        .route("/v1/models", get(models_route))
        .route(
            "/v1/{*rest}",
            get(crate::proxy::proxy)
                .post(crate::proxy::proxy)
                .put(crate::proxy::proxy)
                .delete(crate::proxy::proxy)
                .patch(crate::proxy::proxy),
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
        // 上限常量与 `body::read_body_with_stall` 手动读 body 时用的**是同一个**（那边要自己判，因为
        // 改成手动逐块读之后提取器层的限制不再生效）。
        .layer(DefaultBodyLimit::max(crate::body::MAX_REQUEST_BODY))
        // 层序**不能反**：准入（里）→ id/日志/状态码（外）。被闸门拒掉的 429 必须经过外层
        // 才能带上回显的 `x-request-id`，而状态码记账只在最外层发生一次（见两个模块头）。
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admission_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            request_id_middleware,
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    // 造测试用 `AppState` 的辅助在 `http/test_util.rs`——测试已随被测代码分散到各子模块，
    // 那是它们的共同前提。本模块只剩"路由表能不能装起来"这一条测试。
    use crate::http::test_util::test_state;

    #[test]
    fn app_builds_with_ui_dir() {
        // ui_dir 存在时 app() 注册 ui_fallback（覆盖静态托管分支）
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<div id=\"root\">ui</div>").unwrap();
        let _router = app(test_state(Some(dir.path().to_path_buf())));
        // 未配 ui_dir 时走 ui_missing 占位页分支
        let _router2 = app(test_state(None));
    }
}
