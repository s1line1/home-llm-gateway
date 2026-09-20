//! Admin API：运行时签发 / 列出 / 吊销 API Key。
//! 所有 /admin/* 请求都需要 `Authorization: Bearer <--admin-token>`。

use axum::{
    extract::{Path, State},
    http::{header::AUTHORIZATION, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::state::AppState;
use crate::storage::hash::constant_time_eq;

/// Admin 鉴权中间件：仅放行持有 admin token 的请求。
pub async fn admin_auth(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let expected = state.admin_token.as_deref().unwrap_or_default();
    let ok = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|t| constant_time_eq(expected.as_bytes(), t.as_bytes()))
        .unwrap_or(false);
    if ok {
        return next.run(req).await;
    }
    // 统一走 openai::error_response：`type` 按状态码映射（401 → authentication_error），
    // 与 proxy / 中间件产生的错误同一个语义表——自造 type 会让 SDK 无从判断重试行为。
    crate::openai::error_response(StatusCode::UNAUTHORIZED, "invalid admin token")
}

/// 列出所有动态 key（不暴露明文；明文不落盘后无法显示真实前缀，用固定掩码）。
/// 每项附带该 key 的用量汇总（无记录时为 0）。
pub async fn list_keys(State(state): State<AppState>) -> Json<serde_json::Value> {
    let out: Vec<serde_json::Value> = state
        .key_store
        .list()
        .into_iter()
        .map(|r| {
            let usage = state.key_store.usage_of(&r.id);
            json!({
                "id": r.id,
                "name": r.name,
                "created_at": r.created_at,
                "enabled": r.enabled,
                "prefix": "sk-••••",
                "usage": usage.map(|u| json!({
                    "prompt_tokens": u.prompt_tokens,
                    "completion_tokens": u.completion_tokens,
                    "total_tokens": u.total_tokens,
                    "requests": u.requests,
                    "estimated_requests": u.estimated_requests,
                    "last_used_at": u.last_used_at,
                })).unwrap_or_else(|| json!({
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "total_tokens": 0,
                    "requests": 0,
                    "estimated_requests": 0,
                    "last_used_at": 0,
                })),
            })
        })
        .collect();
    Json(json!(out))
}

/// 全部 key 的用量汇总（含已吊销 key 的历史记录，可审计）。
pub async fn usage_route(State(state): State<AppState>) -> Json<serde_json::Value> {
    let out: Vec<serde_json::Value> = state
        .key_store
        .usage_snapshot()
        .into_iter()
        .map(|u| {
            json!({
                "key_id": u.key_id,
                "name": u.name,
                "prompt_tokens": u.prompt_tokens,
                "completion_tokens": u.completion_tokens,
                "total_tokens": u.total_tokens,
                "requests": u.requests,
                "estimated_requests": u.estimated_requests,
                "last_used_at": u.last_used_at,
            })
        })
        .collect();
    Json(json!(out))
}

/// 创建 key，返回明文（仅此一次展示；此后只存 argon2 哈希）。
pub async fn create_key(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unnamed")
        .to_string();
    if name.chars().count() > 64 {
        return crate::openai::error_response(StatusCode::BAD_REQUEST, "name too long");
    }
    // argon2 哈希 + SQLite 写穿较重，移到阻塞线程池，避免卡 async worker
    let store = state.key_store.clone();
    let created = match tokio::task::spawn_blocking(move || store.create(name)).await {
        Ok(c) => c,
        Err(e) => {
            return crate::openai::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("key creation failed: {e}"),
            );
        }
    };
    (
        StatusCode::CREATED,
        Json(json!({
            "id": created.record.id,
            "key": created.plaintext,
            "name": created.record.name,
            "created_at": created.record.created_at,
            "enabled": created.record.enabled,
            "prefix": "sk-••••",
            "usage": {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "requests": 0,
                "estimated_requests": 0,
                "last_used_at": 0,
            },
        })),
    )
        .into_response()
}

/// 吊销 key。
pub async fn delete_key(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let store = state.key_store.clone();
    let removed = match tokio::task::spawn_blocking(move || store.delete(&id)).await {
        Ok(r) => r,
        Err(e) => {
            return crate::openai::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("key deletion failed: {e}"),
            );
        }
    };
    if removed {
        StatusCode::NO_CONTENT.into_response()
    } else {
        crate::openai::error_response(StatusCode::NOT_FOUND, "key not found")
    }
}

/// 列出在线 agent 明细（注册表快照，按 agent_id 排序）。
pub async fn list_agents(State(state): State<AppState>) -> Json<Vec<crate::registry::AgentInfo>> {
    Json(state.registry.snapshot())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::{
        gateway::Options, metrics::Metrics, registry::Registry, state::AppState, storage::KeyStore,
    };

    fn test_state() -> AppState {
        let opts = Options {
            admin_token: Some("admin-token".into()),
            head_timeout: Duration::from_secs(5),
            ..Options::default()
        };
        AppState::new(
            Registry::default(),
            KeyStore::new(None),
            Metrics::default(),
            &opts,
        )
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn create_key_rejects_overlong_name() {
        let state = test_state();
        let resp = create_key(
            State(state),
            Json(serde_json::json!({ "name": "x".repeat(65) })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // `type` 必须来自 openai::error_response 的映射表（400 → invalid_request_error），
        // 不能是本文件自造的 `invalid_request`（SDK 按 type 决定重试语义）
        assert_eq!(
            body_json(resp).await["error"]["type"],
            "invalid_request_error"
        );
    }

    /// `/admin/*` 的错误体必须与网关别处**同一个**格式：`error.type` 按状态码映射。
    ///
    /// 拆分前这里是自造的名字（`auth_error`），而 `proxy::error_response` 用的是
    /// `authentication_error`——同一个网关两种错误语义，SDK 只能按其中一种判断。
    #[tokio::test]
    async fn admin_errors_use_the_openai_error_shape() {
        use tower::ServiceExt;

        let state = test_state(); // admin_token = Some("admin-token")
        let resp = crate::http::app(state)
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/admin/keys")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(resp).await;
        assert_eq!(
            body["error"]["type"], "authentication_error",
            "admin 401 的 type 与 proxy 的 401 必须一致"
        );
        assert_eq!(body["error"]["message"], "invalid admin token");
    }

    #[tokio::test]
    async fn create_and_list_masks_secret() {
        let state = test_state();
        let resp = create_key(
            State(state.clone()),
            Json(serde_json::json!({ "name": "my-key" })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let created = body_json(resp).await;
        let full_key = created["key"].as_str().unwrap().to_string();
        assert!(full_key.starts_with("sk-"));

        // 列表脱敏：含名称与固定掩码，不暴露明文，也不暴露 argon2 哈希
        let listed = list_keys(State(state)).await;
        let text = listed.0.to_string();
        assert!(text.contains("my-key"));
        assert!(
            !text.contains(&full_key),
            "list must not leak plaintext key"
        );
        assert!(!text.contains("$argon2id$"), "list must not leak key hash");
    }
}
