//! Admin API：运行时签发 / 列出 / 吊销 API Key。
//! 所有 /admin/* 请求都需要 `Authorization: Bearer <--admin-token>`。

use axum::{
    extract::{Path, State},
    http::{header::AUTHORIZATION, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::http::AppState;
use crate::keystore::hash::constant_time_eq;

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
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": { "message": "invalid admin token", "type": "auth_error" } })),
    )
        .into_response()
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
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "message": "name too long", "type": "invalid_request" } })),
        )
            .into_response();
    }
    // argon2 哈希 + SQLite 写穿较重，移到阻塞线程池，避免卡 async worker
    let store = state.key_store.clone();
    let created = match tokio::task::spawn_blocking(move || store.create(name)).await {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "message": format!("key creation failed: {e}"), "type": "gateway_error" } })),
            )
                .into_response();
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": { "message": format!("key deletion failed: {e}"), "type": "gateway_error" } })),
            )
                .into_response();
        }
    };
    if removed {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "message": "key not found", "type": "not_found" } })),
        )
            .into_response()
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

    use crate::{http::AppState, keystore::KeyStore, metrics::Metrics, registry::Registry};

    fn test_state() -> AppState {
        AppState {
            registry: Registry::default(),
            key_store: KeyStore::new(None),
            admin_token: Some("admin-token".into()),
            timeout: Duration::from_secs(10),
            agent_stale_after: Duration::from_secs(10),
            rate_limiter: None,
            metrics: Metrics::default(),
            ui: None,
        }
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
