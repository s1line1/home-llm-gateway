//! Admin API：运行时签发 / 列出 / 吊销 API Key。
//! 所有 /admin/* 请求都需要 `Authorization: Bearer <--admin-token>`。

use axum::{
    extract::{Path, State},
    http::StatusCode,
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
    // 与 `/v1` 认证共用同一套 Bearer 解析（P3-17：scheme 大小写不敏感、`1*SP` 分隔），
    // 否则会出现"api key 认小写、admin token 不认"的半拉子状态。比较仍是恒定时间。
    let ok = crate::auth::bearer_token(req.headers())
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
            let usage = state.key_store.usage_of(r.id());
            json!({
                "id": r.id(),
                "name": r.name(),
                "created_at": r.created_at(),
                "enabled": r.enabled(),
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
        Ok(Ok(c)) => c,
        // 落库失败：**什么都没创建**（key 也没发出去），必须让运维看到失败而不是 201。
        Ok(Err(e)) => {
            return crate::openai::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("key creation failed; no key was created: {e}"),
            );
        }
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
            "id": created.record.id(),
            "key": created.plaintext,
            "name": created.record.name(),
            "created_at": created.record.created_at(),
            "enabled": created.record.enabled(),
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
    // 桶键就是 key id（`ratelimit.rs`）：吊销成功后要把桶一并丢掉，否则一个再也不会被
    // 取用的桶要留到空闲清扫为止（P2-19）。
    let bucket_key = id.clone();
    let store = state.key_store.clone();
    let removed = match tokio::task::spawn_blocking(move || store.delete(&id)).await {
        Ok(Ok(r)) => r,
        // 落库失败：**吊销没有生效**，那把 key 仍然可用——文案要说清这一点，
        // 否则运维看到 500 会以为"至少内存里删掉了"（评估 §5 H2 / 记录 P1-4）。
        Ok(Err(e)) => {
            return crate::openai::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("key deletion failed; the key is still valid: {e}"),
            );
        }
        Err(e) => {
            return crate::openai::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("key deletion failed: {e}"),
            );
        }
    };
    if removed {
        if let Some(rl) = &state.rate_limiter {
            rl.evict(&bucket_key);
        }
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
        metrics::Metrics, options::Options, registry::Registry, state::AppState, storage::KeyStore,
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

    /// 规格（P2-19）：吊销成功要把该 key 的**限流桶一并回收**——桶键就是 key id，吊销后
    /// 这个桶再也不会被取用，不丢就要留到 `ratelimit.rs` 的空闲清扫（10 分钟）为止。
    #[tokio::test]
    async fn deleting_a_key_also_drops_its_rate_limit_bucket() {
        let opts = Options {
            admin_token: Some("admin-token".into()),
            rate_limit_per_min: 60,
            head_timeout: Duration::from_secs(5),
            ..Options::default()
        };
        let state = AppState::new(
            Registry::default(),
            KeyStore::new(None),
            Metrics::default(),
            &opts,
        );
        let created = state
            .key_store
            .create("p2-19".into())
            .expect("建 key 应当成功");
        let id = created.record.id().to_string();
        // 克隆一份句柄：桶表在 `Arc` 里，`delete_key` 会把 `state` 整个吃掉。
        let rl = state
            .rate_limiter
            .clone()
            .expect("前提：60/min 应当建出限流器");
        assert!(rl.try_acquire(&id), "前提：先让这个 key 建出一个桶");
        assert_eq!(rl.bucket_count(), 1);

        let resp = delete_key(State(state), Path(id)).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT, "吊销应当成功");

        assert_eq!(rl.bucket_count(), 0, "吊销后应立即可回收桶，不等空闲清扫");
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
        assert_eq!(
            resp.headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            Some("Bearer"),
            "admin 401 同样要给 challenge（RFC 9110 §15.5.2）"
        );
        let body = body_json(resp).await;
        assert_eq!(
            body["error"]["type"], "authentication_error",
            "admin 401 的 type 与 proxy 的 401 必须一致"
        );
        assert_eq!(body["error"]["message"], "invalid admin token");
    }

    /// 规格（P3-6）：`/admin/*` 的响应必须带 `Cache-Control: no-store`。
    ///
    /// `POST /admin/keys` 的响应体里就是**一次性明文 API key**，列表/用量响应带 key 名与用量
    /// ——这些都不该被任何共享缓存留存（即便按 RFC，带凭据的请求一般不会被缓存，这仍是
    /// 显式声明）。401 那条路径也一并钉住：它是同一个 router 的响应。
    #[tokio::test]
    async fn admin_responses_are_never_stored_by_caches() {
        use tower::ServiceExt;

        for (label, auth) in [("带 token", Some("Bearer admin-token")), ("401", None)] {
            let state = test_state(); // admin_token = Some("admin-token")
            let mut req = axum::extract::Request::builder().uri("/admin/keys");
            if let Some(a) = auth {
                req = req.header(axum::http::header::AUTHORIZATION, a);
            }
            let resp = crate::http::app(state)
                .oneshot(req.body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                resp.headers()
                    .get(axum::http::header::CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok()),
                Some("no-store"),
                "{label} 的 admin 响应也必须 no-store"
            );
        }
    }

    /// 规格（P3-17）：admin 鉴权与 `/v1` 认证必须共用同一套 Bearer 解析——小写 scheme 也放行。
    #[tokio::test]
    async fn admin_auth_accepts_a_lowercase_bearer_scheme() {
        use tower::ServiceExt;

        let state = test_state(); // admin_token = Some("admin-token")
        let resp = crate::http::app(state)
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/admin/keys")
                    .header(axum::http::header::AUTHORIZATION, "bearer admin-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "`bearer` 小写应当被接受");
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
