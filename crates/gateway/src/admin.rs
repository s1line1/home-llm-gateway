//! Admin API：运行时签发 / 列出 / 吊销 API Key。
//! 所有 /admin/* 请求都需要 `Authorization: Bearer <--admin-token>`。

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tracing::error;

use crate::state::AppState;
use crate::storage::hash::constant_time_eq;

/// admin 500 的**细节进日志、响应体只留固定文案**（SL-P3-20）。
///
/// 响应体是给调用方的稳定契约（`openai::error_response` 的文案全仓一致；公开路径连内网地址都
/// 不带），而 `{e}` 里可能是 rusqlite/io 的原文（常含 keys.db 路径）或 `JoinError` 的 panic
/// 载荷。**细节不能丢**：它原来只存在于响应体里，所以这里必须补一条日志 —— 否则就成了"把
/// 诊断信息从唯一的出口拿掉"（`admin.rs` 在这之前一行 log 都没有）。
///
/// `request_id` 取自入站头：`request_id_middleware` 已把规范化后的 id 写回 headers，所以这条
/// 日志能与访问日志对账。
fn log_admin_failure(headers: &HeaderMap, error: &dyn std::fmt::Display, what: &str) {
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");
    error!(request_id, error = %error, "{what}");
}

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
    headers: HeaderMap,
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
            log_admin_failure(&headers, &e, "admin key creation failed (store error)");
            return crate::openai::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key creation failed; no key was created",
            );
        }
        Err(e) => {
            log_admin_failure(&headers, &e, "admin key creation failed (task error)");
            return crate::openai::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key creation failed",
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
pub async fn delete_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    // 桶键就是 key id（`ratelimit.rs`）：吊销成功后要把桶一并丢掉，否则一个再也不会被
    // 取用的桶要留到空闲清扫为止（P2-19）。
    let bucket_key = id.clone();
    let store = state.key_store.clone();
    let removed = match tokio::task::spawn_blocking(move || store.delete(&id)).await {
        Ok(Ok(r)) => r,
        // 落库失败：**吊销没有生效**，那把 key 仍然可用——文案要说清这一点，
        // 否则运维看到 500 会以为"至少内存里删掉了"（评估 §5 H2 / 记录 P1-4）。
        Ok(Err(e)) => {
            log_admin_failure(&headers, &e, "admin key deletion failed (store error)");
            return crate::openai::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key deletion failed; the key is still valid",
            );
        }
        Err(e) => {
            log_admin_failure(&headers, &e, "admin key deletion failed (task error)");
            return crate::openai::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key deletion failed",
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
    use std::sync::Arc;
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

    /// 文件库版的 state（SL-P3-20 要造"落库真失败"）：另外给出库路径，好让测试挂触发器。
    fn file_backed_state() -> (AppState, tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let opts = Options {
            admin_token: Some("admin-token".into()),
            head_timeout: Duration::from_secs(5),
            ..Options::default()
        };
        let state = AppState::new(
            Registry::default(),
            KeyStore::new(Some(path.clone())),
            Metrics::default(),
            &opts,
        );
        (state, dir, path)
    }

    /// 用一个**独立连接**装触发器：让下一次写入必然 `RAISE(ABORT)`，从而真造出 500。
    fn install_trigger(path: &std::path::Path, sql: &str) {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch(sql).unwrap();
    }

    /// tracing 输出抓到内存里（该 crate 里第一处需要断言"某行日志到底有没有打"的测试）。
    ///
    /// ⚠️ 配合 `flavor = "current_thread"` 用：`set_default` 是**线程局部**的，多线程 runtime
    /// 里任务可能被调度到别的 worker 上，事件就抓不到了。
    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<std::sync::Mutex<Vec<u8>>>);

    impl CapturedLogs {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl std::io::Write for CapturedLogs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
        type Writer = CapturedLogs;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// 规格（SL-P3-20）：admin 500 的响应体**只留固定文案**，内部错误原文进日志。
    ///
    /// 真因是造出来的：给 `api_keys` 挂一个必然 ABORT 的插入触发器 ⇒ `store.create` 真的返回
    /// `GatewayError::Sqlite("… debug: forced insert failure …")`。修好前这段原文就出现在
    /// `error.message` 里；修好后响应体只有固定文案，而原文**必须能在日志里看到** ——
    /// `admin.rs` 之前一行 log 都没有，所以"从响应体拿掉"必须同时"加进日志"，否则就是把
    /// 诊断信息从唯一的出口拿掉了。
    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_create_keeps_internals_out_of_the_body_and_in_the_log() {
        use tower::ServiceExt;

        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_env_filter("info")
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (state, _dir, path) = file_backed_state();
        install_trigger(
            &path,
            "CREATE TRIGGER dbg_fail_insert BEFORE INSERT ON api_keys
             BEGIN SELECT RAISE(ABORT, 'debug: forced insert failure'); END;",
        );

        let resp = crate::http::app(state)
            .oneshot(
                axum::extract::Request::builder()
                    .method("POST")
                    .uri("/admin/keys")
                    .header(axum::http::header::AUTHORIZATION, "Bearer admin-token")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(r#"{"name":"p3-20"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(resp).await;
        let message = body["error"]["message"].as_str().unwrap();
        assert_eq!(
            message, "key creation failed; no key was created",
            "响应体必须是固定文案（语义子句留着，运维据此判断要不要重试）"
        );
        assert!(
            !message.contains("forced insert failure") && !message.contains("SQLite"),
            "内部错误原文/类别不得出现在响应体：{message}"
        );
        assert!(
            logs.text().contains("debug: forced insert failure"),
            "细节必须进日志（这是它唯一的出口）：{}",
            logs.text()
        );
    }

    /// 同上，吊销那一支：文案要保住"那把 key 仍然有效"这个语义（评估 §5 H2 / 记录 P1-4）。
    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_delete_keeps_internals_out_of_the_body_and_in_the_log() {
        use tower::ServiceExt;

        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_env_filter("info")
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (state, _dir, path) = file_backed_state();
        let created = state.key_store.create("p3-20".into()).unwrap();
        let id = created.record.id().to_string();
        install_trigger(
            &path,
            "CREATE TRIGGER dbg_fail_delete BEFORE DELETE ON api_keys
             BEGIN SELECT RAISE(ABORT, 'debug: forced delete failure'); END;",
        );

        let resp = crate::http::app(state)
            .oneshot(
                axum::extract::Request::builder()
                    .method("DELETE")
                    .uri(format!("/admin/keys/{id}"))
                    .header(axum::http::header::AUTHORIZATION, "Bearer admin-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(resp).await;
        let message = body["error"]["message"].as_str().unwrap();
        assert_eq!(
            message, "key deletion failed; the key is still valid",
            "响应体必须是固定文案，且要说清那把 key 仍然有效"
        );
        assert!(
            !message.contains("forced delete failure") && !message.contains("SQLite"),
            "内部错误原文/类别不得出现在响应体：{message}"
        );
        assert!(
            logs.text().contains("debug: forced delete failure"),
            "细节必须进日志：{}",
            logs.text()
        );
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

        let resp = delete_key(State(state), HeaderMap::new(), Path(id)).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT, "吊销应当成功");

        assert_eq!(rl.bucket_count(), 0, "吊销后应立即可回收桶，不等空闲清扫");
    }

    #[tokio::test]
    async fn create_key_rejects_overlong_name() {
        let state = test_state();
        let resp = create_key(
            State(state),
            HeaderMap::new(),
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
            HeaderMap::new(),
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
