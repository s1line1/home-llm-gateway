//! 入口认证与限流：把「谁在调用」和「还能不能调用」从请求处理里分出来。
//!
//! 单独成模块的理由与 [`crate::openai`] 相同——**消费者跨越了代理层的边界**：路由层的
//! `/v1/models`（网关自己聚合回答，没有上游可转发）也要走同一套认证与限流。放在 `proxy`
//! 里，等于让路由层反向依赖代理层。
//!
//! 这里同时收掉了原先的两份实现：`proxy` 内联复制过一遍认证+限流（因为它还需要
//! `key_id`/`key_name` 记账，而旧 helper 把它们丢掉了）。现在两条路径都走
//! [`authenticate`]，401/429 的文案与顺序只存在一处。

use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};

use crate::http::AppState;
use crate::openai::error_response;
use tracing::warn;

/// 已通过认证的调用方身份。
pub struct AuthenticatedKey {
    /// 限流桶键：限流是 **per-key** 的（见 [`crate::ratelimit`]）。
    pub token: String,
    /// 用量计量的归属（`/admin/usage` 按它聚合）。
    pub key_id: String,
    pub key_name: String,
}

/// 认证 + 限流：通过返回身份，否则返回**现成的错误响应**（401 / 429）。
///
/// 把错误响应直接交出来（而不是返回 `Option`/`bool` 让调用点自己构造），是为了让
/// "认证没过却继续往下走"写不出来：拿不到 [`AuthenticatedKey`]，唯一能做的就是把它还给客户端。
pub async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedKey, Response> {
    let Some(key) = verify_api_key(state, headers).await else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "invalid or missing API key",
        ));
    };
    if let Some(rl) = &state.rate_limiter {
        if !rl.try_acquire(&key.token) {
            return Err(error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded",
            ));
        }
    }
    Ok(key)
}

async fn verify_api_key(state: &AppState, headers: &HeaderMap) -> Option<AuthenticatedKey> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?;
    let token = value.to_str().ok()?.strip_prefix("Bearer ")?.to_string();
    let store = state.key_store.clone();
    let token_for_verify = token.clone();
    let record = match tokio::task::spawn_blocking(move || {
        store.authorize_record(&token_for_verify)
    })
    .await
    {
        Ok(rec) => rec?,
        Err(e) => {
            // 校验任务 panic/被取消：按认证失败处理，不放行
            warn!("key verification task failed: {e}");
            return None;
        }
    };
    Some(AuthenticatedKey {
        token,
        key_id: record.id,
        key_name: record.name,
    })
}
