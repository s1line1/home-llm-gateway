//! OpenAI 兼容协议面：错误响应的形状与语义。
//!
//! 单独成模块的理由不是"文件太长"，而是它的**消费者跨越了代理层的边界**：路由层
//! （`http/mod.rs` 的总并发中间件）也要用同一份错误格式。把它留在 `proxy` 里，等于让路由层
//! 反向依赖代理层——正是这次拆分要消掉的那类依赖。
//!
//! 目前只有错误面；将来其它「网关自己回答」的 OpenAI 兼容形状也归这里。

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// OpenAI 兼容错误响应：`error.type` 按状态码映射（SDK 据此决定重试/报错语义），
/// 429 自动带 `Retry-After`（秒）供退避，401 自动带 `WWW-Authenticate: Bearer`。
///
/// 路由层的总并发中间件（`http::app` 的 metrics_middleware）用的也是同一个函数，
/// 所以「网关自己产生的错误」格式全局一致。
pub fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    let body = Json(json!({
        "error": {
            "message": message.into(),
            "type": openai_error_type(status),
        }
    }));
    let mut builder = Response::builder().status(status);
    if status == StatusCode::TOO_MANY_REQUESTS {
        builder = builder.header(axum::http::header::RETRY_AFTER, "60");
    }
    if status == StatusCode::UNAUTHORIZED {
        // RFC 9110 §15.5.2：401 **MUST** 带一个 `WWW-Authenticate` challenge，否则客户端
        // 无从知道该用哪种凭据。本网关产生的 401 只有两种（`/v1` 的 API key 不对、
        // `/admin` 的 admin token 不对），两条路径都认 `Authorization: Bearer`，
        // 所以 challenge 固定是 Bearer；放在这里是为了让"以后新增 401"自动带上。
        builder = builder.header(axum::http::header::WWW_AUTHENTICATE, "Bearer");
    }
    builder
        .body(body.into_response().into_body())
        .unwrap_or_else(|e| {
            // builder 失败（理论不发生）：退回无头响应，保证错误仍能送达
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::from(format!(
                    "error building response: {e}"
                )))
                .unwrap()
        })
}

/// OpenAI error.type 语义（https://platform.openai.com/docs/guides/error-codes）：
/// SDK 对 429/5xx 自动重试，对 4xx（除 429）不重试——type 必须与状态码一致。
fn openai_error_type(status: StatusCode) -> &'static str {
    match status.as_u16() {
        400 => "invalid_request_error",
        401 => "authentication_error",
        403 => "permission_error",
        404 => "not_found_error",
        409 => "conflict_error",
        429 => "rate_limit_error",
        500..=599 => "server_error",
        _ => "api_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_type_maps_to_openai_semantics() {
        // 各状态码 → OpenAI error.type（SDK 据此决定是否自动重试）
        assert_eq!(
            openai_error_type(StatusCode::BAD_REQUEST),
            "invalid_request_error"
        );
        assert_eq!(
            openai_error_type(StatusCode::UNAUTHORIZED),
            "authentication_error"
        );
        assert_eq!(openai_error_type(StatusCode::FORBIDDEN), "permission_error");
        assert_eq!(openai_error_type(StatusCode::NOT_FOUND), "not_found_error");
        assert_eq!(openai_error_type(StatusCode::CONFLICT), "conflict_error");
        assert_eq!(
            openai_error_type(StatusCode::TOO_MANY_REQUESTS),
            "rate_limit_error"
        );
        assert_eq!(openai_error_type(StatusCode::BAD_GATEWAY), "server_error");
        assert_eq!(
            openai_error_type(StatusCode::SERVICE_UNAVAILABLE),
            "server_error"
        );
        assert_eq!(openai_error_type(StatusCode::OK), "api_error");
    }

    #[tokio::test]
    async fn error_response_carries_type_and_retry_after_on_429() {
        let resp = error_response(StatusCode::BAD_REQUEST, "bad");
        let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"]["type"], "invalid_request_error");

        // 429 必须带 Retry-After（SDK/脚本退避依赖）
        let resp = error_response(StatusCode::TOO_MANY_REQUESTS, "slow down");
        assert_eq!(
            resp.headers().get(axum::http::header::RETRY_AFTER),
            Some(&axum::http::HeaderValue::from_static("60"))
        );
        // 非 429 不带 Retry-After
        let resp = error_response(StatusCode::BAD_REQUEST, "bad");
        assert!(resp
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .is_none());
    }
}
