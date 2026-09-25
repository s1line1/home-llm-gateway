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
/// 所以「网关自己产生的错误」格式全局一致（含 `Content-Type: application/json`，见下）。
pub fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    // **保留 `Json` 造好的响应 parts**（尤其 `content-type: application/json`），只改状态码、
    // 按需补两个头。曾经这里是 `builder.body(body.into_response().into_body())`：`Json` 把
    // `content-type` 放在 **parts** 里，而 `.into_body()` 只取 body，于是重装出来的响应**丢掉**
    // 了它 —— 网关自己产生的每个错误响应（401/404/429/413/5xx、admin 的 400/401/404/500）
    // 都成了「无类型的 JSON」（重扫 A1；实测 `curl -D- /v1/models` 只有 `www-authenticate`）。
    let mut resp = Json(json!({
        "error": {
            "message": message.into(),
            "type": openai_error_type(status),
        }
    }))
    .into_response();
    *resp.status_mut() = status;
    if status == StatusCode::TOO_MANY_REQUESTS {
        resp.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("60"),
        );
    }
    if status == StatusCode::UNAUTHORIZED {
        // RFC 9110 §15.5.2：401 **MUST** 带一个 `WWW-Authenticate` challenge，否则客户端
        // 无从知道该用哪种凭据。本网关产生的 401 只有两种（`/v1` 的 API key 不对、
        // `/admin` 的 admin token 不对），两条路径都认 `Authorization: Bearer`，
        // 所以 challenge 固定是 Bearer；放在这里是为了让"以后新增 401"自动带上。
        resp.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            axum::http::HeaderValue::from_static("Bearer"),
        );
    }
    resp
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

    /// 规格（重扫 A1）：**错误响应必须声明自己是 JSON**。
    ///
    /// 修复前 `Json(..).into_response()` 设的 `content-type` 留在响应的 **parts** 里，而这个函数
    /// 只取 `.into_body()`、再用 `Response::builder()` 重新装一个 ⇒ 网关自己产生的**每一个**
    /// 错误响应（`/v1` 的 401、限流与闸门的 429、SPA 的 404、413/502/503、admin 的 400/401/404/500）
    /// 都是"无类型的 JSON"；按 `Content-Type` 分支的 SDK/中间件会当成未知文本。
    /// 唯一"正常"的只有 `/healthz` 的 503——它走 `http/api.rs` 另一条构造路径，于是同一进程里
    /// 两种风格并存（实测修复前：`curl -D- /v1/models` 只有 `www-authenticate`，没有 `content-type`）。
    #[tokio::test]
    async fn error_response_declares_json_content_type() {
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::NOT_FOUND,
            StatusCode::PAYLOAD_TOO_LARGE,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::BAD_GATEWAY,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let resp = error_response(status, "boom");
            assert_eq!(resp.status(), status, "状态码不得被改写");
            assert_eq!(
                resp.headers().get(axum::http::header::CONTENT_TYPE),
                Some(&axum::http::HeaderValue::from_static("application/json")),
                "{status} 的错误响应必须声明 application/json"
            );
            // 正文仍是可解析的 JSON（改成 parts-preserving 写法后不能把 body 弄丢）
            let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(v["error"]["message"], "boom");
        }
    }
}
