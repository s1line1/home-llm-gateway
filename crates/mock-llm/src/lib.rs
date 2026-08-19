//! mock-llm：模拟 OpenAI 兼容接口的假 LLM，用于在无真实模型时打通全链路。
//! 支持实例名，多 agent 场景下可用不同实例名区分上游来源。

use std::{convert::Infallible, sync::Arc, time::Duration};

use async_stream::stream;
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{header::{CACHE_CONTROL, CONTENT_TYPE}, HeaderValue},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};

#[derive(Clone)]
struct AppState {
    name: Arc<str>,
}

pub fn router(name: &str) -> Router {
    Router::new()
        .route("/v1/models", get(models))
        .route("/v1/chat/completions", post(chat))
        .route("/v1/embeddings", post(embeddings))
        .route("/v1/slow", post(slow))
        .with_state(AppState {
            name: Arc::from(name),
        })
}

async fn models(State(st): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "object": "list",
        "data": [{ "id": st.name.as_ref(), "object": "model", "owned_by": "mock" }]
    }))
}

async fn chat(
    State(st): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Response {
    let model = req
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or(st.name.as_ref())
        .to_string();
    let content = req
        .get("messages")
        .and_then(|v| v.as_array())
        .and_then(|arr| {
            arr.iter()
                .rev()
                .find_map(|m| m.get("content").and_then(|c| c.as_str()))
        })
        .unwrap_or_default()
        .to_string();

    let is_stream = req
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if is_stream {
        // 模拟 SSE：逐字输出，模拟真实模型的打字机效果
        let name = st.name.clone();
        let model = model.clone();
        let content = content.clone();
        let s = stream! {
            for ch in content.chars() {
                tokio::time::sleep(Duration::from_millis(10)).await;
                let chunk = serde_json::json!({
                    "id": "chatcmpl-mock-1",
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": model,
                    "server": name.as_ref(),
                    "choices": [{
                        "index": 0,
                        "delta": { "content": ch.to_string() },
                        "finish_reason": null
                    }]
                });
                yield Ok::<_, Infallible>(Bytes::from(format!("data: {chunk}\n\n")));
            }
            let done = serde_json::json!({
                "id": "chatcmpl-mock-1",
                "object": "chat.completion.chunk",
                "created": 0,
                "model": model,
                "server": name.as_ref(),
                "choices": [{ "index": 0, "delta": {}, "finish_reason": "stop" }]
            });
            yield Ok::<_, Infallible>(Bytes::from(format!("data: {done}\n\n")));
            yield Ok::<_, Infallible>(Bytes::from("data: [DONE]\n\n".to_string()));
        };
        return Response::builder()
            .header(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"))
            .header(CACHE_CONTROL, HeaderValue::from_static("no-cache"))
            .body(Body::from_stream(s))
            .unwrap();
    }

    let name = st.name.as_ref();
    Json(serde_json::json!({
        "id": "chatcmpl-mock-1",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "server": name,
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": format!("mock({name}) reply to: {content}") },
            "finish_reason": "stop"
        }],
        "usage": { "prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2 }
    }))
    .into_response()
}

async fn embeddings(
    State(st): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let model = req.get("model").and_then(|v| v.as_str()).unwrap_or(st.name.as_ref());
    Json(serde_json::json!({
        "object": "list",
        "data": [{ "object": "embedding", "index": 0, "embedding": [0.1, 0.2, 0.3] }],
        "model": model,
        "server": st.name.as_ref()
    }))
}

/// 慢端点：先睡 800ms 再响应，用于测试网关超时/并发控制。
async fn slow(State(st): State<AppState>) -> Json<serde_json::Value> {
    tokio::time::sleep(Duration::from_millis(800)).await;
    Json(serde_json::json!({ "ok": true, "slow": true, "server": st.name.as_ref() }))
}
