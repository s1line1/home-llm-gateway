//! mock-llm：模拟 OpenAI 兼容接口的假 LLM，用于在无真实模型时打通全链路。
//! 支持实例名，多 agent 场景下可用不同实例名区分上游来源。

use std::{convert::Infallible, sync::Arc, time::Duration};

use async_stream::stream;
use axum::{
    body::{Body, Bytes},
    extract::Query,
    extract::State,
    http::{
        header::{CACHE_CONTROL, CONTENT_TYPE},
        HeaderValue,
    },
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};

/// 持续产出 `chunks` 块、每块 `kb` KB（块间 `delay_ms` 毫秒，默认 0）。
/// 上游会一直产到被取消为止——这正是"客户端不读时会不会永久占住槽位"要考的场景。
async fn flood(Query(p): Query<std::collections::HashMap<String, String>>) -> Response {
    let num = |k: &str, d: u64| p.get(k).and_then(|v| v.parse().ok()).unwrap_or(d);
    let chunks = num("chunks", 100_000) as usize;
    let kb = (num("kb", 64) as usize).clamp(1, 1024);
    let delay = Duration::from_millis(num("delay_ms", 0));
    let payload = Bytes::from(vec![b'F'; kb * 1024]);
    let s = stream! {
        for _ in 0..chunks {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            yield Ok::<_, Infallible>(payload.clone());
        }
    };
    Response::builder()
        .header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        )
        .body(Body::from_stream(s))
        .unwrap()
}

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
        // 立刻回响应头、但正文迟迟不出：用来测**响应体空闲超时**（/v1/slow 卡的是响应头，
        // 属于另一条超时——网关的 head_timeout；两者语义不同，必须分开测）。
        .route("/v1/slow_body", post(slow_body))
        // 连续快速产出：用来测**背压与取消**——客户端停止消费时，网关必须放弃该请求
        // 并释放准入槽位（`?chunks=&kb=&delay_ms=`）。用一次性的固定大小响应测不出这件事：
        // 数据可以先塞进 socket 缓冲与通道，通道并不会一直满着。
        .route("/v1/flood", post(flood))
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

async fn chat(State(st): State<AppState>, Json(req): Json<serde_json::Value>) -> Response {
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

    let is_stream = req.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);

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
    let model = req
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or(st.name.as_ref());
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

/// `/v1/slow_body` 的正文停顿：故意取得比常见空闲超时（100–300ms）**长一个数量级**，
/// 这样"超时是否生效"与"机器快慢"就能明确区分开——如果测试里把超时调大，
/// 断言窗口（2s）仍远小于这个停顿（3s），不会因为 CI 机器慢而假失败。
pub const SLOW_BODY_STALL: Duration = Duration::from_secs(3);

/// 慢**正文**端点：响应头立刻返回（SSE），正文在 [`SLOW_BODY_STALL`] 后才出第一块。
/// 用于测「响应体逐帧空闲超时」——与 /v1/slow（卡响应头）语义不同。
async fn slow_body(State(st): State<AppState>) -> Response {
    let name = st.name.clone();
    let s = stream! {
        tokio::time::sleep(SLOW_BODY_STALL).await;
        let chunk = serde_json::json!({
            "id": "chatcmpl-slow-body",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": "mock-llm",
            "server": name.as_ref(),
            "choices": [{ "index": 0, "delta": { "content": "x" }, "finish_reason": null }]
        });
        yield Ok::<_, Infallible>(Bytes::from(format!("data: {chunk}\n\n")));
        yield Ok::<_, Infallible>(Bytes::from("data: [DONE]\n\n".to_string()));
    };
    Response::builder()
        .header(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"))
        .header(CACHE_CONTROL, HeaderValue::from_static("no-cache"))
        .body(Body::from_stream(s))
        .unwrap()
}
