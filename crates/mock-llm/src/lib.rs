//! mock-llm：模拟 OpenAI 兼容接口的假 LLM，用于在无真实模型时打通全链路。
//! 支持实例名，多 agent 场景下可用不同实例名区分上游来源。

use std::{
    convert::Infallible,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use async_stream::stream;
use axum::{
    body::{Body, Bytes},
    extract::DefaultBodyLimit,
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

/// mock 接受的请求体上限。
///
/// axum 的 `Json` 提取器**默认只收 2 MiB**，而被测的网关允许到 16 MiB
/// （`gateway::body::MAX_REQUEST_BODY`）⇒ 本地压大请求体时，会先在 mock 这里撞 413、
/// 或者写 body 时被 reset（agent 因此回 502 `local upstream request failed`），把
/// "网关/agent 能不能扛大 body"的测试卡在一个与它们无关的地方（2026-09-22 实测踩到）。
/// 放宽到 32 MiB：网关上限的两倍，留一倍余量。
pub const MOCK_MAX_REQUEST_BODY: usize = 32 * 1024 * 1024;

/// 持续产出 `chunks` 块、每块 `kb` KB（块间 `delay_ms` 毫秒，默认 0）。
/// 上游会一直产到被取消为止——这正是"客户端不读时会不会永久占住槽位"要考的场景。
async fn flood(
    State(st): State<AppState>,
    Query(p): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let num = |k: &str, d: u64| p.get(k).and_then(|v| v.parse().ok()).unwrap_or(d);
    let chunks = num("chunks", 100_000) as usize;
    let kb = (num("kb", 64) as usize).clamp(1, 1024);
    let delay = Duration::from_millis(num("delay_ms", 0));
    let payload = Bytes::from(vec![b'F'; kb * 1024]);
    let guard = CancelGuard::new(st.cancelled.clone());
    let s = stream! {
        let mut guard = guard;
        for _ in 0..chunks {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            yield Ok::<_, Infallible>(payload.clone());
        }
        guard.completed = true;
    };
    Response::builder()
        .header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        )
        .body(Body::from_stream(s))
        .unwrap()
}

/// 上游视角的"请求被取消"计数守卫。
///
/// 为什么需要它：`TODO.md:414-422` 登记了"`Cancel` → 上游确实被取消"缺**上游侧**断言——
/// 网关的日志能说它发了 Cancel，agent 的代码看起来也会丢上游请求，但"上游真的停了"只能由
/// 上游自己证明。放进响应体流里：流正常跑完置 `completed`；客户端（agent）中途断开/取消时
/// axum 丢掉 body → 生成器连同局部变量一起被 drop → Drop 里 +1。
///
/// 用法上的坑：`completed` 必须在 `stream!` 块**内部**的最后一行置位，不能放在块外——
/// 块外的代码在流被 drop 时根本不会执行，那就变成"永远算取消"。
struct CancelGuard {
    counter: Arc<AtomicU64>,
    completed: bool,
}

impl CancelGuard {
    fn new(counter: Arc<AtomicU64>) -> Self {
        Self {
            counter,
            completed: false,
        }
    }
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Clone)]
struct AppState {
    name: Arc<str>,
    /// 被中途丢弃的响应体数（= 上游观察到的取消次数），见 [`CancelGuard`]。
    cancelled: Arc<AtomicU64>,
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
        // 观测面：`cancelled` = 上游看到的"中途取消"次数（供 e2e 断言"Cancel 真的到了上游"）
        .route("/stats", get(stats))
        // 测试上游不该比被测系统更严：见 `MOCK_MAX_REQUEST_BODY`。
        .layer(DefaultBodyLimit::max(MOCK_MAX_REQUEST_BODY))
        .with_state(AppState {
            name: Arc::from(name),
            cancelled: Arc::new(AtomicU64::new(0)),
        })
}

/// 上游自述的观测数据：目前只有"被中途取消的响应体数"。
async fn stats(State(st): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "name": st.name.as_ref(),
        "cancelled": st.cancelled.load(Ordering::Relaxed),
    }))
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

/// 慢端点：先睡一会儿再响应（默认 800ms），用于测试网关超时/并发控制。
///
/// `?ms=N` 可调延迟——测"响应头超时但 agent 仍在正常回其它请求"这类场景需要把延迟
/// 推到 `head_timeout` 之上（见 `tests/e2e/stalls.rs`）。
async fn slow(
    State(st): State<AppState>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let ms = q.get("ms").and_then(|v| v.parse().ok()).unwrap_or(800);
    tokio::time::sleep(Duration::from_millis(ms)).await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    /// 规格：守卫只为**被中途丢弃**的流计数。
    ///
    /// 这个方向必须钉住，否则"上游观察到取消"这件事就没有意义了——如果 `completed` 忘了置位，
    /// 每个正常读完的 `/v1/flood` 也会被算成取消，那条 e2e 断言就变成永远为真。
    #[test]
    fn cancel_guard_counts_only_streams_that_were_dropped_early() {
        let counter = Arc::new(AtomicU64::new(0));

        // 正常跑完：在 `stream!` 块内部把 completed 置位（块外的代码在 drop 时不会执行）
        {
            let mut guard = CancelGuard::new(counter.clone());
            guard.completed = true;
        }
        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "正常结束的流不该算成取消"
        );

        // 中途丢弃
        {
            let _guard = CancelGuard::new(counter.clone());
        }
        assert_eq!(
            counter.load(Ordering::Relaxed),
            1,
            "被丢弃的流必须算成一次取消"
        );
    }

    /// 规格（2026-09-22 实测踩到的坑）：**mock 必须收下比 axum 默认 2 MiB 更大的请求体**，
    /// 否则本地大 body 测试会先在 mock 这里失败（413 或连接被 reset），把"网关/agent 能不能
    /// 扛大 body"卡在与它们无关的地方。
    ///
    /// 起真服务器 + 裸 socket 直接发，不用额外的 HTTP 客户端依赖（mock-llm 没有 dev-deps）。
    /// 请求体里用**被忽略的字段**填充，于是响应仍然很小。
    #[tokio::test(flavor = "multi_thread")]
    async fn a_body_larger_than_axums_default_limit_is_accepted() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router("big-body").into_make_service()).await;
        });

        // 4 MiB：超过 axum 的 2 MiB 默认上限，但在 `MOCK_MAX_REQUEST_BODY` 之内
        let pad = "a".repeat(4 * 1024 * 1024);
        let body = format!(
            r#"{{"model":"m","messages":[{{"role":"user","content":"hi"}}],"pad":"{pad}"}}"#
        );
        let head = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );

        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        sock.write_all(head.as_bytes()).await.unwrap();
        sock.write_all(body.as_bytes()).await.unwrap();

        let mut response = Vec::new();
        sock.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response);
        let status = text.lines().next().unwrap_or_default();
        assert!(
            status.contains("200"),
            "4 MiB 请求体必须被收下（axum 默认上限是 2 MiB，会回 413）：{status}"
        );
        assert!(
            text.contains("mock(big-body) reply to: hi"),
            "body 内容照旧要能解析出来：{}",
            &text[..text.len().min(200)]
        );
    }
}
