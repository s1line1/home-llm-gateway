//! 请求路径的中间件：`x-request-id`、全局并发闸门、访问日志，以及**准入票据的移交**。
//!
//! 三条策略在这里，但它们不是并列的——第 3 条是前两条能成立的前提：
//!
//! 1. **id**：客户端自带 `x-request-id` 则沿用（幂等重试可对账），否则分配 `req-{n}`；
//!    同时写响应头与**入站 headers**，后者供 `proxy` 复用为隧道 `request_id`。
//!    ⚠️ 已知缺口（TODO 登记）：`proxy` 只认 `req-<u64>` 形状，真实客户端（Codex/DSH）
//!    发的是 UUID → 它会回落到 `proxy` 里**另一个**同名计数器，两边都从 1 开始 → 可能撞号。
//! 2. **闸门**：`max_concurrent_requests` 是全局在途上限（`/metrics` 豁免），超限立即 429，
//!    防多 key 总和压垮单实例。
//! 3. **票据移交**：`Admission` 的释放**完全由 Drop 负责**，且分两段——移交 body 之前
//!    （含客户端中断导致 future 被 drop）就地归还；移交之后随 body 结束/丢弃归还。
//!    移交用 `map_frame` 把票据绑在 body 上，于是闸门覆盖的是**整个请求**，包括 LLM 的
//!    SSE 长流（恰恰最需要被计入）。这条契约是 `io_stall::WriteStall` 存在的原因：
//!    hyper 没有写超时，客户端不读就永远不 drop body → 票据永不归还（实测 8 个僵尸槽位）。
//!
//! 访问日志分级（target `gateway::access`）：<400 debug / 4xx info / 5xx error；
//! `/metrics` 自身完全不记（抓取流量不该淹没真实告警）。
//! 需要临时恢复全量访问日志：`RUST_LOG=info,gateway::access=debug`。

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use tracing::{debug, error, info, warn};

use crate::state::AppState;

/// 记录请求状态码与耗时（/metrics 自身不计入），并为每个请求生成/透传
/// `x-request-id`（响应头 + 写进入站 headers 供 proxy 复用为隧道 request_id，
/// 使 HTTP 层、隧道层、日志三方对账一致）。
///
/// 访问日志分级（target `gateway::access`），避免每请求一条 info 淹没真正的
/// warn/error 日志：
///   - status < 400 → debug（正常流量；状态码/耗时已由 /metrics 覆盖）
///   - 400..=499     → info（客户端/路由类异常，代码多静默返回，仅此可见）
///   - status >= 500 → error（真实失败：tunnel/upstream/内部错误）
///
/// 需要临时恢复全量访问日志：`RUST_LOG=info,gateway::access=debug`
pub(super) async fn metrics_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    if req.uri().path() == "/metrics" {
        return next.run(req).await;
    }
    // 客户端自带 x-request-id 则沿用（幂等重试对账），否则分配
    let request_id = match req.headers().get("x-request-id") {
        Some(v) => v.to_str().unwrap_or_default().to_string(),
        None => {
            let id = NEXT_REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let id = format!("req-{id}");
            if let Ok(v) = axum::http::HeaderValue::from_str(&id) {
                req.headers_mut().insert("x-request-id", v);
            }
            id
        }
    };
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    // HTTP 全局在途上限（0 = 不限）：try_enter 原子占位（旧值判定，无竞态），
    // 超限返回 None → 立即 429，防多 key 总和压垮单实例。
    // 票据的释放完全由 Drop 负责，分两段：① 移交 body 之前（含客户端中断导致 future
    // 被 drop）→ 就地 Drop 归还；② 移交 body 之后 → 随 body 结束/丢弃归还。
    let limit = state.max_concurrent_requests;
    let Some(admission) = state.metrics.try_enter(limit) else {
        state.metrics.record_rejected(429);
        let mut resp = crate::openai::error_response(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "too many concurrent requests, retry later",
        );
        if let Ok(v) = axum::http::HeaderValue::from_str(&request_id) {
            resp.headers_mut().insert("x-request-id", v);
        }
        warn!(
            request_id = %request_id,
            method = %method,
            path = %path,
            active = state.metrics.active_count(),
            limit,
            "concurrent request limit reached, rejecting 429"
        );
        return resp;
    };
    let start = admission.started_at();
    let mut resp = next.run(req).await;
    let status = resp.status().as_u16();
    state.metrics.record_status(status);
    if let Ok(v) = axum::http::HeaderValue::from_str(&request_id) {
        resp.headers_mut().insert("x-request-id", v);
    }
    // 访问日志记的是"到首字节"的延迟（TTFB）；完整请求耗时的记账在准入票据里，
    // 它在 body 结束时才结算（见下方移交），故两者字段名区分开。
    let ttfb_ms = start.elapsed().as_millis() as u64;
    match status {
        400..=499 => info!(
            target: "gateway::access",
            request_id = %request_id,
            method = %method,
            path = %path,
            status,
            ttfb_ms,
            "request failed (client error)"
        ),
        s if s >= 500 => error!(
            target: "gateway::access",
            request_id = %request_id,
            method = %method,
            path = %path,
            status,
            ttfb_ms,
            "request failed (server error)"
        ),
        _ => debug!(
            target: "gateway::access",
            request_id = %request_id,
            method = %method,
            path = %path,
            status,
            ttfb_ms,
            "request handled"
        ),
    }

    // 把准入票据**移交**给 response body：槽位与耗时记账持有到 body 流结束、或中途
    // 被丢弃（客户端断开）为止。这样闸门才真正覆盖"整个请求"——LLM 的 SSE 长流恰恰
    // 是最需要被计入的场景；若在此处直接释放，闸门只能覆盖到首字节。
    let (parts, body) = resp.into_parts();
    let body = http_body_util::BodyExt::map_frame(body, move |frame| {
        let _held = &admission; // 仅为把票据生命周期绑定到 body 上，不改动任何帧
        frame
    });
    Response::from_parts(parts, axum::body::Body::new(body))
}

static NEXT_REQUEST_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[cfg(test)]
mod tests {
    use crate::http::app;
    use crate::http::test_util::test_state;
    use crate::metrics::Metrics;
    use crate::storage::KeyStore;
    use axum::http::StatusCode;
    use std::time::Duration;
    use tower::ServiceExt;

    #[tokio::test]
    async fn x_request_id_generated_and_echoed() {
        // /healthz 经 metrics_middleware：响应带 x-request-id；客户端自带则沿用
        let router = app(test_state(None));

        // 无自带 → 生成 req-N 并回显
        let resp = router
            .clone()
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let rid = resp
            .headers()
            .get("x-request-id")
            .expect("x-request-id set on response")
            .to_str()
            .unwrap()
            .to_string();
        assert!(rid.starts_with("req-"), "generated id format req-N: {rid}");

        // 客户端自带 → 沿用（幂等重试对账）
        let resp = router
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/healthz")
                    .header("x-request-id", "req-999")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.headers()
                .get("x-request-id")
                .unwrap()
                .to_str()
                .unwrap(),
            "req-999",
            "client-supplied id is echoed"
        );
    }

    #[tokio::test]
    async fn concurrent_request_limit_rejects_with_429() {
        // max_concurrent_requests=1：先人为占住 1 个在途 → 第二个请求 429
        let mut state = test_state(None);
        state.max_concurrent_requests = 1;
        let metrics = state.metrics.clone();
        let router = app(state);

        // 占住唯一的并发槽（limit=0 = 不限，必进；票据持有到 drop 为止）
        let held = metrics
            .try_enter(0)
            .expect("limit=0 admits unconditionally");
        let resp = router
            .clone()
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "second concurrent request over limit must be rejected"
        );
        assert_eq!(
            resp.headers().get(axum::http::header::RETRY_AFTER),
            Some(&axum::http::HeaderValue::from_static("60")),
            "429 carries Retry-After"
        );
        drop(held); // 票据 Drop → 释放槽位

        // 槽位释放后恢复
        let resp = router
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn zero_limit_never_rejects() {
        // max_concurrent_requests=0（默认）→ 不限
        let router = app(test_state(None));
        let resp = router
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn try_enter_is_atomic_under_concurrency() {
        // limit=1：8 个线程同时 try_enter → 恰 1 个成功（无 check-then-act 竞态）。
        // 这是 e2e 曾出现 [429,429] 双拒的根因回归测试。
        // 票据随返回值离开线程并在此持有，保证 8 次尝试真正并发竞争同一个槽位。
        let metrics = Metrics::default();
        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = metrics.clone();
            handles.push(std::thread::spawn(move || m.try_enter(1)));
        }
        let admissions: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let admitted = admissions.iter().filter(|a| a.is_some()).count();
        assert_eq!(admitted, 1, "exactly one concurrent entry admitted");
        // 占用未释放时后续仍拒；票据 Drop 后恢复
        assert!(metrics.try_enter(1).is_none());
        drop(admissions); // 释放占用的那个
        assert!(metrics.try_enter(1).is_some());
    }

    /// 规格：API Key 校验（argon2，单次 10-30ms CPU）**不得阻塞 async worker**。
    ///
    /// 用默认的 current-thread runtime：worker 一旦被同步阻塞，其它任务（这里是 1ms
    /// 周期的计时任务）完全无法推进。把 argon2 放回请求路径上同步执行，本测试即红。
    #[tokio::test]
    async fn key_verification_does_not_block_the_runtime() {
        use std::sync::{
            atomic::{AtomicU32, Ordering},
            Arc,
        };

        // 真实 KeyStore（argon2 校验真的会跑）；key 在计时任务起跑前先建好
        let store = KeyStore::new(None);
        let created = store.create("blocking-test".into());
        let mut state = test_state(None);
        state.key_store = store;
        let router = app(state);

        // 1ms 周期的计时任务：只有 runtime 让出线程时才会推进
        let ticks = Arc::new(AtomicU32::new(0));
        let t = Arc::clone(&ticks);
        let ticker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(1)).await;
                t.fetch_add(1, Ordering::Relaxed);
            }
        });
        tokio::time::sleep(Duration::from_millis(5)).await;
        let before = ticks.load(Ordering::Relaxed);

        let resp = router
            .oneshot(
                axum::extract::Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header(
                        axum::http::header::AUTHORIZATION,
                        format!("Bearer {}", created.plaintext),
                    )
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(r#"{"model":"m","messages":[]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let ticks_during = ticks.load(Ordering::Relaxed) - before;
        ticker.abort();

        // 认证已通过（无 agent → 503），说明 argon2 确实被执行过
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "key should authenticate, then fail for lack of an agent"
        );
        assert!(
            ticks_during >= 5,
            "argon2 校验阻塞了 runtime：1ms 计时任务在整段校验期间只推进了 {ticks_during} 次\
                 （校验本身 10-30ms，放到阻塞线程池后应推进几十次）"
        );
    }

    /// 客户端在 handler 返回前中断（请求 future 被 drop）**不得**泄漏全局并发槽位。
    ///
    /// 回归背景：释放原先只挂在中间件尾部（`next.run(req).await` 之后），而 hyper 会在
    /// 连接断开时直接 drop 在途 future → 尾部永不执行 → 槽位永久占住，此后**所有**请求
    /// （含 /healthz）被打成 429，只能重启网关。
    #[tokio::test]
    async fn aborted_request_does_not_leak_concurrency_slot() {
        let mut state = test_state(None);
        state.admin_token = Some("admin".into());
        state.max_concurrent_requests = 1;
        let router = app(state);

        // /admin/keys 的 handler 会 parked 在 spawn_blocking(argon2)（约 10-30ms），
        // 1ms 后放弃即落在窗口内。多次尝试确保至少一次落在窗口内：若全部正常返回，
        // 本测试会退化成空转（不会误报，但也拦不住回归）。
        for _ in 0..30 {
            let req = axum::extract::Request::builder()
                .method("POST")
                .uri("/admin/keys")
                .header(axum::http::header::AUTHORIZATION, "Bearer admin")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(r#"{"name":"probe"}"#))
                .unwrap();
            let _ =
                tokio::time::timeout(Duration::from_millis(1), router.clone().oneshot(req)).await;
        }

        // 用户可见契约：中断后槽位必须已释放，后续请求不得被 429
        let resp = router
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "aborted in-flight request leaked the concurrency slot"
        );
    }
}
