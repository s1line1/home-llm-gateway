//! 全局准入闸门：**谁能进**（豁免表）、**超限怎么拒**（429 + `Retry-After`）、以及
//! **准入票据怎么绑到 body 上**（覆盖整个请求，含 SSE 长流）。
//!
//! 为什么从 `observability.rs` 里搬出来（并集评估 §2 的 S1，三份样本里有两位都指向这里）：
//! 闸门是**资源正确性策略**，而那个文件承诺的是"id / 访问日志 / 状态码记账"——两条改动理由
//! 不同。搬出来之后本模块只留策略；票据与计数器仍住在 [`crate::metrics::Metrics`] 里，
//! 因为 `Admission::drop` 要写指标那几个原子——把它们一起搬走只会让两边接口都变大
//! （同评估里被否掉的那条候选）。
//!
//! **层序有硬要求**：本中间件必须在 `request_id_middleware` 的**里层**。被闸门拒掉的 429
//! 要经过外层才能带上回显的 `x-request-id`，状态码记账也才只发生一次（这里只补
//! `request_count`，外层统一 `record_status`）。回归测试：
//! `a_gate_rejection_still_echoes_the_client_request_id`、`concurrent_request_limit_rejects_with_429`。
//! 链序见 [`crate::http::app`]。

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use tracing::warn;

use crate::state::AppState;

pub(super) async fn admission_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    // `/metrics` 自己完全不记（抓取流量不该淹没真实告警），也**不占**闸门槽位。
    // 外层的 id 中间件对它同样直接放行，所以这一条不会被重复判定。
    if req.uri().path() == "/metrics" {
        return next.run(req).await;
    }
    let path = req.uri().path().to_string();
    // 外层已把规范化后的 `req-{n}` 写回入站头，这里沿用它做日志（客户端原值在外层的
    // 访问日志里另有 `client_request_id` 字段）。
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();
    let method = req.method().clone();
    // HTTP 全局在途上限（0 = 不限）：try_enter 原子占位（旧值判定，无竞态），
    // 超限返回 None → 立即 429，防多 key 总和压垮单实例。
    // 票据的释放完全由 Drop 负责，分两段：① 移交 body 之前（含客户端中断导致 future
    // 被 drop）→ 就地 Drop 归还；② 移交 body 之后 → 随 body 结束/丢弃归还。
    //
    // /healthz **豁免**（REBUILD §5.3 / R12）：闸门打满时探针若被 429，LB 会摘除实例、
    // systemd 会重启循环——把上游的"慢"放大成整机"全挂"。用 `0 = 不限` 表达豁免，
    // 于是 id、访问日志、在途与耗时记账与其它路径完全一致，区别只有"能不能被拒"。
    let limit = if path == "/healthz" {
        0
    } else {
        state.max_concurrent_requests
    };
    let Some(admission) = state.metrics.try_enter(limit) else {
        // 只补"被闸门拒掉也算一次请求"：`try_enter` 失败时没有自增，而状态码由外层统一记。
        state.metrics.record_rejected();
        warn!(
            request_id = %request_id,
            method = %method,
            path = %path,
            active = state.metrics.active_count(),
            limit,
            "concurrent request limit reached, rejecting 429"
        );
        return crate::openai::error_response(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "too many concurrent requests, retry later",
        );
    };

    // 把准入票据**移交**给 response body：槽位与耗时记账持有到 body 流结束、或中途
    // 被丢弃（客户端断开）为止。这样闸门才真正覆盖"整个请求"——LLM 的 SSE 长流恰恰
    // 是最需要被计入的场景；若在此处直接释放，闸门只能覆盖到首字节。
    let resp = next.run(req).await;
    let (parts, body) = resp.into_parts();
    let body = http_body_util::BodyExt::map_frame(body, move |frame| {
        let _held = &admission; // 仅为把票据生命周期绑定到 body 上，不改动任何帧
        frame
    });
    Response::from_parts(parts, axum::body::Body::new(body))
}

#[cfg(test)]
mod tests {
    use crate::http::app;
    use crate::http::test_util::test_state;
    use axum::http::StatusCode;
    use tower::ServiceExt; // `Router::oneshot`

    /// 规格（评估 §2 S1 的层序约束）：**闸门拒掉的 429 仍要带上回显的 `x-request-id`**。
    ///
    /// 这正是准入必须住在 id 中间件**里层**的原因：429 由本模块构造、由外层补头。用 UUID
    /// 形状的入站 id 做判据——规范化后的隧道 id 是 `req-{n}`，只有"外层真的跑了并把**客户端
    /// 原值**回显回来"才会看到那个 UUID。
    #[tokio::test]
    async fn a_gate_rejection_still_echoes_the_client_request_id() {
        let mut state = test_state(None);
        state.max_concurrent_requests = 1;
        let metrics = state.metrics.clone();
        let router = app(state);

        // 占住唯一的槽（limit=0 = 不限）
        let held = metrics.try_enter(0).expect("limit=0 必进");

        let uuid = "0197f1c2-9f0b-7c31-8a44-1b2c3d4e5f60";
        let resp = router
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/v1/models")
                    .header("x-request-id", uuid)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get("x-request-id")
                .and_then(|v| v.to_str().ok()),
            Some(uuid),
            "被闸门拒掉的响应也必须回显客户端原值（否则准入就被搬到了 id 中间件外层）"
        );

        drop(held);
    }
}
