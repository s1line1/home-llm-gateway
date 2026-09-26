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

use crate::metrics::AdmissionDomain;
use crate::state::AppState;

/// 探针（`/healthz`）域的独立上限（复扫 A3）。
///
/// **为什么不干脆不限**：`/healthz` 是公网**无认证**入口，完全不限等于留一个免费的资源消耗点
/// （连接、任务、fd 都要花钱）。但它也不能太小——给它任何上限都会在洪水场景下重新引入 R12
/// 那条失败模式（探针被 429 → LB 摘实例 → 把上游的"慢"放大成整机"全挂"），所以取一个
/// **显著高于任何正常探针并发**的值：正常 LB 就几条探针，64 足够宽松，同时给洪水封了顶。
///
/// 它**不**与 `max_concurrent_requests` 共享计数：那条是受限路径的预算，探针占它就会让
/// `/v1` 在探针洪水下全线 429（见 [`AdmissionDomain`]）。
const MAX_CONCURRENT_PROBES: u32 = 64;

/// 路径 → `(准入域, 该域的上限)`。
///
/// 抽成纯函数是为了让**接线**本身可测：这条映射写错（例如 `/healthz` 落回受限域），
/// `Metrics` 那边的域隔离做得再对也没用——探针照样吃 `/v1` 的额度。
fn admission_domain(path: &str, gated_limit: u32) -> (AdmissionDomain, u32) {
    if path == "/healthz" {
        (AdmissionDomain::Probe, MAX_CONCURRENT_PROBES)
    } else {
        (AdmissionDomain::Gated, gated_limit)
    }
}

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
    // HTTP 全局在途上限（0 = 不限）：try_enter **CAS 占位**（记录 R8：不再用
    // `fetch_add` + 超限回滚，那会在回滚前留下"幽灵占位"、连锁误拒闸门其实为空的请求），
    // 超限返回 None → 立即 429，防多 key 总和压垮单实例。
    // 票据的释放完全由 Drop 负责，分两段：① 移交 body 之前（含客户端中断导致 future
    // 被 drop）→ 就地 Drop 归还；② 移交 body 之后 → 随 body 结束/丢弃归还。
    //
    // /healthz **豁免受限闸门**（REBUILD §5.3 / R12）：闸门打满时探针若被 429，LB 会摘除实例、
    // systemd 会重启循环——把上游的"慢"放大成整机"全挂"。
    //
    // 但"豁免"必须是**不占受限预算**，不能只是"不能被拒"（复扫 A3）：先前用 `limit = 0` 表达，
    // 而 `0` 免掉的只是上限判定——领票、计数照旧，加的还是受限路径用来比较的**同一个**计数器
    // ⇒ 一个无认证的探针洪水就能把 `/v1` 顶到 429，而 LB 看到探针 200、认为实例健康。
    // 现在它进**探针域**：有自己的在途计数与自己的宽松上限（`MAX_CONCURRENT_PROBES`），与受限域
    // 互不影响；而 id、访问日志、`hlmg_active_requests` 与耗时记账与其它路径仍然完全一致。
    let (domain, limit) = admission_domain(&path, state.max_concurrent_requests);
    let Some(admission) = state.metrics.try_enter(limit, domain) else {
        // 只补"被闸门拒掉也算一次请求"：`try_enter` 失败时没有自增，而状态码由外层统一记。
        state.metrics.record_rejected();
        match domain {
            // 探针被拒说明是**洪水**（正常 LB 那几条碰不到 64），这条日志是它唯一的信号。
            AdmissionDomain::Probe => warn!(
                request_id = %request_id,
                method = %method,
                path = %path,
                probes = state.metrics.active_probe_count(),
                max_probes = MAX_CONCURRENT_PROBES,
                "probe concurrency limit reached, rejecting 429"
            ),
            AdmissionDomain::Gated => warn!(
                request_id = %request_id,
                method = %method,
                path = %path,
                active = state.metrics.active_count(),
                gated = state.metrics.active_gated_count(),
                limit,
                "concurrent request limit reached, rejecting 429"
            ),
        }
        // 429 的 `Retry-After` 给 1s（复扫 A4）：准入槽位在**任何**在途请求结束时释放，通常是
        // 亚秒级；原先那个写死的 60s 是凭空的，按它退避的客户端白等一分钟。
        return crate::openai::rate_limited("too many concurrent requests, retry later", 1);
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
    use super::{admission_domain, MAX_CONCURRENT_PROBES};
    use crate::http::app;
    use crate::http::test_util::test_state;
    use crate::metrics::AdmissionDomain;
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
        let held = metrics
            .try_enter(0, AdmissionDomain::Gated)
            .expect("limit=0 必进");

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

    /// 规格（复扫 A3）：**`/healthz` 必须落在探针域**，其余路径落在受限域。
    ///
    /// 这条测的是接线：`Metrics` 的域隔离再对，映射写错也白搭——探针会重新吃 `/v1` 的额度。
    #[test]
    fn healthz_maps_to_the_probe_domain_and_everything_else_to_the_gated_one() {
        assert_eq!(
            admission_domain("/healthz", 7),
            (AdmissionDomain::Probe, MAX_CONCURRENT_PROBES),
            "探针必须进自己的域，且用探针自己的上限"
        );
        for gated in ["/v1/models", "/v1/chat/completions", "/", "/admin/keys"] {
            assert_eq!(
                admission_domain(gated, 7),
                (AdmissionDomain::Gated, 7),
                "{gated} 必须走受限域、用配置的上限"
            );
        }
        // 只认精确路径：别让 `/healthz/` 或前缀把别的请求也拖进探针域（那等于绕过受限闸门）。
        assert_eq!(
            admission_domain("/healthz/", 7),
            (AdmissionDomain::Gated, 7),
            "只有精确的 /healthz 才是探针"
        );
    }
}
