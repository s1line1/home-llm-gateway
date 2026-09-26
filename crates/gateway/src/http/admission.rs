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
//!
//! **三个域**（复扫 A3 / A8）：受限（`max_concurrent_requests`）、探针（`/healthz`，自己的常量
//! 上限）、抓取（`/metrics`，自己的常量上限）。域之间只共享"在途总数"这一个读数，额度互不相欠
//! ——任何两条路径共用一个域，其中一条的洪水就能把另一条顶成 429（`/v1` 全量失败、或 LB 摘掉一个
//! 健康实例）。抓取域另有两点不同：它**不算一次请求**（外层对它整段放行，记了会让
//! `request_count − Σ状态码 − aborted` 每次抓取漂移 +1），因此它的拒绝**只出现在本模块的日志
//! 里**，不进状态码/访问日志。

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use tracing::warn;

use crate::metrics::{Admission, AdmissionDomain};
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

/// `/metrics` 抓取域的独立上限（复扫 A8）。
///
/// **与探针域分开计数**（哪怕取值同一个量级）：共享一个域等于"抓取洪水能把 `/healthz` 顶成
/// 429"——那正是 R12 那条失败模式（LB 摘掉一个**健康**实例）的另一个入口，而 A3 刚刚才把
/// `/v1` 那一侧封上。`/metrics` 进自己的域之后，"有多少在途"这件事第一次有上界。
///
/// 取值口径与 [`MAX_CONCURRENT_PROBES`] 相同：**显著高于任何正常抓取并发**（Prometheus 对单个
/// target 通常 1 条在途；Dashboard 每个标签页 5s 一次、在途 1 条），所以正常运维碰不到它；洪水
/// （或一堆慢读者）到这里封顶。它**不承诺"不被拒"**：固定上限总会被更大的洪水撞到，目标是给
/// fd/任务封顶，而不是零拒绝。
const MAX_CONCURRENT_SCRAPES: u32 = 64;

/// 路径 → `(准入域, 该域的上限)`。
///
/// 抽成纯函数是为了让**接线**本身可测：这条映射写错（例如 `/healthz` 落回受限域），
/// `Metrics` 那边的域隔离做得再对也没用——探针照样吃 `/v1` 的额度。
fn admission_domain(path: &str, gated_limit: u32) -> (AdmissionDomain, u32) {
    match path {
        "/healthz" => (AdmissionDomain::Probe, MAX_CONCURRENT_PROBES),
        // 复扫 A8：`/metrics` 曾经在这里**直接放行**（连票都不领）——"抓取流量不该淹没真实
        // 告警"是对的，但"不进计数"与"没有上限"是两件事：一条无认证路径完全不设界，靠的就只剩
        // `max_entry_connections` 与 `client_stall` 兜底；而 A3 之后，两条公开路径里只剩它无界。
        "/metrics" => (AdmissionDomain::Scrape, MAX_CONCURRENT_SCRAPES),
        _ => (AdmissionDomain::Gated, gated_limit),
    }
}

/// 把准入票据**移交**给响应 body：槽位持有到 body 流结束、或中途被丢弃（客户端断开）为止。
/// 这样闸门才真正覆盖"整个请求"——LLM 的 SSE 长流恰恰是最需要被计入的场景；若在 `next.run`
/// 之后就地释放，闸门只能覆盖到首字节。三条路径（受限/探针/抓取）共用同一个移交实现，免得
/// "抓取这条忘了移交"变成另一种无界。
fn hold_until_body_ends(resp: Response, admission: Admission) -> Response {
    let (parts, body) = resp.into_parts();
    let body = http_body_util::BodyExt::map_frame(body, move |frame| {
        let _held = &admission; // 仅为把票据生命周期绑定到 body 上，不改动任何帧
        frame
    });
    Response::from_parts(parts, axum::body::Body::new(body))
}

pub(super) async fn admission_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    // 外层已把规范化后的 `req-{n}` 写回入站头，这里沿用它做日志（客户端原值在外层的
    // 访问日志里另有 `client_request_id` 字段）。`/metrics` 不经过外层，所以这里是 `-`。
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
    //
    // /metrics 是第三种（复扫 A8）：自己的域 + 自己的上限，且**只领额度、不算一次请求**
    // （`try_enter_uncounted`）——它不走 id/访问日志/状态码那条链，记账会让
    // `request_count − Σ状态码 − aborted` 每次抓取各漂移 +1。
    let (domain, limit) = admission_domain(&path, state.max_concurrent_requests);
    let ticket = if domain == AdmissionDomain::Scrape {
        state.metrics.try_enter_uncounted(limit, domain)
    } else {
        state.metrics.try_enter(limit, domain)
    };
    let Some(admission) = ticket else {
        // 受限域与探针域都会经过外层的状态码记账，所以这里**只补** `request_count` 那一半；
        // 抓取域完全不同（外层对它整段放行），补了反而破坏恒等式，所以那一支不补。
        match domain {
            AdmissionDomain::Gated | AdmissionDomain::Probe => state.metrics.record_rejected(),
            AdmissionDomain::Scrape => {}
        }
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
            // 抓取的拒绝**只在这条日志里**（不进 request_count/状态码/访问日志），这正是
            // "抓取流量不该淹没真实告警"的另一半：它不污染请求指标，但洪水有界、也有据可查。
            AdmissionDomain::Scrape => warn!(
                method = %method,
                path = %path,
                scrapes = state.metrics.active_scrape_count(),
                max_scrapes = MAX_CONCURRENT_SCRAPES,
                "metrics scrape concurrency limit reached, rejecting 429"
            ),
        }
        // 429 的 `Retry-After` 给 1s（复扫 A4）：准入槽位在**任何**在途请求结束时释放，通常是
        // 亚秒级；原先那个写死的 60s 是凭空的，按它退避的客户端白等一分钟。
        return crate::openai::rate_limited("too many concurrent requests, retry later", 1);
    };

    hold_until_body_ends(next.run(req).await, admission)
}

#[cfg(test)]
mod tests {
    use super::{admission_domain, MAX_CONCURRENT_PROBES, MAX_CONCURRENT_SCRAPES};
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

    /// 规格（复扫 A3 / A8）：**两条无认证路径各进各的域**（`/healthz` → 探针、`/metrics` →
    /// 抓取），其余路径落在受限域。
    ///
    /// 这条测的是接线：`Metrics` 的域隔离再对，映射写错也白搭——探针会重新吃 `/v1` 的额度，
    /// 抓取会重新无界（或把探针顶掉）。
    #[test]
    fn healthz_and_metrics_map_to_their_own_domains_and_the_rest_to_the_gated_one() {
        assert_eq!(
            admission_domain("/healthz", 7),
            (AdmissionDomain::Probe, MAX_CONCURRENT_PROBES),
            "探针必须进自己的域，且用探针自己的上限"
        );
        assert_eq!(
            admission_domain("/metrics", 7),
            (AdmissionDomain::Scrape, MAX_CONCURRENT_SCRAPES),
            "抓取必须进自己的域（不能进探针域：抓取洪水会把 /healthz 顶成 429），且用自己的上限"
        );
        for gated in ["/v1/models", "/v1/chat/completions", "/", "/admin/keys"] {
            assert_eq!(
                admission_domain(gated, 7),
                (AdmissionDomain::Gated, 7),
                "{gated} 必须走受限域、用配置的上限"
            );
        }
        // 只认精确路径：别让 `/healthz/` 或前缀把别的请求也拖进豁免域（那等于绕过受限闸门）。
        for prefixed in ["/healthz/", "/metrics/", "/metrics/prometheus"] {
            assert_eq!(
                admission_domain(prefixed, 7),
                (AdmissionDomain::Gated, 7),
                "只有精确的 /healthz 与 /metrics 才豁免，{prefixed} 不行"
            );
        }
    }

    /// 规格（复扫 A8）：**`/metrics` 有自己的一块额度**，与受限域、探针域互不相欠。
    ///
    /// 修复前它对中间件直接放行：一条公开、无认证的路径完全不设界（A3 之后只剩它）。现在它进
    /// 抓取域，满了就 429；而受限域打满**不影响**它，它的洪水也**不影响**探针。
    #[tokio::test]
    async fn a_saturated_scrape_budget_rejects_metrics_but_not_healthz() {
        use tower::ServiceExt;

        let mut state = test_state(None);
        state.max_concurrent_requests = 1;
        let metrics = state.metrics.clone();
        let router = app(state);

        // ① 受限域打满 ≠ `/metrics` 被拒：抓取花的不是受限预算（A3 那条不变量的抓取版本）
        let gated = metrics
            .try_enter(1, AdmissionDomain::Gated)
            .expect("占住唯一的受限额度");
        let resp = router
            .clone()
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "受限域满了不该拒 /metrics —— 它有自己的预算（复扫 A8）"
        );
        assert_eq!(metrics.active_gated_count(), 1, "抓取同样不该推动受限计数");
        drop(resp);
        assert_eq!(
            metrics.active_scrape_count(),
            0,
            "响应 body 被丢弃后抓取票必须归还（票据绑在 body 上）"
        );

        // ② 抓取域打满 ⇒ `/metrics` 429；探针不受影响（这一条是"分开计数"的全部意义）
        let held: Vec<_> = (0..MAX_CONCURRENT_SCRAPES)
            .map(|_| {
                metrics
                    .try_enter_uncounted(MAX_CONCURRENT_SCRAPES, AdmissionDomain::Scrape)
                    .expect("抓取预算内")
            })
            .collect();
        let resp = router
            .clone()
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "抓取域满了必须 429（修复前这条路径完全没有上限）"
        );
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
            StatusCode::OK,
            "抓取洪水不得把探针顶成 429 —— 那会让 LB 摘掉一个健康实例（R12 的另一种入口）"
        );
        drop(resp);

        // ③ 上限是"在途"而不是"频率"：放开一个抓取票就立刻能再抓
        drop(held.into_iter().next().expect("至少持有一张"));
        let resp = router
            .clone()
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "释放一张票后应当立刻能抓");
        drop((resp, gated));
    }

    /// 规格（复扫 A8 的另一半）：**抓取不进请求账本**。
    ///
    /// `/metrics` 绕过 id / 访问日志 / 状态码那条链，而仓库自用的恒等式
    /// `request_count − Σ状态码 − aborted == 0` 依赖"记了状态码才算一次请求"。抓取票因此走
    /// `try_enter_uncounted`：`request_count`、`active`（`hlmg_active_requests` 与 `drain()` 的
    /// 读数）、耗时记账一个都不动。若哪天有人把它换回 `try_enter`，每次抓取都会让恒等式 +1，
    /// 真正的槽位泄漏就被淹没了——这条测试就是那个不变量在抓取路径上的守卫。
    #[tokio::test]
    async fn metrics_scrapes_stay_out_of_the_request_books() {
        use tower::ServiceExt;

        let state = test_state(None);
        let metrics = state.metrics.clone();
        let router = app(state);

        let before = metrics.identity_terms();
        let resp = router
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            metrics.active_count(),
            0,
            "抓取不算在途请求（否则 hlmg_active_requests 与 drain 的判据会被抓取流量扰动）"
        );
        assert_eq!(
            metrics.identity_terms(),
            before,
            "一次成功的抓取不得动 request_count / Σ状态码 / aborted"
        );

        drop(resp);
        assert_eq!(
            metrics.active_scrape_count(),
            0,
            "抓取票必须随 body 一起归还"
        );
        assert_eq!(
            metrics.identity_terms(),
            before,
            "归还路径同样不得动请求账本"
        );
    }
}
