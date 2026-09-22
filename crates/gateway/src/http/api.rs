//! 网关**自己回答**的端点：`/healthz`、`/metrics`、`/v1/models`。
//!
//! 它们的共同点是不经隧道：健康探针、Prometheus 抓取、以及把"当前有哪些模型可用"
//! 聚合成 OpenAI 兼容的 `/v1/models`。判定与聚合的细节都留在这里，路由表只管挂载。
//!
//! `/metrics` 有一个双面行为：Prometheus 抓取（`Accept: */*`）拿文本，浏览器直接访问
//! （`Accept: text/html`）拿 SPA——这是为了让浏览器刷新指标页也能渲染，而不是看到一坨文本。

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::state::AppState;

/// 存活探针：状态码回答**唯一一个"探针还答得上、但实例已经没用"**的问题——
/// 隧道入口是否还在接受新 agent（`hlmg_quic_accepting`）。
///
/// 200 ⇔ 隧道入口接受中；否则 503 + `status: "degraded"`。为什么是这个判据、为什么不是别的：
/// - **它必须进状态码**：QUIC 端点停摆后进程、systemd、HTTP 入口、`/metrics` 全都正常，
///   而此后每个 `/v1` 都会 503（没有 agent 能接入）——`quic.rs` 那条 `error!` 说的正是
///   "需要重启网关"，让 LB / 编排器重启它是唯一有效的处置，而它们只看状态码。
/// - **HTTP 入口自己不查**：它一停，探针本身就不可达（`TcpListener` 随任务结束被 drop），
///   探针失败即是信号；在这里"自检"只会得到永远不会为假的判断。
/// - **agent 数不进状态码**（只在 body 里报）：没有 agent ≠ 进程不健康。把它塞进来会让
///   "刚启动、还没等到 agent 注册"变成探针失败 → LB 摘除 / 容器重启循环，而重启并不能让
///   agent 出现。要按 readiness 摘流的部署自己读 body 的 `agents.healthy`。
/// - **落库可写性也不进**（`TODO.md` R12 的结转项）：唯一可靠的判据是"真写一次"，而 SQLite
///   目前没有 `busy_timeout`（P2-7），探针的写入可能撞 `SQLITE_BUSY` 把健康实例判死。
///
/// body 是 JSON（早期是纯文本 `ok`）；**状态码与 body 的 `status` 永远一致**，
/// `agents.oldest_last_seen_secs_ago` 用来区分"没人注册"与"有人但全过期"（`null` = 注册表为空）。
pub(super) async fn healthz(State(state): State<AppState>) -> Response {
    let accepting = state.metrics.quic_accepting() == 1;
    let status = state.registry.status(state.agent_stale_after);

    let mut body = json!({
        "status": if accepting { "ok" } else { "degraded" },
        "tunnel_entry": if accepting { "accepting" } else { "stopped" },
        "agents": {
            "registered": status.registered,
            "healthy": status.healthy,
            "oldest_last_seen_secs_ago": status.oldest_last_seen_ago.map(|d| d.as_secs()),
        },
    });
    if !accepting {
        body["detail"] =
            json!("the tunnel entry stopped accepting new agents; restart the gateway");
    }

    let code = if accepting {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body)).into_response()
}

/// OpenAI 兼容 `/v1/models`：聚合所有**健康** agent 显式声明的模型并集
/// （`["*"]` 全匹配的 agent 不贡献条目——它接受任意请求，但具体能跑什么
/// 只有上游知道，列出会误导客户端）。与代理入口同级的认证 + 限流。
pub(super) async fn models_route(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(rejection) = crate::auth::authenticate(&state, &headers).await {
        return rejection.into_response();
    }
    let data: Vec<_> = state
        .registry
        .healthy_models(state.agent_stale_after)
        .into_iter()
        .map(|id| {
            json!({
                "id": id,
                "object": "model",
                "created": 0,
                "owned_by": "edge-agent",
            })
        })
        .collect();
    Json(json!({ "object": "list", "data": data })).into_response()
}

/// Prometheus 文本格式指标。
/// 浏览器直接访问/刷新（`Accept: text/html`）时返回 SPA 页面，让前端路由渲染指标页；
/// Prometheus 抓取与前端解析（`Accept: */*`）仍拿到文本。
pub(super) async fn metrics_route(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let wants_html = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false);
    if wants_html {
        // 走 `AppState` 里的缓存读（按 mtime 校验）：以前这里每次请求同步
        // `std::fs::read_to_string`，是在 async 上下文里做阻塞 I/O。
        if let Some(index) = &state.ui_index {
            if let Some(html) = index.load().await {
                return Html(html.to_string()).into_response();
            }
        }
    }
    // 已验证身份缓存的命中/未命中：命中多说明 argon2 复用良好（内存/CPU 都省）
    let (verify_hits, verify_misses) = state.key_store.verified_counters();
    // 注册条目数 与 真正可路由数必须分开暴露：前者含失联但连接未关的 agent，
    // 排查"全部请求 503"时只有后者能说明问题（见 `hlmg_agents_healthy` 的 HELP）。
    let healthy = state.registry.healthy_count(state.agent_stale_after);
    state
        .metrics
        .render(state.registry.len(), healthy, verify_hits, verify_misses)
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::test_util::{body_str, headers_with_accept, test_state};
    use axum::http::StatusCode;

    #[tokio::test]
    async fn metrics_browser_request_serves_spa() {
        // 浏览器（Accept: text/html）直接访问 /metrics → SPA 页面
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<div id=\"root\">ui</div>").unwrap();
        let state = test_state(Some(dir.path().to_path_buf()));

        let resp = metrics_route(State(state.clone()), headers_with_accept("text/html")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            body_str(resp).await.contains("id=\"root\""),
            "browser should get the SPA"
        );

        // 未配 ui_dir 时降级为 Prometheus 文本
        let state2 = test_state(None);
        let resp = metrics_route(State(state2.clone()), headers_with_accept("text/html")).await;
        assert!(body_str(resp).await.contains("hlmg_requests_total"));
    }

    #[tokio::test]
    async fn metrics_scraper_gets_prometheus_text() {
        // Prometheus 抓取 / 前端 fetch（Accept: */* 或无 Accept）→ 文本
        let state = test_state(None);
        let resp = metrics_route(State(state.clone()), headers_with_accept("*/*")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let text = body_str(resp).await;
        assert!(text.contains("# TYPE hlmg_requests_total counter"));
        assert!(text.contains("hlmg_agents"));
    }

    /// 规格（R12）：**隧道入口停摆时必须 503**——这是唯一一个"探针还答得上、但实例已经没用"
    /// 的故障（QUIC 端点停了以后进程、systemd、HTTP 入口、`/metrics` 全都正常，而此后每个
    /// `/v1` 都会 503）。修复前这里恒返 `200 "ok"`。
    #[tokio::test]
    async fn healthz_is_degraded_while_the_tunnel_entry_is_not_accepting() {
        let state = test_state(None);
        // 测试态默认置成"接受中"（见 test_util），这里显式制造"入口停摆"
        state.metrics.set_quic_accepting_for_test(false);

        let resp = healthz(State(state)).await;
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "隧道入口没在接受新 agent 时必须是 503"
        );
        let v: serde_json::Value =
            serde_json::from_str(&body_str(resp).await).expect("body 是 JSON");
        assert_eq!(v["status"], "degraded");
        assert_eq!(v["tunnel_entry"], "stopped");
        assert!(
            v["detail"].as_str().is_some_and(|d| d.contains("restart")),
            "degraded 时说清处置方式（重启）：{v}"
        );
    }

    /// 规格（R12）：入口接受中时 200，并且 body 能回答"隧道入口状态 + 注册/健康 agent 数"。
    ///
    /// **agent 数刻意不进状态码**（只在这里报）：没有 agent ≠ 进程不健康，把它塞进状态码会让
    /// "刚启动、还没注册"变成探针失败 → 摘除/重启循环。真正的计数由 e2e
    /// `lifecycle::e2e_healthz_reports_the_same_agent_counts_as_the_api` 用真 agent 交叉验证。
    #[tokio::test]
    async fn healthz_reports_ok_and_the_agent_fields_while_accepting() {
        let state = test_state(None);
        // 守卫要活到断言结束：Drop 会把 gauge 置回 0
        let _accepting = state.metrics.mark_accepting();

        let resp = healthz(State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v: serde_json::Value =
            serde_json::from_str(&body_str(resp).await).expect("body 是 JSON");
        assert_eq!(v["status"], "ok");
        assert_eq!(v["tunnel_entry"], "accepting");
        assert_eq!(v["agents"]["registered"], 0);
        assert_eq!(v["agents"]["healthy"], 0);
        assert!(
            v["agents"]["oldest_last_seen_secs_ago"].is_null(),
            "注册表为空时最久心跳年龄是 null（不是 0）：{v}"
        );
        assert!(v["detail"].is_null(), "正常时不该有 detail：{v}");
    }
}
