//! 网关可观测性指标（Prometheus 文本格式，手写无依赖）。

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

use crate::sync::lock_or_recover;

#[derive(Clone, Default)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
}

#[derive(Default)]
struct MetricsInner {
    /// 按 HTTP 状态码计数的请求数。
    status_counts: Mutex<HashMap<u16, u64>>,
    /// 当前在途请求数。
    active: AtomicU64,
    /// 转发给客户端的字节数。
    bytes_out: AtomicU64,
    /// 累计请求耗时（毫秒）。
    total_duration_ms: AtomicU64,
    /// 累计请求数（含 /metrics 之外的所有请求）。
    request_count: AtomicU64,
    /// **写出状态码之前**就被丢弃的请求数（客户端断开 / 连接被掐 / future 被 drop）。
    ///
    /// 为什么必须单独记：`request_count` 在准入成功时就 +1，而状态码是在处理返回之后才记的；
    /// 中断路径上后者永远不执行 → 仓库自用的"僵尸槽位"判据 `request_count − Σ状态码`
    /// 会**每个中断漂移 +1**，把真泄漏淹没。减掉这一项之后恒等式才重新可判
    /// （见 `render` 里 `hlmg_requests_aborted_total` 的 HELP 与 `README.md` 的排障一节）。
    aborted: AtomicU64,
    /// 公网入口 `accept()` 失败的次数（含 `EMFILE`/`ECONNABORTED`/`EINTR` 等暂时性错误）。
    ///
    /// 修复之前这类错误会让整个入口**永久停摆**（`accepted?` 结束循环），而进程、systemd
    /// 与其它入口全都正常；现在它会退避重试，这个计数就是"入口正在挣扎"的唯一信号——
    /// 持续增长说明 fd 长期不够用（`nofile.rs` 抬额度、`max_entry_connections` 或上游泄漏）。
    http_accept_errors: AtomicU64,
    /// 当前在线 QUIC 连接数（隧道层 gauge）。
    quic_connections: AtomicU64,
    /// 累计 agent 连接次数（重连计数，counter）。
    agent_connections_total: AtomicU64,
    /// QUIC 隧道入口是否仍在接受新连接（1/0）。入口停止后进程照常运行，这是唯一的告警信号。
    quic_accepting: AtomicU64,
    /// 因"挑不出可路由的 agent"而拒绝的请求数，按原因分（reason → count）。
    ///
    /// 与 HTTP 状态码计数是两件事：客户端只看到 503/404/429，而这里回答的是
    /// **为什么**——尤其是 `registry-empty`（真没人注册）与 `all-candidates-stale`
    /// （有人注册但心跳全过期）必须分开：两者都表现为 503，处置方式却完全不同。
    agent_rejections: Mutex<HashMap<&'static str, u64>>,
    /// "隧道建立失败后换 agent 重试"的次数，按结果分（ok = 重试成功，failed = 换过仍失败）。
    tunnel_retries: Mutex<HashMap<&'static str, u64>>,
    /// 客户端停滞而主动放弃的次数，按方向分（`request-body` = 请求体读不动、
    /// `response-body` = 客户端不消费响应体）。
    ///
    /// 这个计数是"准入槽位泄漏"的直接告警：修好之前，这类停滞不会留下任何痕迹，
    /// 只表现为 `hlmg_active_requests` 只增不减（实测云端沉淀 8 个，只能重启恢复）。
    client_stalls: Mutex<HashMap<&'static str, u64>>,
    /// **响应头**超时的次数，按判定分：`slow` = 最近还在正常回响应头（被堵住的慢，不摘除）、
    /// `silent` = 窗口内一次都没回过（判死，计入连续超时）。
    ///
    /// 与 `tunnel_open_timeouts` 分开是刻意的：那条问"还有额度吗"，这条问"最近还干活吗"，
    /// 两者混在一起就没法判断"该扩容还是该查网络"。
    head_timeouts: Mutex<HashMap<&'static str, u64>>,
    /// 开流超时的次数，按判定分：`busy` = 在途已顶到承载上限（背压，不摘除）、
    /// `dead` = 未到上限却开不出流（坏连接，摘除）。
    ///
    /// 这个区分是排障的关键：`busy` 陡增说明容量不足（该扩容或调 `max_concurrency`），
    /// `dead` 陡增才是隧道/网络故障。两者在状态码上都会表现为 5xx/429。
    tunnel_open_timeouts: Mutex<HashMap<&'static str, u64>>,
    /// 写请求帧失败的次数，按性质分：`backpressure` = 写超时（连接级背压，**不摘除**）、
    /// `broken` = 写直接返回错误（坏连接，计 strike）。
    ///
    /// 与 `tunnel_open_timeouts` 分开：那条量"开不出流"，这条量"帧写不进去"。
    /// `backpressure` 陡增说明 agent 读得慢或链路拥塞（该查 agent / 带宽），
    /// `broken` 陡增才是隧道/网络故障。两者原先都不区分，写超时被当成死亡。
    tunnel_write_failures: Mutex<HashMap<&'static str, u64>>,
}

impl Metrics {
    /// 标记「隧道入口正在接受连接」；返回的守卫 Drop 时置回 0。
    ///
    /// 用 Drop 而不是「循环之后的语句」，是因为任务被 abort（优雅关闭）或 panic 时
    /// 循环后的代码不会执行——本仓库已经在同一个坑里摔过两次（`Admission` 的槽位释放、
    /// `serve_https` 的配置解析），手法保持一致。
    pub fn mark_accepting(&self) -> AcceptingGuard {
        self.inner.quic_accepting.store(1, Ordering::Relaxed);
        AcceptingGuard(self.clone())
    }

    /// 当前在线 agent 连接数（`hlmg_quic_connections` 同一份读数）。
    pub fn quic_connections(&self) -> u64 {
        self.inner.quic_connections.load(Ordering::Relaxed)
    }

    /// 隧道入口是否仍在接受新连接（1/0）。
    pub fn quic_accepting(&self) -> u64 {
        self.inner.quic_accepting.load(Ordering::Relaxed)
    }

    /// 测试专用：直接置位「隧道入口接受中」（生产只走 [`Metrics::mark_accepting`] 的 Drop 守卫）。
    ///
    /// 存在的理由：`/healthz` 现在拿这个 gauge 当存活判据，而测试里的裸 `AppState`
    /// （`http::test_util::test_state`）没有真 QUIC 入口——不置位的话**所有**走 `/healthz`
    /// 的用例都会看到 503。
    #[cfg(test)]
    pub fn set_quic_accepting_for_test(&self, accepting: bool) {
        self.inner
            .quic_accepting
            .store(u64::from(accepting), Ordering::Relaxed);
    }

    /// 原子占位（HTTP 全局并发 admission）：`fetch_add` 用**旧值**判定是否超限——
    /// 两个并发请求各自拿到唯一旧值，恰好允许 limit 个进入，无 check-then-act 竞态。
    /// 超限 → 回退占位并返回 None（调用方返回 429）；
    /// 通过 → 返回 [`Admission`] 票据，**槽位由票据的 Drop 释放**（见其文档）。
    pub fn try_enter(&self, limit: u32) -> Option<Admission> {
        let prev = self.inner.active.fetch_add(1, Ordering::Relaxed);
        if limit > 0 && prev >= limit as u64 {
            self.inner.active.fetch_sub(1, Ordering::Relaxed);
            None
        } else {
            self.inner.request_count.fetch_add(1, Ordering::Relaxed);
            Some(Admission {
                metrics: self.clone(),
                start: Instant::now(),
            })
        }
    }

    /// 记录被 admission 拒绝的请求（不计 active/耗时，但计入请求数与状态码分布）。
    /// 记录一次"无可路由 agent"的拒绝及其原因（原因常量见 `proxy` 的调用点）。
    pub fn record_agent_rejection(&self, reason: &'static str) {
        *lock_or_recover(&self.inner.agent_rejections)
            .entry(reason)
            .or_insert(0) += 1;
    }

    /// 记录一次"因隧道建立失败而换 agent 重试"及其结果。
    pub fn record_tunnel_retry(&self, outcome: &'static str) {
        *lock_or_recover(&self.inner.tunnel_retries)
            .entry(outcome)
            .or_insert(0) += 1;
    }

    /// 记录一次响应头超时（`kind`：`slow` = 还在回响应头，`silent` = 窗口内没有任何响应头）。
    pub fn record_head_timeout(&self, kind: &'static str) {
        *lock_or_recover(&self.inner.head_timeouts)
            .entry(kind)
            .or_insert(0) += 1;
    }

    /// 记录一次"客户端停滞 → 放弃"（`phase`：`request-body` / `response-body`）。
    pub fn record_client_stall(&self, phase: &'static str) {
        *lock_or_recover(&self.inner.client_stalls)
            .entry(phase)
            .or_insert(0) += 1;
    }

    /// 记录一次开流超时（`kind`：`busy` = 背压排队，`dead` = 坏连接）。
    pub fn record_tunnel_open_timeout(&self, kind: &'static str) {
        *lock_or_recover(&self.inner.tunnel_open_timeouts)
            .entry(kind)
            .or_insert(0) += 1;
    }

    /// 记录一次写请求帧失败（`kind`：`backpressure` = 写超时，`broken` = 写直接失败）。
    pub fn record_tunnel_write_failure(&self, kind: &'static str) {
        *lock_or_recover(&self.inner.tunnel_write_failures)
            .entry(kind)
            .or_insert(0) += 1;
    }

    /// 记一次「被全局闸门拒掉」。**只补 `request_count`**：`try_enter` 失败时没有自增。
    ///
    /// 状态码**不在这里记**——闸门住在 id 中间件里层，被拒的 429 会经过外层，由外层统一
    /// `record_status`。两边各记一半，`request_count − Σ状态码 − aborted` 才平衡
    /// （在这里也记一次就会重复计数，恒等式反而变成 -1）。
    pub fn record_rejected(&self) {
        self.inner.request_count.fetch_add(1, Ordering::Relaxed);
    }

    /// 记录请求结果状态码（在途槽位的释放不在此处，由 [`Admission`] 负责）。
    pub fn record_status(&self, status: u16) {
        *lock_or_recover(&self.inner.status_counts)
            .entry(status)
            .or_insert(0) += 1;
    }

    /// 记一次「请求在写出状态码之前被丢弃」。由 `metrics_middleware` 的 RAII 守卫调用
    /// （见 `http/observability.rs`）：取消没有"出口"可写，只有 Drop 能覆盖。
    pub fn record_aborted(&self) {
        self.inner.aborted.fetch_add(1, Ordering::Relaxed);
    }

    /// 记一次公网入口 `accept()` 失败（调用方已经退避重试，入口会继续监听）。
    pub fn record_accept_error(&self) {
        self.inner
            .http_accept_errors
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 公网入口 `accept()` 累计失败次数。
    pub fn http_accept_errors(&self) -> u64 {
        self.inner.http_accept_errors.load(Ordering::Relaxed)
    }

    /// 三项供测试核对恒等式 `request_count − Σ状态码 − aborted == 0`（真泄漏才会让它 >0）。
    #[cfg(test)]
    pub fn identity_terms(&self) -> (u64, u64, u64) {
        let status_total: u64 = lock_or_recover(&self.inner.status_counts).values().sum();
        (
            self.inner.request_count.load(Ordering::Relaxed),
            status_total,
            self.inner.aborted.load(Ordering::Relaxed),
        )
    }

    pub fn add_bytes_out(&self, n: usize) {
        self.inner.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// 当前在途请求数（admission 判定用）。
    pub fn active_count(&self) -> u64 {
        self.inner.active.load(Ordering::Relaxed)
    }

    /// 累计请求数。
    pub fn request_count(&self) -> u64 {
        self.inner.request_count.load(Ordering::Relaxed)
    }

    /// agent 连接建立：累计 +1、当前在线 +1。
    pub fn mark_agent_connected(&self) -> AgentConnectionGuard {
        self.inner
            .agent_connections_total
            .fetch_add(1, Ordering::Relaxed);
        self.inner.quic_connections.fetch_add(1, Ordering::Relaxed);
        AgentConnectionGuard(self.clone())
    }

    /// agent 连接断开：当前在线 -1。**只由 [`AgentConnectionGuard`] 调用**。
    ///
    /// 饱和减而不是裸 `fetch_sub`：gauge 在 0 上回绕会变成 `u64::MAX`（`hlmg_quic_connections`
    /// 永远报警）。守卫已经保证每 +1 恰好配一次 -1，这里是第二道保险——一处逻辑错误不该把
    /// 仪表盘彻底毁掉。
    fn agent_disconnected(&self) {
        let _ =
            self.inner
                .quic_connections
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    Some(n.saturating_sub(1))
                });
    }

    /// 渲染为 Prometheus 文本格式。
    ///
    /// - `agent_count`：注册表条目数（含失联但连接未关的）
    /// - `agents_healthy`：其中**心跳未过期、真正可路由**的数量
    /// - `verify_hits` / `verify_misses`：已验证身份缓存的命中数与**真跑 argon2 的次数**
    ///   （来自 `KeyStore`；`verified_cache_max: 0` 时前者恒为 0、后者等于校验次数）
    pub fn render(
        &self,
        agent_count: usize,
        agents_healthy: usize,
        verify_hits: u64,
        verify_misses: u64,
    ) -> String {
        let inner = &self.inner;
        let mut out = String::with_capacity(512);
        out.push_str("# HELP hlmg_requests_total Total gateway requests by HTTP status.\n");
        out.push_str("# TYPE hlmg_requests_total counter\n");
        let counts = lock_or_recover(&inner.status_counts);
        let mut keys: Vec<u16> = counts.keys().copied().collect();
        keys.sort_unstable();
        for code in keys {
            out.push_str(&format!(
                "hlmg_requests_total{{status=\"{code}\"}} {}\n",
                counts[&code]
            ));
        }
        out.push_str("# HELP hlmg_active_requests Currently in-flight requests.\n");
        out.push_str("# TYPE hlmg_active_requests gauge\n");
        out.push_str(&format!(
            "hlmg_active_requests {}\n",
            inner.active.load(Ordering::Relaxed)
        ));
        // 语义说明（旧 HELP 文案写的是 "Registered healthy agents"，但该值不过滤心跳，
        // 失联 agent 也会算进去——排查"全部请求 503"时极易误判，这里按实际语义改正）。
        out.push_str("# HELP hlmg_agents Registered agent entries, including ones whose heartbeats have expired.\n");
        out.push_str("# TYPE hlmg_agents gauge\n");
        out.push_str(&format!("hlmg_agents {agent_count}\n"));
        out.push_str("# HELP hlmg_agents_healthy Registered agents whose last heartbeat is within agent_stale_secs (routable candidates).\n");
        out.push_str("# TYPE hlmg_agents_healthy gauge\n");
        out.push_str(&format!("hlmg_agents_healthy {agents_healthy}\n"));
        {
            let retries = lock_or_recover(&inner.tunnel_retries);
            if !retries.is_empty() {
                out.push_str("# HELP hlmg_tunnel_retries_total Requests retried on another agent after a tunnel setup failure, by outcome.\n");
                out.push_str("# TYPE hlmg_tunnel_retries_total counter\n");
                let mut outcomes: Vec<&&str> = retries.keys().collect();
                outcomes.sort_unstable();
                for o in outcomes {
                    out.push_str(&format!(
                        "hlmg_tunnel_retries_total{{outcome=\"{o}\"}} {}\n",
                        retries[*o]
                    ));
                }
            }
        }
        {
            let rej = lock_or_recover(&inner.agent_rejections);
            if !rej.is_empty() {
                out.push_str("# HELP hlmg_agent_rejections_total Requests rejected because no routable agent was available, by reason.\n");
                out.push_str("# TYPE hlmg_agent_rejections_total counter\n");
                let mut reasons: Vec<&&str> = rej.keys().collect();
                reasons.sort_unstable();
                for r in reasons {
                    out.push_str(&format!(
                        "hlmg_agent_rejections_total{{reason=\"{r}\"}} {}\n",
                        rej[*r]
                    ));
                }
            }
        }
        {
            let cs = lock_or_recover(&inner.client_stalls);
            if !cs.is_empty() {
                out.push_str("# HELP hlmg_client_stalls_total Requests abandoned because the client stopped making progress, by direction. Kept slots do not leak: each one is released when the request ends.\n");
                out.push_str("# TYPE hlmg_client_stalls_total counter\n");
                let mut phases: Vec<&&str> = cs.keys().collect();
                phases.sort_unstable();
                for p in phases {
                    out.push_str(&format!(
                        "hlmg_client_stalls_total{{phase=\"{p}\"}} {}\n",
                        cs[*p]
                    ));
                }
            }
        }
        {
            let ht = lock_or_recover(&inner.head_timeouts);
            if !ht.is_empty() {
                out.push_str("# HELP hlmg_upstream_head_timeouts_total Response heads that exceeded head_timeout_secs; class=slow means the agent had answered recently and is merely blocked (504, not evicted), class=silent means nothing came back within the window (counts toward eviction).\n");
                out.push_str("# TYPE hlmg_upstream_head_timeouts_total counter\n");
                let mut kinds: Vec<&&str> = ht.keys().collect();
                kinds.sort_unstable();
                for k in kinds {
                    out.push_str(&format!(
                        "hlmg_upstream_head_timeouts_total{{class=\"{k}\"}} {}\n",
                        ht[*k]
                    ));
                }
            }
        }
        {
            let to = lock_or_recover(&inner.tunnel_open_timeouts);
            if !to.is_empty() {
                out.push_str("# HELP hlmg_tunnel_open_timeouts_total Tunnel stream opens that exceeded tunnel_op_secs; class=busy means the agent was at capacity (backpressure, not evicted), class=dead means the connection was treated as broken and evicted.\n");
                out.push_str("# TYPE hlmg_tunnel_open_timeouts_total counter\n");
                let mut kinds: Vec<&&str> = to.keys().collect();
                kinds.sort_unstable();
                for k in kinds {
                    out.push_str(&format!(
                        "hlmg_tunnel_open_timeouts_total{{class=\"{k}\"}} {}\n",
                        to[*k]
                    ));
                }
            }
        }
        {
            let wf = lock_or_recover(&inner.tunnel_write_failures);
            if !wf.is_empty() {
                out.push_str("# HELP hlmg_tunnel_write_failures_total Request frames that could not be written to the tunnel; class=backpressure means the write timed out (connection-level backpressure, not evicted), class=broken means the write returned an error (connection treated as broken and evicted).\n");
                out.push_str("# TYPE hlmg_tunnel_write_failures_total counter\n");
                let mut kinds: Vec<&&str> = wf.keys().collect();
                kinds.sort_unstable();
                for k in kinds {
                    out.push_str(&format!(
                        "hlmg_tunnel_write_failures_total{{class=\"{k}\"}} {}\n",
                        wf[*k]
                    ));
                }
            }
        }
        out.push_str("# HELP hlmg_bytes_out Bytes forwarded to clients.\n");
        out.push_str("# TYPE hlmg_bytes_out counter\n");
        out.push_str(&format!(
            "hlmg_bytes_out {}\n",
            inner.bytes_out.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP hlmg_request_duration_ms Total request duration in ms (sum).\n");
        out.push_str("# TYPE hlmg_request_duration_ms counter\n");
        out.push_str(&format!(
            "hlmg_request_duration_ms {}\n",
            inner.total_duration_ms.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP hlmg_request_count Total requests (sum).\n");
        out.push_str("# TYPE hlmg_request_count counter\n");
        out.push_str(&format!(
            "hlmg_request_count {}\n",
            inner.request_count.load(Ordering::Relaxed)
        ));
        // HELP/TYPE 必须**紧贴**在各自样本之前（Prometheus 文本格式按"家族"解析），
        // 所以这一条整块放在 request_count 之后，而不是插进它的 HELP 与 TYPE 之间。
        out.push_str(
            "# HELP hlmg_requests_aborted_total Requests dropped before a status was written (client aborted or the connection was cut).\n",
        );
        out.push_str("# TYPE hlmg_requests_aborted_total counter\n");
        out.push_str(&format!(
            "hlmg_requests_aborted_total {}\n",
            inner.aborted.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP hlmg_key_verify_hits_total Cached key verifications served without argon2.\n",
        );
        out.push_str("# TYPE hlmg_key_verify_hits_total counter\n");
        out.push_str(&format!("hlmg_key_verify_hits_total {verify_hits}\n"));
        out.push_str(
            "# HELP hlmg_key_verify_misses_total Key verifications that ran argon2 (a cache miss, or the cache is disabled via verified_cache_max: 0).\n",
        );
        out.push_str("# TYPE hlmg_key_verify_misses_total counter\n");
        out.push_str(&format!("hlmg_key_verify_misses_total {verify_misses}\n"));
        out.push_str("# HELP hlmg_quic_connections Currently open agent QUIC connections.\n");
        out.push_str("# TYPE hlmg_quic_connections gauge\n");
        out.push_str(&format!(
            "hlmg_quic_connections {}\n",
            inner.quic_connections.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP hlmg_quic_accepting Whether the tunnel entry still accepts new edge connections (1/0).\n",
        );
        out.push_str("# TYPE hlmg_quic_accepting gauge\n");
        out.push_str(&format!(
            "hlmg_quic_accepting {}\n",
            inner.quic_accepting.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP hlmg_http_accept_errors_total Public entry accept() failures (EMFILE, ECONNABORTED, ...); the entry keeps listening and retries with backoff.\n",
        );
        out.push_str("# TYPE hlmg_http_accept_errors_total counter\n");
        out.push_str(&format!(
            "hlmg_http_accept_errors_total {}\n",
            inner.http_accept_errors.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP hlmg_agent_connections_total Cumulative agent connections (reconnects).\n",
        );
        out.push_str("# TYPE hlmg_agent_connections_total counter\n");
        out.push_str(&format!(
            "hlmg_agent_connections_total {}\n",
            inner.agent_connections_total.load(Ordering::Relaxed)
        ));
        out
    }
}

/// 在途准入票据：持有期间该请求计入 `hlmg_active_requests`；**槽位在 Drop 时释放**。
///
/// 释放必须挂在 Drop 上，不能依赖调用方"await 之后"的尾部语句：客户端中断时 hyper 会
/// 直接 drop 在途的请求 future，尾部代码永不执行——槽位会永久泄漏，配了
/// `max_concurrent_requests` 的网关会被**一次**中断打成此后全部 429（只能重启）。
///
/// 因此：票据要么被正常作用域 drop，要么随请求 future 被丢弃而 drop，两条路都归还槽位。
/// 注意不可 `Clone`/`Copy`（会导致重复释放）。
pub struct Admission {
    metrics: Metrics,
    start: Instant,
}

impl Admission {
    /// 占位时刻（调用方据此计算 TTFB 等日志字段）。
    pub fn started_at(&self) -> Instant {
        self.start
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        self.metrics.inner.active.fetch_sub(1, Ordering::Relaxed);
        self.metrics
            .inner
            .total_duration_ms
            .fetch_add(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
}

/// 隧道入口「接受中」守卫：见 [`Metrics::mark_accepting`]。Drop 时把 gauge 置回 0，
/// 因此**结束方式不影响可观测性**——正常返回、任务被 abort、panic 都会留下痕迹。
pub struct AcceptingGuard(Metrics);

impl Drop for AcceptingGuard {
    fn drop(&mut self) {
        self.0.inner.quic_accepting.store(0, Ordering::Relaxed);
    }
}

/// 一条 agent 连接的生命周期守卫：见 [`Metrics::mark_agent_connected`]。
///
/// **为什么必须用 Drop**（评估记录 P2-11）：以前 `quic.rs` 是在连接任务里"先 +1、末尾 -1"，
/// 而 `handle_conn` 里任何 panic 都会让末尾那句不执行——`hlmg_quic_connections` 于是**永久虚高**，
/// 而且注册表条目也再也摘不掉（没有 stale 清扫器）。仓库其它资源（`AcceptingGuard` /
/// `Admission` / `SlotGuard`）早就是这个模式，这是最后一处例外。
pub struct AgentConnectionGuard(Metrics);

impl Drop for AgentConnectionGuard {
    fn drop(&mut self) {
        self.0.agent_disconnected();
    }
}

#[cfg(test)]
mod tests {
    use super::Metrics;

    /// 规格（评估 §7 步骤 6 的结转项 A / `PROJECT_SCAN` P2-12）：**计数锁中毒后
    /// `/metrics` 不能跟着挂**。
    ///
    /// 这些映射只被"加一"与"渲染"访问，守卫内 panic 不会写坏它们；而 `.lock().unwrap()`
    /// 会把一次 panic 放大成"`/metrics` 永久 500"——恰恰是排障时最需要它的时刻。
    #[test]
    fn a_poisoned_counter_lock_does_not_take_metrics_down() {
        let m = Metrics::default();
        m.record_status(200);

        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = m.inner.status_counts.lock().unwrap();
            panic!("poison status_counts");
        }));
        assert!(poisoned.is_err(), "前提：panic 发生了");
        assert!(m.inner.status_counts.is_poisoned(), "前提：锁中毒了");

        // 写路径与渲染路径都必须照常
        m.record_status(204);
        let text = m.render(0, 0, 0, 0);
        assert!(
            text.contains("hlmg_requests_total{status=\"200\"} 1"),
            "渲染必须带上中毒前的计数：\n{text}"
        );
        assert!(
            text.contains("hlmg_requests_total{status=\"204\"} 1"),
            "中毒后新记的状态码也要出现：\n{text}"
        );
    }

    /// 规格（P2-11）：**连接任务的 panic 必须把 `hlmg_quic_connections` 降回去**。
    ///
    /// 旧的"先 +1、末尾 -1"写法在这条测试下必然红：panic 展开时末尾那句不执行，gauge 永久虚高，
    /// 而没有任何东西会去纠正它（注册表条目同样漏掉，见 `registry::Registration`）。
    #[test]
    fn the_connection_gauge_is_released_even_when_the_task_panics() {
        let m = Metrics::default();
        assert_eq!(m.quic_connections(), 0);

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = m.mark_agent_connected();
            assert_eq!(m.quic_connections(), 1, "在连时应为 1");
            panic!("connection task blew up");
        }));
        assert!(panicked.is_err(), "前提：panic 发生了");
        assert_eq!(
            m.quic_connections(),
            0,
            "panic 展开也必须归还 gauge（否则永久虚高，只能重启）"
        );
        assert!(
            m.render(0, 0, 0, 0)
                .contains("hlmg_agent_connections_total 1"),
            "累计连接数是 counter，不因 panic 回退"
        );
    }

    /// 规格（P2-11）：递减**饱和**——0 上再减不许回绕成 `u64::MAX`。
    #[test]
    fn the_connection_gauge_never_wraps_around() {
        let m = Metrics::default();
        m.agent_disconnected();
        m.agent_disconnected();
        assert_eq!(
            m.quic_connections(),
            0,
            "裸 fetch_sub 会回绕成 u64::MAX，仪表盘彻底不可读"
        );
    }

    /// 规格：渲染出的每个 `# HELP` 后面必须**紧跟同名的 `# TYPE`**。
    ///
    /// 这不是格式洁癖：Prometheus 的文本解析按"家族"分组，HELP 与 TYPE 之间插进另一个家族的
    /// 样本会让解析失败（整轮抓取报废）。本仓库真踩过这个坑——加 `hlmg_requests_aborted_total`
    /// 时把 HELP 插到了 `hlmg_request_count` 的 HELP 与 TYPE 之间。这条把它变成机器判据，
    /// 顺带保证新指标（`hlmg_http_accept_errors_total`）确实被渲染出来。
    #[test]
    fn every_help_line_is_immediately_followed_by_its_own_type_line() {
        let text = Metrics::default().render(0, 0, 0, 0);
        let lines: Vec<&str> = text.lines().collect();
        let mut checked = 0;
        for (i, line) in lines.iter().enumerate() {
            let Some(name) = line.strip_prefix("# HELP ") else {
                continue;
            };
            let name = name.split_whitespace().next().expect("HELP 必须带指标名");
            let next = lines.get(i + 1).unwrap_or(&"");
            assert!(
                next.starts_with(&format!("# TYPE {name} ")),
                "`{name}` 的 HELP 后面必须紧跟同名的 TYPE（家族不能交错），实际下一行是 `{next}`"
            );
            checked += 1;
        }
        assert!(checked > 10, "应当检查到足够多的家族（实际 {checked}）");
        assert!(
            text.contains("# TYPE hlmg_http_accept_errors_total counter"),
            "新指标必须被渲染：\n{text}"
        );
    }
}
