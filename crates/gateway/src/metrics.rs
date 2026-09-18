//! 网关可观测性指标（Prometheus 文本格式，手写无依赖）。

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

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

    /// 隧道入口是否仍在接受新连接（1/0）。
    pub fn quic_accepting(&self) -> u64 {
        self.inner.quic_accepting.load(Ordering::Relaxed)
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
    /// 记录一次"无可路由 agent"的拒绝及其原因（原因常量见 `http_proxy` 的调用点）。
    pub fn record_agent_rejection(&self, reason: &'static str) {
        *self
            .inner
            .agent_rejections
            .lock()
            .unwrap()
            .entry(reason)
            .or_insert(0) += 1;
    }

    /// 记录一次"因隧道建立失败而换 agent 重试"及其结果。
    pub fn record_tunnel_retry(&self, outcome: &'static str) {
        *self
            .inner
            .tunnel_retries
            .lock()
            .unwrap()
            .entry(outcome)
            .or_insert(0) += 1;
    }

    /// 记录一次响应头超时（`kind`：`slow` = 还在回响应头，`silent` = 窗口内没有任何响应头）。
    pub fn record_head_timeout(&self, kind: &'static str) {
        *self
            .inner
            .head_timeouts
            .lock()
            .unwrap()
            .entry(kind)
            .or_insert(0) += 1;
    }

    /// 记录一次"客户端停滞 → 放弃"（`phase`：`request-body` / `response-body`）。
    pub fn record_client_stall(&self, phase: &'static str) {
        *self
            .inner
            .client_stalls
            .lock()
            .unwrap()
            .entry(phase)
            .or_insert(0) += 1;
    }

    /// 记录一次开流超时（`kind`：`busy` = 背压排队，`dead` = 坏连接）。
    pub fn record_tunnel_open_timeout(&self, kind: &'static str) {
        *self
            .inner
            .tunnel_open_timeouts
            .lock()
            .unwrap()
            .entry(kind)
            .or_insert(0) += 1;
    }

    pub fn record_rejected(&self, status: u16) {
        self.inner.request_count.fetch_add(1, Ordering::Relaxed);
        self.record_status(status);
    }

    /// 记录请求结果状态码（在途槽位的释放不在此处，由 [`Admission`] 负责）。
    pub fn record_status(&self, status: u16) {
        *self
            .inner
            .status_counts
            .lock()
            .unwrap()
            .entry(status)
            .or_insert(0) += 1;
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
    pub fn agent_connected(&self) {
        self.inner
            .agent_connections_total
            .fetch_add(1, Ordering::Relaxed);
        self.inner.quic_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// agent 连接断开：当前在线 -1。
    pub fn agent_disconnected(&self) {
        self.inner.quic_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// 渲染为 Prometheus 文本格式。
    ///
    /// - `agent_count`：注册表条目数（含失联但连接未关的）
    /// - `agents_healthy`：其中**心跳未过期、真正可路由**的数量
    /// - `verify_hits` / `verify_misses`：已验证身份缓存的命中/未命中（来自 KeyStore）
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
        let counts = inner.status_counts.lock().unwrap();
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
            let retries = inner.tunnel_retries.lock().unwrap();
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
            let rej = inner.agent_rejections.lock().unwrap();
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
            let cs = inner.client_stalls.lock().unwrap();
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
            let ht = inner.head_timeouts.lock().unwrap();
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
            let to = inner.tunnel_open_timeouts.lock().unwrap();
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
        out.push_str(
            "# HELP hlmg_key_verify_hits_total Cached key verifications served without argon2.\n",
        );
        out.push_str("# TYPE hlmg_key_verify_hits_total counter\n");
        out.push_str(&format!("hlmg_key_verify_hits_total {verify_hits}\n"));
        out.push_str(
            "# HELP hlmg_key_verify_misses_total Key verifications that ran argon2 (cache miss).\n",
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
