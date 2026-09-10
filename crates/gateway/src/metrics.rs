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

    /// 渲染为 Prometheus 文本格式；`agent_count` 由调用方传入（注册表实时值）。
    pub fn render(&self, agent_count: usize) -> String {
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
        out.push_str("# HELP hlmg_agents Registered healthy agents.\n");
        out.push_str("# TYPE hlmg_agents gauge\n");
        out.push_str(&format!("hlmg_agents {agent_count}\n"));
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
