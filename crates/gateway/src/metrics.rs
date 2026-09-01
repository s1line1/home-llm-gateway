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
}

impl Metrics {
    pub fn record_start(&self) -> Instant {
        self.inner.active.fetch_add(1, Ordering::Relaxed);
        self.inner.request_count.fetch_add(1, Ordering::Relaxed);
        Instant::now()
    }

    pub fn record_end(&self, start: Instant, status: u16) {
        self.inner.active.fetch_sub(1, Ordering::Relaxed);
        self.inner
            .total_duration_ms
            .fetch_add(start.elapsed().as_millis() as u64, Ordering::Relaxed);
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
