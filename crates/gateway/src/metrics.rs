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

/// 准入域（复扫 A3）：**豁免路径不得消耗受限路径的预算**。
///
/// 为什么需要"域"这个概念：先前用 `limit == 0` 表达"豁免"（`/healthz`），而 `0` 的语义只是
/// "不判上限"——领票、计数一样不少，加的还恰好是**受限路径用来比较的同一个计数器**。于是豁免
/// 路径实际在花受限预算：对着无认证的 `/healthz` 打一轮就能把 `/v1` 顶到 429，而 LB 因为探针
/// 仍返回 200 而认为实例健康（"整机正常、谁都调不通"）。
///
/// 域把"能不能被拒"与"记在谁的账上"分开：每个域有自己的在途计数与自己的上限，互不干扰；
/// **总数**（[`Metrics::active_count`]）仍然统计全部在途票，所以 `hlmg_active_requests` 与
/// `drain()` 的语义一个都没变。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDomain {
    /// 受 `max_concurrent_requests` 约束的常规路径（`/v1/*`、UI、admin…）。
    Gated,
    /// 探针（`/healthz`）：自己不占受限额度，但有一个**独立的、宽松的**上限，免得这条无认证
    /// 路径被洪水无界消耗（取值与理由见 `http::admission::MAX_CONCURRENT_PROBES`）。
    Probe,
    /// 指标抓取（`/metrics`）：与探针域同理，但计数**完全独立**（复扫 A8）。
    ///
    /// 三个域各自一个计数器，不是"省一个字段"的问题：只要两条路径共用一个域，其中一条的洪水
    /// 就能把另一条顶成 429——`/healthz` 被 429 会让 LB 摘掉健康实例，`/v1` 被 429 就是全量
    /// 失败。抓取域的票据还**不算一次请求**（见 [`Metrics::try_enter_uncounted`]）。
    Scrape,
}

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
    /// **受限域**在途数：只有 [`AdmissionDomain::Gated`] 的票据增减它，`max_concurrent_requests`
    /// 也只与它比较。
    ///
    /// 为什么不复用 `active`（复扫 A3）：`/healthz` 是**无认证**的豁免路径，却同样领票；探针
    /// （或对它的洪水）会把 `active` 抬到受限上限之上，让 `/v1` 全线 429，而探针自己仍是 200。
    active_gated: AtomicU64,
    /// **探针域**在途数：只有 [`AdmissionDomain::Probe`] 的票据增减它。
    active_probe: AtomicU64,
    /// **抓取域**在途数：只有 [`AdmissionDomain::Scrape`] 的票据增减它（复扫 A8）。
    ///
    /// 与探针域分开的理由同 `active_gated`：`/metrics` 也是**无认证**入口，共用探针域就等于
    /// "一轮抓取洪水能把 `/healthz` 顶成 429"，而 LB 会因此摘掉一个**健康**实例。
    active_scrape: AtomicU64,
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
    /// 响应转发的**退出原因**（kind → count，记录 P2-14）。
    ///
    /// 七条以上的出口里，大多数发生时**状态码已经写出去了**（200 已发给客户端，只是响应体
    /// 半截/空闲超时/上游断流），访问日志只记状态码 ⇒ 这类"客户端拿到半截回答"的失败本来
    /// 在生产上完全不可观测。kind 取自 `proxy::forward::ForwardEnd::label`（`&'static str`，
    /// 基数有界）。
    forward_ends: Mutex<HashMap<&'static str, u64>>,
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

    /// 原子占位（HTTP 全局并发 admission）：**CAS 循环**，超限直接返回 `None`（调用方 429）；
    /// 通过 → 返回 [`Admission`] 票据，**槽位由票据的 Drop 释放**（见其文档）。
    ///
    /// 为什么是 CAS 而不是 `fetch_add` + 超限回滚（记录 R8）：后者在"加了但还没回滚"的那一瞬间
    /// 让计数**比真实持票数多 1**（幽灵占位）。若恰好有持票者在这一刻释放，紧接着到达的请求会
    /// 读到 `prev >= limit` 而被拒——**闸门其实是空的**（"双双误拒"，客户端拿到本不该有的 429）。
    /// CAS 只在"确实要到票"时才加计数，因此
    /// `active_count()` **恒等于**已发出的票数（顺带让 `hlmg_active_requests` 不再有瞬时尖峰，
    /// 排空判据 `drain()` 读的也是它）。
    ///
    /// `limit == 0` = **本域不限**：直接占位（仍然计数，票据照常负责 `request_count` 与时长记账）。
    ///
    /// `domain` 决定这笔在途记进哪个域（见 [`AdmissionDomain`]）：受限路径只与受限域的计数比较，
    /// 所以豁免路径在途多少都不会减少别人能用的额度。
    pub fn try_enter(&self, limit: u32, domain: AdmissionDomain) -> Option<Admission> {
        self.enter(limit, domain, true)
    }

    /// 同 [`Metrics::try_enter`]，但票据**不算一次请求**：不进 `request_count`、不进
    /// `active`（`hlmg_active_requests` 与 `drain()`）、也不记耗时（复扫 A8）。
    ///
    /// 给 `/metrics` 抓取用。它必须与 `try_enter` 分开，因为"配额"与"记账"是两件事：
    /// `/metrics` 不走 id / 访问日志 / 状态码那条链（`request_id_middleware` 对它直接放行），
    /// 而仓库自用的恒等式 `request_count − Σ状态码 − aborted == 0` 依赖"记了状态码才算一次
    /// 请求"——在这里也 `request_count += 1`，恒等式就会被**每次抓取**各漂移 +1，把真正的槽位
    /// 泄漏淹没。它占的只有 [`AdmissionDomain::Scrape`] 的在途计数（于是抓取洪水有界）。
    pub fn try_enter_uncounted(&self, limit: u32, domain: AdmissionDomain) -> Option<Admission> {
        self.enter(limit, domain, false)
    }

    fn enter(&self, limit: u32, domain: AdmissionDomain, counted: bool) -> Option<Admission> {
        let domain_counter = match domain {
            AdmissionDomain::Gated => &self.inner.active_gated,
            AdmissionDomain::Probe => &self.inner.active_probe,
            AdmissionDomain::Scrape => &self.inner.active_scrape,
        };
        if limit > 0 {
            let limit = u64::from(limit);
            let mut current = domain_counter.load(Ordering::Relaxed);
            loop {
                if current >= limit {
                    return None;
                }
                match domain_counter.compare_exchange_weak(
                    current,
                    current + 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    // 别的线程改了计数：用观测到的新值重试（不重试就真的会漏放行）
                    Err(observed) => current = observed,
                }
            }
        } else {
            domain_counter.fetch_add(1, Ordering::Relaxed);
        }
        // 总数（`hlmg_active_requests` 与 `drain()` 读它）：**只在本域确实占到票之后**才加，
        // 所以它仍然恒等于已发出的票数、不会留下幽灵占位（R8）。抓取票（`counted = false`）
        // 刻意不在这里出现——见 `try_enter_uncounted`。
        if counted {
            self.inner.active.fetch_add(1, Ordering::Relaxed);
            self.inner.request_count.fetch_add(1, Ordering::Relaxed);
        }
        Some(Admission {
            metrics: self.clone(),
            start: Instant::now(),
            domain,
            counted,
        })
    }

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

    /// 记录一次响应转发的退出原因（`kind` 见 `proxy::forward::ForwardEnd::label`）。
    pub fn record_forward_end(&self, kind: &'static str) {
        *lock_or_recover(&self.inner.forward_ends)
            .entry(kind)
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

    /// 当前在途请求数（**全部域**；`hlmg_active_requests` 与 `drain()` 读它）。
    ///
    /// 注意它**不再是准入门槛**——判据在 [`Self::try_enter`] 里按域取（复扫 A3）。
    pub fn active_count(&self) -> u64 {
        self.inner.active.load(Ordering::Relaxed)
    }

    /// **受限域**在途数：准入门槛、拒绝日志与测试读它。
    pub fn active_gated_count(&self) -> u64 {
        self.inner.active_gated.load(Ordering::Relaxed)
    }

    /// **探针域**在途数（`/healthz`）：拒绝日志与测试读它。
    pub fn active_probe_count(&self) -> u64 {
        self.inner.active_probe.load(Ordering::Relaxed)
    }

    /// **抓取域**在途数（`/metrics`）：拒绝日志与测试读它（复扫 A8）。
    pub fn active_scrape_count(&self) -> u64 {
        self.inner.active_scrape.load(Ordering::Relaxed)
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
        let _ = self
            .inner
            .quic_connections
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
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
                out.push_str("# HELP hlmg_tunnel_retries_total Tunnel-setup failures that led to an agent switch, by outcome. ok and failed count retries; no-alternative counts the times there was no other agent to switch to, so it is not a retry and the family sum is neither the retry count nor the failure count.\n");
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
            let fe = lock_or_recover(&inner.forward_ends);
            if !fe.is_empty() {
                out.push_str("# HELP hlmg_forward_ends_total Response forwarding exits by reason. Most of these happen after a 200 was already written to the client (truncated body, idle timeout, upstream closed), so the access log cannot show them; see ForwardEnd::label for the kinds.\n");
                out.push_str("# TYPE hlmg_forward_ends_total counter\n");
                let mut kinds: Vec<&&str> = fe.keys().collect();
                kinds.sort_unstable();
                for k in kinds {
                    out.push_str(&format!(
                        "hlmg_forward_ends_total{{kind=\"{k}\"}} {}\n",
                        fe[*k]
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
///
/// 票据记着自己是哪个域的（复扫 A3），否则 Drop 不知道该把票还给受限域还是探针域；
/// 还记着它**算不算一次请求**（复扫 A8，见 [`Metrics::try_enter_uncounted`]）。
pub struct Admission {
    metrics: Metrics,
    start: Instant,
    domain: AdmissionDomain,
    /// `false` = 只占域额度、不进 `request_count` / `active` / 耗时（`/metrics` 抓取票）。
    counted: bool,
}

impl Admission {}

impl Drop for Admission {
    fn drop(&mut self) {
        match self.domain {
            AdmissionDomain::Gated => &self.metrics.inner.active_gated,
            AdmissionDomain::Probe => &self.metrics.inner.active_probe,
            AdmissionDomain::Scrape => &self.metrics.inner.active_scrape,
        }
        .fetch_sub(1, Ordering::Relaxed);
        if !self.counted {
            return;
        }
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
    use super::{AdmissionDomain, Metrics};

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

    /// 规格（记录 R8）：**占位不得制造"幽灵占位"**——`active_count()` 永远不超过已发出的票数。
    ///
    /// 旧实现（`fetch_add` 后超限回滚）在回滚前那一瞬间把计数抬高 1；若持票者恰在那一刻释放，
    /// 紧接着到达的请求会读到 `prev >= limit` 而被拒，而闸门其实是空的。这条用一个**采样线程**
    /// 盯住计数上界：M 个线程在 barrier 上对齐、同时抢同一个槽位，采样到 `active > limit` 即红。
    #[test]
    fn try_enter_never_inflates_the_counter_above_the_limit() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Barrier,
        };

        for round in 0..50 {
            let metrics = Metrics::default();
            let threads = 8usize;
            let barrier = Arc::new(Barrier::new(threads + 1));
            let stop = Arc::new(AtomicBool::new(false));

            let sampler = {
                let (m, b, stop) = (metrics.clone(), barrier.clone(), stop.clone());
                std::thread::spawn(move || {
                    b.wait();
                    let (mut worst, mut worst_gated) = (0u64, 0u64);
                    while !stop.load(Ordering::Relaxed) {
                        worst = worst.max(m.active_count());
                        worst_gated = worst_gated.max(m.active_gated_count());
                    }
                    (worst, worst_gated)
                })
            };
            let workers: Vec<_> = (0..threads)
                .map(|_| {
                    let (m, b) = (metrics.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        b.wait();
                        // 抢到就立刻放：制造"持票者释放"与"别人正在占位"重叠的窗口
                        if let Some(ticket) = m.try_enter(1, AdmissionDomain::Gated) {
                            drop(ticket);
                        }
                    })
                })
                .collect();
            for w in workers {
                w.join().unwrap();
            }
            stop.store(true, Ordering::Relaxed);
            let (worst, worst_gated) = sampler.join().unwrap();
            assert!(
                worst <= 1 && worst_gated <= 1,
                "第 {round} 轮采样到 active={worst} / gated={worst_gated} > limit=1：                 存在幽灵占位 ⇒ 会误拒（R8）"
            );
        }
    }

    /// 规格（R8 的另一半）：**占位/释放的记账必须精确**，`0` 仍然是"不限"。
    #[test]
    fn try_enter_accounts_exactly_and_treats_zero_as_unlimited() {
        let m = Metrics::default();
        let a = m
            .try_enter(2, AdmissionDomain::Gated)
            .expect("第 1 个应当放行");
        let b = m
            .try_enter(2, AdmissionDomain::Gated)
            .expect("第 2 个应当放行");
        assert!(
            m.try_enter(2, AdmissionDomain::Gated).is_none(),
            "第 3 个必须被拒"
        );
        assert_eq!(
            m.active_count(),
            2,
            "被拒的那次不得留下任何计数（否则会连锁误拒）"
        );

        drop(a);
        assert_eq!(m.active_count(), 1);
        let c = m
            .try_enter(2, AdmissionDomain::Gated)
            .expect("释放一个之后必须能再进");
        assert_eq!(m.active_count(), 2);
        drop((b, c));
        assert_eq!(m.active_count(), 0);

        // `0` = 不限：一直放行，但仍然计数
        let m2 = Metrics::default();
        let t1 = m2
            .try_enter(0, AdmissionDomain::Gated)
            .expect("limit=0 无条件放行");
        let t2 = m2
            .try_enter(0, AdmissionDomain::Gated)
            .expect("limit=0 无条件放行");
        assert_eq!(m2.active_count(), 2);
        drop(t1);
        assert_eq!(m2.active_count(), 1);
        drop(t2);
        assert_eq!(m2.active_count(), 0);
    }

    /// 规格（复扫 A3）：**探针域的票据不得消耗受限域的预算**。
    ///
    /// `/healthz` 是**无认证**的豁免路径（鉴权只包 `/admin`），先前用 `limit = 0` 表达"不能被拒"。
    /// 但它照样领票、照样加 `active`，而 `/v1/*` 判的是**同一个** `active` ⇒ 对着 `/healthz` 打
    /// 一轮就能把 `/v1` 顶到 429，而 LB 看到探针仍 200、认为实例健康：探针把闸门占满了，对外
    /// 却表现为"整机正常、谁都调不通"。
    ///
    /// 域把"能不能被拒"与"记在谁的账上"分开。这条同时钉住三件事：①探针在途不影响受限余量；
    /// ②探针域有自己的上限；③**总数**仍统计全部在途（`hlmg_active_requests` 与 `drain()` 的
    /// 语义不变）。
    #[test]
    fn a_probe_ticket_does_not_consume_the_gated_budget() {
        let m = Metrics::default();
        let g1 = m
            .try_enter(2, AdmissionDomain::Gated)
            .expect("第 1 个受限请求");
        let g2 = m
            .try_enter(2, AdmissionDomain::Gated)
            .expect("第 2 个受限请求");
        assert!(
            m.try_enter(2, AdmissionDomain::Gated).is_none(),
            "前提：受限域已满"
        );

        // 探针域有**自己**的预算（这里用 2 演示；生产取值见 `MAX_CONCURRENT_PROBES`）。
        let p1 = m
            .try_enter(2, AdmissionDomain::Probe)
            .expect("探针有自己的预算");
        let p2 = m
            .try_enter(2, AdmissionDomain::Probe)
            .expect("探针有自己的预算");
        assert_eq!(
            m.active_gated_count(),
            2,
            "探针在途不得推动受限计数（修复前这里是 4）"
        );
        assert_eq!(
            m.active_count(),
            4,
            "总数仍统计全部在途：指标与 drain 的语义不变"
        );

        // ① 受限域释放一个 → 立刻能再进，哪怕探针还在途
        drop(g1);
        let g3 = m
            .try_enter(2, AdmissionDomain::Gated)
            .expect("探针在途不该占受限余量（修复前这里是 None）");

        // ② 探针域自己的上限独立生效
        assert!(
            m.try_enter(2, AdmissionDomain::Probe).is_none(),
            "探针预算满了也要拒（无认证路径不能无界消耗）"
        );
        assert_eq!(m.active_probe_count(), 2);

        // ③ 借与还都必须精确回到 0
        drop((g2, g3, p1, p2));
        assert_eq!(
            (
                m.active_count(),
                m.active_gated_count(),
                m.active_probe_count()
            ),
            (0, 0, 0),
            "票据 Drop 必须把三个计数都还干净"
        );
    }

    /// 规格（复扫 A8）：**抓取票只占抓取域的额度，完全不算一次请求**。
    ///
    /// `/metrics` 不走 id / 访问日志 / 状态码那条链（`request_id_middleware` 对它直接放行），而
    /// 恒等式 `request_count − Σ状态码 − aborted == 0` 依赖"记了状态码才算一次请求"。所以抓取票
    /// 必须与 `try_enter` 分开：它只加抓取域的计数，`request_count` / `active` / 耗时一个都不动
    /// ——否则每次抓取都让恒等式 +1，真正的槽位泄漏会被淹没。
    #[test]
    fn a_scrape_ticket_bounds_scrapes_without_counting_them_as_requests() {
        let m = Metrics::default();
        let before = m.identity_terms();

        let s1 = m
            .try_enter_uncounted(2, AdmissionDomain::Scrape)
            .expect("抓取有自己的预算");
        let s2 = m
            .try_enter_uncounted(2, AdmissionDomain::Scrape)
            .expect("抓取有自己的预算");
        assert_eq!(m.active_scrape_count(), 2);
        assert!(
            m.try_enter_uncounted(2, AdmissionDomain::Scrape).is_none(),
            "抓取预算满了要拒（这条无认证路径此前完全无界）"
        );
        assert_eq!(
            m.identity_terms(),
            before,
            "抓取不得动 request_count（否则恒等式每次抓取漂移 +1）"
        );
        assert_eq!(
            m.active_count(),
            0,
            "抓取也不该出现在 hlmg_active_requests / drain 的读数里"
        );
        assert_eq!(
            (m.active_gated_count(), m.active_probe_count()),
            (0, 0),
            "抓取票不得推动另外两个域的计数"
        );

        drop((s1, s2));
        assert_eq!(m.active_scrape_count(), 0, "票据 Drop 要把抓取计数还干净");
        assert_eq!(m.identity_terms(), before, "归还路径同样不得动请求账本");
    }

    /// 规格（复扫 C2-5）：这一族的三种标签是**三件不同的事**，HELP 不能把它们统称"重试"。    ///
    /// 文案是给人看的，但它决定告警怎么写：把 `no-alternative` 当成重试次数，会从"重试很多"
    /// 得出"上游不稳"的错误结论——而它实际的含义是"**没有别的 agent 可换**"。
    #[test]
    fn tunnel_retry_help_does_not_call_every_outcome_a_retry() {
        let m = Metrics::default();
        for outcome in ["ok", "failed", "no-alternative"] {
            m.record_tunnel_retry(outcome);
        }
        let text = m.render(0, 0, 0, 0);
        for outcome in ["ok", "failed", "no-alternative"] {
            assert!(
                text.contains(&format!(
                    "hlmg_tunnel_retries_total{{outcome=\"{outcome}\"}} 1"
                )),
                "{outcome} 应当各自成一条样本：\n{text}"
            );
        }
        let help = text
            .lines()
            .find(|l| l.starts_with("# HELP hlmg_tunnel_retries_total"))
            .expect("HELP 必须在");
        assert!(
            !help.contains("Requests retried"),
            "整族不是 'Requests retried'（`no-alternative` 不是重试）：{help}"
        );
        assert!(
            help.contains("no-alternative"),
            "HELP 要点名那个例外：{help}"
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
    /// 规格（记录 P2-14）：**转发退出原因要真的渲染出来**，且 HELP/TYPE 成对、空家族不输出。
    #[test]
    fn forward_end_kinds_are_rendered_with_their_own_type_line() {
        let m = Metrics::default();
        assert!(
            !m.render(0, 0, 0, 0).contains("hlmg_forward_ends_total"),
            "没有记录过就不该输出这个家族（避免 HELP 后面没有样本）"
        );

        m.record_forward_end("upstream_closed");
        m.record_forward_end("upstream_closed");
        m.record_forward_end("idle_timeout");
        let text = m.render(0, 0, 0, 0);
        assert!(
            text.contains("# HELP hlmg_forward_ends_total "),
            "要有 HELP：\n{text}"
        );
        assert!(
            text.contains("# TYPE hlmg_forward_ends_total counter"),
            "要有 TYPE：\n{text}"
        );
        assert!(
            text.contains("hlmg_forward_ends_total{kind=\"upstream_closed\"} 2"),
            "计数要准：\n{text}"
        );
        assert!(
            text.contains("hlmg_forward_ends_total{kind=\"idle_timeout\"} 1"),
            "kind 要各算各的：\n{text}"
        );
    }

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
