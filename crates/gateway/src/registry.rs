//! edge-agent 注册表：agent_id → 连接 + 健康状态 + 并发占位。

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU32, AtomicUsize, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};

use serde::Serialize;
use tracing::{info, warn};

/// 连接身份发号器：给每条注册进来的连接发一个**进程内唯一且永不复用**的编号。
///
/// 为什么不用 `Handle::id()`：那是 s2n-quic 的**端点内部**连接序号，源码注释写的是
/// "stable and internally identifies a connection over the whole lifetime of **an endpoint**"，
/// 而生成器是每个端点各自从 0 开始（s2n-quic-transport/src/endpoint/mod.rs:79,323、
/// src/connection/internal_connection_id.rs:26-32）——跨端点必然撞号：注册表的单元测试
/// 里每次新建一对端点，两条连接的 id 都是 0，于是 `remove_if_same` 会误删同名新连接的条目。
/// 注册表要的是"同一进程内、对一条连接稳定、且不复用"的编号（复用同样会导致误删），自己发号最稳。
static NEXT_CONN_ID: AtomicUsize = AtomicUsize::new(1);

/// agent 明细快照（供 /admin/agents 管理接口序列化）。
#[derive(Debug, Clone, Serialize)]
pub struct AgentInfo {
    pub agent_id: String,
    pub models: Vec<String>,
    pub max_concurrency: u32,
    /// 当前在途请求数。
    pub inflight: u32,
    /// 距上次心跳的秒数。
    pub last_seen_secs_ago: u64,
}

#[derive(Clone, Default)]
pub struct Registry {
    inner: Arc<RwLock<HashMap<String, Entry>>>,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub conn: s2n_quic::connection::Handle,
    pub stable_id: usize,
    /// 注册时的 agent_id。`try_acquire` 只交出 `Entry`（HashMap 的 key 不在其中），
    /// 而隧道写超时后需要按 stable_id 把这条坏连接摘掉（见 [`Registry::evict`]），
    /// 所以 id 必须随条目一起带出来。
    pub agent_id: String,
    pub models: Vec<String>,
    pub max_concurrency: u32,
    /// 当前在途请求数（admission control）。
    pub inflight: Arc<AtomicU32>,
    pub last_seen: Instant,
}

impl Registry {
    /// 注册 agent；若同名 agent 已有其他连接，关闭旧连接。
    ///
    /// 返回本次注册分配的 `stable_id`：调用方之后要用它调 [`Self::remove_if_same`] 摘除条目，
    /// 所以**必须用这个返回值**，不要自己另算一份——`Entry.stable_id` 由这里独占决定，
    /// 两处各算一次就会对不上，连接结束时条目永远摘不掉（注册表只增不减）。
    pub fn register(
        &self,
        agent_id: String,
        models: Vec<String>,
        max_concurrency: u32,
        conn: s2n_quic::connection::Handle,
    ) -> usize {
        let stable_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        let mut inner = self.inner.write().unwrap();
        if let Some(old) = inner.get(&agent_id) {
            if old.stable_id != stable_id {
                warn!(agent = %agent_id, "duplicate agent connection, closing old one");
                old.conn.close(0u32.into())
            }
        }
        inner.insert(
            agent_id.clone(),
            Entry {
                conn,
                stable_id,
                agent_id,
                models,
                max_concurrency,
                inflight: Arc::new(AtomicU32::new(0)),
                last_seen: Instant::now(),
            },
        );
        stable_id
    }

    pub fn heartbeat(&self, agent_id: &str) {
        if let Some(e) = self.inner.write().unwrap().get_mut(agent_id) {
            e.last_seen = Instant::now();
        }
    }

    /// 仅当条目仍对应给定连接（stable_id）时才移除，防止误删新连接的同名条目。
    pub fn remove_if_same(&self, agent_id: &str, stable_id: usize) {
        let mut inner = self.inner.write().unwrap();
        if let Some(e) = inner.get(agent_id) {
            if e.stable_id == stable_id {
                inner.remove(agent_id);
                info!(agent = %agent_id, "agent removed (connection closed)");
            }
        }
    }

    /// 按 stable_id 摘除条目：用于"隧道控制操作超时 = 这条连接已经死了"的场合
    /// （打开流 / 写请求帧 / 等响应头任一超时）。
    ///
    /// 为什么必须有这条路径：注册表条目原本只在 `accept_bidirectional_stream()` 返回时
    /// 才被摘掉，而对端进程消失（没有 CONNECTION_CLOSE）时那个循环不会返回——条目会一直
    /// 留着，后续请求继续选中同一条死连接，每个都白等一次超时。超时是"连接已死"的
    /// 可靠信号，据此摘掉，后续请求才会立刻落到 `NoAgent`（503）或别的 agent 上。
    ///
    /// 返回是否真的摘掉了（false = 已经被别人摘掉/已被新连接替换）。
    pub fn evict(&self, stable_id: usize) -> bool {
        let mut inner = self.inner.write().unwrap();
        let hit = inner
            .iter()
            .find(|(_, e)| e.stable_id == stable_id)
            .map(|(k, _)| k.clone());
        match hit {
            Some(agent_id) => {
                inner.remove(&agent_id);
                info!(agent = %agent_id, "agent evicted (tunnel op timed out)");
                true
            }
            None => false,
        }
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    /// 注册表里 **心跳未过期** 的 agent 数（= 真正能被路由的候选数）。
    ///
    /// 与 [`Self::len`] 的区别很要紧：条目要等连接真正关闭才摘除，所以失联 agent
    /// 会继续被 `len()`（以及 `/metrics hlmg_agents`、`/admin/agents`）算作"在线"，
    /// 但它**不参与路由**。排查"所有请求 503"时必须能区分这两者——否则会误判为
    /// "agent 掉了"，实际是"注册表里有、但全部不健康"。
    pub fn healthy_count(&self, stale_after: Duration) -> usize {
        let inner = self.inner.read().unwrap();
        inner
            .values()
            .filter(|e| e.last_seen.elapsed() < stale_after)
            .count()
    }

    /// 挑不出候选时的诊断快照（只用于失败路径的日志/指标，不进热路径）。
    pub fn status(&self, stale_after: Duration) -> RegistryStatus {
        let inner = self.inner.read().unwrap();
        let now = Instant::now();
        let mut healthy = 0usize;
        let mut oldest: Option<Duration> = None;
        for e in inner.values() {
            let age = now.duration_since(e.last_seen);
            if age < stale_after {
                healthy += 1;
            }
            oldest = Some(match oldest {
                Some(o) if o >= age => o,
                _ => age,
            });
        }
        RegistryStatus {
            registered: inner.len(),
            healthy,
            oldest_last_seen_ago: oldest,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }

    /// 返回全部已注册 agent 的明细快照（按 agent_id 排序）。
    pub fn snapshot(&self) -> Vec<AgentInfo> {
        let inner = self.inner.read().unwrap();
        let now = Instant::now();
        let mut out: Vec<AgentInfo> = inner
            .iter()
            .map(|(id, e)| AgentInfo {
                agent_id: id.clone(),
                models: e.models.clone(),
                max_concurrency: e.max_concurrency,
                inflight: e.inflight.load(Ordering::Relaxed),
                last_seen_secs_ago: now.duration_since(e.last_seen).as_secs(),
            })
            .collect();
        out.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
        out
    }

    /// 聚合所有**健康** agent 显式声明的模型（去重、排序）。
    /// `["*"]` 不贡献条目（全匹配，但具体能跑什么只有上游知道）。
    pub fn healthy_models(&self, stale_after: Duration) -> Vec<String> {
        let inner = self.inner.read().unwrap();
        let mut out: Vec<String> = inner
            .values()
            .filter(|e| e.last_seen.elapsed() < stale_after)
            .flat_map(|e| e.models.iter().filter(|m| m.as_str() != "*").cloned())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// 在**能服务指定模型**的健康 agent 中挑选一个并原子占用并发槽位；
    /// 返回的 [`SlotGuard`] 期间该请求计入在途数。
    ///
    /// 模型匹配语义：agent 声明的 `models` 含 `"*"`（全匹配/兜底）或含 `model`。
    /// 优先级：**精确声明该模型者优先于仅 `*` 通配者**（通配是兜底，不抢单）；
    /// 同级内按负载最轻优先，同等负载取最近心跳者（多 agent 均衡）。
    pub fn try_acquire(
        &self,
        stale_after: Duration,
        model: &str,
    ) -> Result<(Entry, SlotGuard), AcquireError> {
        let inner = self.inner.read().unwrap();
        let mut candidates: Vec<&Entry> = inner
            .values()
            .filter(|e| e.last_seen.elapsed() < stale_after)
            .collect();
        if candidates.is_empty() {
            return Err(AcquireError::NoAgent);
        }
        // 模型过滤：只保留能服务请求模型的 agent（声明含 "*" 或含 model）
        candidates.retain(|e| e.models.iter().any(|m| m == "*" || m == model));
        if candidates.is_empty() {
            return Err(AcquireError::NoModel);
        }
        // 排序：精确声明（exact=true）排前 → 负载轻优先 → 心跳新者优先。
        // bool 排序 false < true，故用 !exact 让精确者排前。
        candidates.sort_by_key(|e| {
            let exact = e.models.iter().any(|m| m == model);
            (
                !exact,
                e.inflight.load(Ordering::Relaxed),
                std::cmp::Reverse(e.last_seen),
            )
        });
        for candidate in candidates {
            let entry = candidate.clone();
            let acquired = entry.max_concurrency == 0
                || entry
                    .inflight
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                        (n < entry.max_concurrency).then_some(n + 1)
                    })
                    .is_ok();
            if acquired {
                let guard = SlotGuard(entry.inflight.clone());
                return Ok((entry, guard));
            }
        }
        Err(AcquireError::AtCapacity)
    }
}

/// 拒绝请求时的注册表诊断快照（仅日志/指标用）。
#[derive(Debug, Clone, Copy, Default)]
pub struct RegistryStatus {
    /// 注册表条目数（含失联但连接未关的）。
    pub registered: usize,
    /// 心跳未过期、真正可路由的条目数。
    pub healthy: usize,
    /// 最久没有心跳的条目距今多久（None = 注册表为空）。
    pub oldest_last_seen_ago: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireError {
    /// 没有任何健康 agent。
    NoAgent,
    /// 有健康 agent，但没有任何一个能服务请求的模型。
    NoModel,
    /// agent 并发已满。
    AtCapacity,
}

/// Drop 时自动归还并发槽位。
pub struct SlotGuard(Arc<AtomicU32>);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    /// 建一对本地 s2n-quic 端点，返回**客户端连接句柄**（无 mTLS，只为构造 Handle）。
    ///
    /// 返回 `Handle` 而不是 `Connection`，因为注册表里存的就是 Handle（`Entry.conn`）：
    /// Handle 是 `#[derive(Clone, Debug)]`（s2n-quic/src/connection/handle.rs:431），
    /// 既能进 HashMap 也能被 `try_acquire` clone 出来；而 `Connection` 没有 Clone。
    ///
    /// 返回后端点随作用域结束 drop、连接随之关闭，但测试只读 `id()` 与 `inflight`：
    /// `Handle::id()` 是无锁的字段读取、也不返回 Result
    /// （s2n-quic-transport/src/connection/connection_container.rs:319-321），
    /// 所以连接死掉之后读 id 依然有效——注册表测试不依赖连接可用性。
    async fn test_connection() -> s2n_quic::connection::Handle {
        proto::install_ring_crypto_provider();

        // 服务端：自签证书；ALPN 两端必须一致，否则握手协商不上
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

        let mut stls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        stls.alpn_protocols = vec![proto::ALPN.to_vec()];

        let mut server = s2n_quic::Server::builder()
            .with_tls(s2n_quic::provider::tls::rustls::Server::from(Arc::new(
                stls,
            )))
            .unwrap()
            .with_io("127.0.0.1:0")
            .unwrap()
            .start()
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        // 必须驱动服务端 accept，否则 QUIC 握手永远无法完成；
        // 握完把两半句柄挂在 pending 上——返回会 drop 句柄、立刻关掉连接。
        tokio::spawn(async move {
            if let Some(conn) = server.accept().await {
                let (_handle, _acceptor) = conn.split();
                std::future::pending::<()>().await;
            }
        });

        // 客户端：信任自签证书（无 mTLS），ALPN 与服务端一致
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let mut ctls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        ctls.alpn_protocols = vec![proto::ALPN.to_vec()];

        let client = s2n_quic::Client::builder()
            .with_tls(s2n_quic::provider::tls::rustls::Client::from(Arc::new(
                ctls,
            )))
            .unwrap()
            .with_io("0.0.0.0:0")
            .unwrap()
            .start()
            .unwrap();

        let conn = client
            .connect(s2n_quic::client::Connect::new(server_addr).with_server_name("localhost"))
            .await
            .unwrap();
        let (handle, _acceptor) = conn.split();
        handle
    }

    #[tokio::test]
    async fn register_duplicate_replaces_and_len() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let id1 = reg.register("home-1".into(), vec!["m".into()], 2, c1.clone());
        assert_eq!(reg.len(), 1);
        // 同名重复注册：旧连接被关闭，条目替换为新连接，长度仍为 1
        let c2 = test_connection().await;
        let id2 = reg.register("home-1".into(), vec!["m".into()], 2, c2.clone());
        assert_eq!(reg.len(), 1);
        let entry = reg.inner.read().unwrap().get("home-1").cloned().unwrap();
        assert_ne!(id1, id2, "每次注册都必须拿到新的 stable_id");
        assert_eq!(entry.stable_id, id2, "条目应属于后注册的那条连接");
    }

    #[tokio::test]
    async fn remove_if_same_guards_stable_id() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        let id1 = reg.register("x".into(), vec![], 4, c1.clone());
        let id2 = reg.register("x".into(), vec![], 4, c2.clone()); // 条目换成 c2，c1 被关
                                                                   // 用旧连接的 stable_id 移除 → 不删除（条目现在属于 c2）
        reg.remove_if_same("x", id1);
        assert_eq!(reg.len(), 1);
        // 用当前连接的 stable_id 移除 → 删除
        reg.remove_if_same("x", id2);
        assert_eq!(reg.len(), 0);
        // 对不存在的 agent 移除 → 无害
        reg.remove_if_same("ghost", id2);
    }

    /// 可观测性契约：**注册条目数**与**可路由数**必须能分开看。
    ///
    /// 失联 agent 的条目要等连接真正关闭才摘除，所以 `len()` 会把它算作"在线"，
    /// 而 `try_acquire` 会把它过滤掉。两者混为一谈时，"所有请求 503"会被误读成
    /// "agent 掉了"——线上排查正是卡在这里（/metrics 显示 2 个 agent，实际全部 stale）。
    #[tokio::test]
    async fn healthy_count_separates_registered_from_routable() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        reg.register("fresh".into(), vec!["*".into()], 4, c1.clone());
        reg.register("stale".into(), vec!["*".into()], 4, c2.clone());

        let stale_after = Duration::from_millis(30);
        tokio::time::sleep(Duration::from_millis(50)).await;
        // 两条都过期
        assert_eq!(reg.len(), 2, "条目仍在注册表里（连接没关）");
        assert_eq!(reg.healthy_count(stale_after), 0, "但没有一条可路由");
        let st = reg.status(stale_after);
        assert_eq!((st.registered, st.healthy), (2, 0));
        assert!(st.oldest_last_seen_ago.unwrap() >= Duration::from_millis(50));
        assert!(matches!(
            reg.try_acquire(stale_after, "qwen2.5"),
            Err(AcquireError::NoAgent)
        ));

        // 一条心跳恢复 → 只有它可路由
        reg.heartbeat("fresh");
        assert_eq!(reg.len(), 2);
        assert_eq!(reg.healthy_count(stale_after), 1);
        assert_eq!(reg.status(stale_after).healthy, 1);
        assert!(reg.try_acquire(stale_after, "qwen2.5").is_ok());

        // 空注册表：两个数都是 0，且没有 last_seen 可报
        let empty = Registry::default();
        assert_eq!(empty.healthy_count(stale_after), 0);
        assert_eq!(empty.status(stale_after).registered, 0);
        assert!(empty.status(stale_after).oldest_last_seen_ago.is_none());
    }

    #[tokio::test]
    async fn heartbeat_refreshes_stale_entry() {
        let reg = Registry::default();
        let conn = test_connection().await;
        reg.register("h".into(), vec!["*".into()], 4, conn.clone());
        // 30ms 后仍按 10ms 判定失联
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(matches!(
            reg.try_acquire(Duration::from_millis(10), "qwen2.5"),
            Err(AcquireError::NoAgent)
        ));
        // 心跳刷新 last_seen → 恢复可用
        reg.heartbeat("h");
        assert!(reg
            .try_acquire(Duration::from_millis(100), "qwen2.5")
            .is_ok());
        // 对不存在的 agent 心跳 → 无害
        reg.heartbeat("ghost");
    }

    #[tokio::test]
    async fn try_acquire_spreads_load_and_capacity() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        reg.register("a".into(), vec!["*".into()], 1, c1.clone());
        reg.register("b".into(), vec!["*".into()], 1, c2.clone());

        // 两个容量各 1 的 agent：连续两个请求应命中不同 agent
        let (e1, s1) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        let (e2, s2) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        assert_ne!(e1.stable_id, e2.stable_id);
        // 全满 → AtCapacity
        assert!(matches!(
            reg.try_acquire(Duration::from_secs(10), "qwen2.5"),
            Err(AcquireError::AtCapacity)
        ));
        drop(s1);
        drop(s2);
        // 槽位释放后恢复
        assert!(reg.try_acquire(Duration::from_secs(10), "qwen2.5").is_ok());
    }

    #[tokio::test]
    async fn max_concurrency_zero_always_acquires() {
        let reg = Registry::default();
        let conn = test_connection().await;
        reg.register("z".into(), vec!["*".into()], 0, conn.clone()); // 0 = 不限
        for _ in 0..5 {
            let (_entry, _slot) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        }
    }

    #[tokio::test]
    async fn try_acquire_filters_by_model() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        let c3 = test_connection().await;
        reg.register(
            "qwen-edge".into(),
            vec!["qwen2.5".into()],
            1, // 容量 1：打满后验证回落通配
            c1.clone(),
        );
        reg.register("llama-edge".into(), vec!["llama3".into()], 4, c2.clone());
        // 通配 edge：任何模型都可路由到它
        reg.register("wildcard-edge".into(), vec!["*".into()], 4, c3.clone());

        // qwen2.5 → 精确声明的 qwen-edge 优先于仅通配的 wildcard-edge，
        // 绝不能是 llama-edge
        let (e, s) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        let id = {
            let inner = reg.inner.read().unwrap();
            inner
                .iter()
                .find(|(_, v)| v.stable_id == e.stable_id)
                .map(|(id, _)| id.clone())
                .unwrap()
        };
        assert_eq!(id, "qwen-edge", "exact model match must win over wildcard");
        drop(s);

        // llama3 → 精确声明的 llama-edge 优先
        let (e, s) = reg.try_acquire(Duration::from_secs(10), "llama3").unwrap();
        let id = {
            let inner = reg.inner.read().unwrap();
            inner
                .iter()
                .find(|(_, v)| v.stable_id == e.stable_id)
                .map(|(id, _)| id.clone())
                .unwrap()
        };
        assert_eq!(id, "llama-edge", "exact model match must win over wildcard");
        drop(s);

        // 精确 edge 容量打满后，请求回落到通配 edge
        let (e1, s1) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        let (e2, s2) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        assert_ne!(
            e1.stable_id, e2.stable_id,
            "second qwen2.5 request should fall back to wildcard edge"
        );
        drop(s1);
        drop(s2);
    }

    #[tokio::test]
    async fn try_acquire_returns_no_model_when_none_match() {
        let reg = Registry::default();
        // 无通配 agent：所有健康 agent 都无法服务 mistral-7b
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        reg.register("qwen-edge".into(), vec!["qwen2.5".into()], 4, c1.clone());
        reg.register("llama-edge".into(), vec!["llama3".into()], 4, c2.clone());
        assert!(matches!(
            reg.try_acquire(Duration::from_secs(10), "mistral-7b"),
            Err(AcquireError::NoModel)
        ));
    }

    #[tokio::test]
    async fn healthy_models_aggregates_and_excludes_wildcard() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        reg.register(
            "edge-a".into(),
            vec!["qwen2.5".into(), "llama3".into()],
            4,
            c1.clone(),
        );
        reg.register(
            "edge-b".into(),
            vec!["llama3".into(), "*".into()],
            4,
            c2.clone(),
        );
        // 去重、排序、排除 "*"
        assert_eq!(
            reg.healthy_models(Duration::from_secs(10)),
            vec!["llama3", "qwen2.5"]
        );
        // 失联 agent 的模型不聚合
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(reg.healthy_models(Duration::from_millis(10)).is_empty());
    }

    #[tokio::test]
    async fn snapshot_reports_agent_details() {
        let reg = Registry::default();
        let conn = test_connection().await;
        reg.register(
            "home-1".into(),
            vec!["qwen2.5".into(), "llama3".into()],
            2,
            conn.clone(),
        );
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].agent_id, "home-1");
        assert_eq!(
            snap[0].models,
            vec!["qwen2.5".to_string(), "llama3".to_string()]
        );
        assert_eq!(snap[0].max_concurrency, 2);
        assert_eq!(snap[0].inflight, 0);
        assert!(snap[0].last_seen_secs_ago < 1, "freshly registered agent");

        // 按 agent_id 排序、空注册表为空
        let conn2 = test_connection().await;
        reg.register("agent-a".into(), vec![], 4, conn2.clone());
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].agent_id, "agent-a");
        assert_eq!(snap[1].agent_id, "home-1");
        assert!(Registry::default().snapshot().is_empty());
    }
}
