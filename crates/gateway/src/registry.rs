//! 家端 agent 注册表：agent_id → 连接 + 健康状态 + 并发占位。

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};

use quinn::Connection;
use serde::Serialize;
use tracing::{info, warn};

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

#[derive(Clone)]
pub struct Entry {
    pub conn: Connection,
    pub stable_id: usize,
    pub models: Vec<String>,
    pub max_concurrency: u32,
    /// 当前在途请求数（admission control）。
    pub inflight: Arc<AtomicU32>,
    pub last_seen: Instant,
}

impl Registry {
    /// 注册 agent；若同名 agent 已有其他连接，关闭旧连接。
    pub fn register(
        &self,
        agent_id: String,
        models: Vec<String>,
        max_concurrency: u32,
        conn: Connection,
    ) {
        let stable_id = conn.stable_id();
        let mut inner = self.inner.write().unwrap();
        if let Some(old) = inner.get(&agent_id) {
            if old.stable_id != stable_id {
                warn!(agent = %agent_id, "duplicate agent connection, closing old one");
                old.conn.close(0u32.into(), b"duplicate agent");
            }
        }
        inner.insert(
            agent_id,
            Entry {
                conn,
                stable_id,
                models,
                max_concurrency,
                inflight: Arc::new(AtomicU32::new(0)),
                last_seen: Instant::now(),
            },
        );
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

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
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

    /// 按最少负载（在途数最小）挑选一个健康 agent 并原子占用并发槽位；
    /// 返回的 [`SlotGuard`] 期间该请求计入在途数。
    pub fn try_acquire(&self, stale_after: Duration) -> Result<(Entry, SlotGuard), AcquireError> {
        let inner = self.inner.read().unwrap();
        let mut candidates: Vec<&Entry> = inner
            .values()
            .filter(|e| e.last_seen.elapsed() < stale_after)
            .collect();
        if candidates.is_empty() {
            return Err(AcquireError::NoAgent);
        }
        // 负载最轻优先；同等负载取最近心跳者（多 agent 均衡）
        candidates.sort_by_key(|e| {
            (
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireError {
    /// 没有任何健康 agent。
    NoAgent,
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
    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    /// 建立一对本地 QUIC 端点并返回客户端连接（无 mTLS，仅用于构造 Connection）。
    /// 返回后端点随作用域结束 drop，连接被关闭，但 stable_id / inflight 字段仍可读，
    /// 注册表测试不依赖连接可用性。
    async fn test_connection() -> Connection {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        let quic = QuicServerConfig::try_from(tls).unwrap();
        let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(quic));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
        scfg.transport_config(Arc::new(transport));
        let server = quinn::Endpoint::server(scfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        // 必须驱动服务端 accept 循环，否则 QUIC 握手永远无法完成
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                tokio::spawn(async move {
                    let _ = incoming.await;
                });
            }
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let client_tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let client_cfg =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls).unwrap()));
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(client_cfg);
        client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn register_duplicate_replaces_and_len() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        reg.register("home-1".into(), vec!["m".into()], 2, c1.clone());
        assert_eq!(reg.len(), 1);
        // 同名重复注册：旧连接被关闭，条目替换为新连接，长度仍为 1
        let c2 = test_connection().await;
        reg.register("home-1".into(), vec!["m".into()], 2, c2.clone());
        assert_eq!(reg.len(), 1);
        let entry = reg.inner.read().unwrap().get("home-1").cloned().unwrap();
        assert_eq!(entry.stable_id, c2.stable_id());
    }

    #[tokio::test]
    async fn remove_if_same_guards_stable_id() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        reg.register("x".into(), vec![], 4, c1.clone());
        reg.register("x".into(), vec![], 4, c2.clone()); // 条目换成 c2，c1 被关
                                                         // 用旧连接的 stable_id 移除 → 不删除（条目现在属于 c2）
        reg.remove_if_same("x", c1.stable_id());
        assert_eq!(reg.len(), 1);
        // 用当前连接的 stable_id 移除 → 删除
        reg.remove_if_same("x", c2.stable_id());
        assert_eq!(reg.len(), 0);
        // 对不存在的 agent 移除 → 无害
        reg.remove_if_same("ghost", c2.stable_id());
    }

    #[tokio::test]
    async fn heartbeat_refreshes_stale_entry() {
        let reg = Registry::default();
        let conn = test_connection().await;
        reg.register("h".into(), vec![], 4, conn.clone());
        // 30ms 后仍按 10ms 判定失联
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(matches!(
            reg.try_acquire(Duration::from_millis(10)),
            Err(AcquireError::NoAgent)
        ));
        // 心跳刷新 last_seen → 恢复可用
        reg.heartbeat("h");
        assert!(reg.try_acquire(Duration::from_millis(100)).is_ok());
        // 对不存在的 agent 心跳 → 无害
        reg.heartbeat("ghost");
    }

    #[tokio::test]
    async fn try_acquire_spreads_load_and_capacity() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        reg.register("a".into(), vec![], 1, c1.clone());
        reg.register("b".into(), vec![], 1, c2.clone());

        // 两个容量各 1 的 agent：连续两个请求应命中不同 agent
        let (e1, s1) = reg.try_acquire(Duration::from_secs(10)).unwrap();
        let (e2, s2) = reg.try_acquire(Duration::from_secs(10)).unwrap();
        assert_ne!(e1.stable_id, e2.stable_id);
        // 全满 → AtCapacity
        assert!(matches!(
            reg.try_acquire(Duration::from_secs(10)),
            Err(AcquireError::AtCapacity)
        ));
        drop(s1);
        drop(s2);
        // 槽位释放后恢复
        assert!(reg.try_acquire(Duration::from_secs(10)).is_ok());
    }

    #[tokio::test]
    async fn max_concurrency_zero_always_acquires() {
        let reg = Registry::default();
        let conn = test_connection().await;
        reg.register("z".into(), vec![], 0, conn.clone()); // 0 = 不限
        for _ in 0..5 {
            let (_entry, _slot) = reg.try_acquire(Duration::from_secs(10)).unwrap();
        }
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
