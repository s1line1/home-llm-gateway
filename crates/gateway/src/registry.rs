//! 家端 agent 注册表：agent_id → 连接 + 健康状态 + 并发占位。

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use quinn::Connection;

#[derive(Clone, Default)]
pub struct Registry {
    inner: Arc<Mutex<HashMap<String, Entry>>>,
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
    pub fn register(&self, agent_id: String, models: Vec<String>, max_concurrency: u32, conn: Connection) {
        let stable_id = conn.stable_id();
        let mut inner = self.inner.lock().unwrap();
        if let Some(old) = inner.get(&agent_id) {
            if old.stable_id != stable_id {
                let _ = old.conn.close(0u32.into(), b"duplicate agent");
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
        if let Some(e) = self.inner.lock().unwrap().get_mut(agent_id) {
            e.last_seen = Instant::now();
        }
    }

    /// 仅当条目仍对应给定连接（stable_id）时才移除，防止误删新连接的同名条目。
    pub fn remove_if_same(&self, agent_id: &str, stable_id: usize) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(e) = inner.get(agent_id) {
            if e.stable_id == stable_id {
                inner.remove(agent_id);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// 按最少负载（在途数最小）挑选一个健康 agent 并原子占用并发槽位；
    /// 返回的 [`SlotGuard`] 期间该请求计入在途数。
    pub fn try_acquire(&self, stale_after: Duration) -> Result<(Entry, SlotGuard), AcquireError> {
        let inner = self.inner.lock().unwrap();
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
