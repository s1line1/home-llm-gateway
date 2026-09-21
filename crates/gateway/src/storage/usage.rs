//! 每 key 用量：**内存记账 + 批量落库**。与凭据存储（[`super::KeyStore`]）分开。
//!
//! ## 为什么它与凭据分开
//!
//! 两块状态**没有一次互相读写**：凭据是 `lookup → KeyRecord`（授权权威，必须即时且持久），
//! 用量是 `key_id → 累计快照`（可审计的账，落库允许滞后一个周期）。它们的失败语义也不同——
//! 凭据写失败意味着"吊销可能回滚"，用量写失败只意味着"少记一段、下轮重试"——所以两者
//! **改动的理由不同**（凭据与缓存策略 vs 记账模型与落库节奏）。
//!
//! 唯一共享的东西是那条 SQLite 连接：它是资源，不是状态，因此以 `Arc<Mutex<..>>` 注入。
//! "多久写一次、在哪个线程上写"由调用方决定（`usage_flush.rs` 的周期任务、`Gateway::shutdown`
//! 的强制落库），本模块只管"怎么写"。
//!
//! ## 记账模型（为什么是绝对值而不是增量）
//!
//! 内存里存的是**绝对累计值快照**（[`UsageSnapshot`]），落库也写这个绝对值：
//! 于是落库天然幂等、重启后不会重复累加，也不会像"取走增量"那样出现
//! "取走后落库失败 ⇒ 这段用量永久丢失"的窗口。记录里另存一份 `flushed` 作为"已落库"标记，
//! **只在提交成功后更新**，因此失败会在下一轮自动重试。
//!
//! 已知边界（`TODO.md` 的 R12）：正常关闭会强制落库，但**在强制落库之后、进程退出之前**
//! 结算的用量仍会丢；周期落库之间崩溃则最多丢一个周期。

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
};

use rusqlite::Connection;
use serde::Serialize;

// `now_secs` 只用于 `last_used_at`，与凭据表里的 `created_at` 同源（都在 `super::hash`）。
use super::hash::now_secs;

/// 每 key 的用量明细（/admin/usage 序列化用）。
#[derive(Debug, Clone, Serialize)]
pub struct KeyUsageInfo {
    pub key_id: String,
    /// key 名称快照（吊销后仍可审计名称）。
    pub name: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub requests: u64,
    /// 其中多少次请求走了估算降级（上游未提供 usage）。
    pub estimated_requests: u64,
    /// 最后使用时间（unix 秒）。
    pub last_used_at: u64,
}

/// 一次用量的绝对累计值（= 内存里的真相）。落库写的也是它，而不是增量：
/// 这样落库天然幂等、重启后不会重复累加，也不会像增量那样"丢一条就永久少一条"。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct UsageSnapshot {
    name: String,
    prompt_tokens: u64,
    completion_tokens: u64,
    requests: u64,
    estimated_requests: u64,
    last_used_at: u64,
}

/// 用量表里的一条：内存真相 + "已落库"的副本。
///
/// `flushed == current` 表示库里已经是这个值，无需再写——所以静默期完全不会碰 SQLite，
/// 有流量时也只在 flush 周期内各 key 写一次（而不是每请求一次）。
#[derive(Debug, Default)]
struct UsageRecord {
    current: UsageSnapshot,
    flushed: UsageSnapshot,
    /// 是否成功落过库。用于区分"从未落库"（即使值未变也要补写一次）与"已一致"。
    ever_flushed: bool,
}

/// 一次请求的用量增量（usage 提取见 `crate::usage_meter`）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsageDelta {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    /// 是否估算来源（上游未提供 usage）。
    pub estimated: bool,
}

/// 用量记账 + 落库原语。
///
/// `db` 与凭据存储共享（同一条 SQLite 连接）；`usage` 是本模块独占的状态。
pub(crate) struct UsageStore {
    usage: RwLock<HashMap<String, UsageRecord>>,
    db: Arc<Mutex<Option<Connection>>>,
}

impl UsageStore {
    /// 建实例：库可用则从 `key_usage` 载入（失败只告警、按空账本继续，与凭据存储同风格），
    /// 库不可用（`None`）则纯内存记账。
    pub(crate) fn new(db: Arc<Mutex<Option<Connection>>>) -> Self {
        let usage = match db.lock().unwrap().as_ref() {
            Some(conn) => match load_usage(conn) {
                Ok(map) => map,
                Err(e) => {
                    tracing::warn!("usage db load failed: {e}; using empty usage store");
                    HashMap::new()
                }
            },
            None => HashMap::new(),
        };
        Self {
            usage: RwLock::new(usage),
            db,
        }
    }

    /// 记录一次用量并**立即同步落库**（= `accumulate` + `persist`）。
    ///
    /// 仅测试使用：生产路径只做内存累加，落库交给后台周期任务
    /// （`usage_flush::spawn`）与关闭前的强制 flush。这里保留同步组合是为了让
    /// 测试能一步写完就读库断言，因此用 `cfg(test)` 挡在生产代码之外。
    #[cfg(test)]
    pub(crate) fn record(&self, key_id: &str, name: &str, delta: &UsageDelta) {
        self.accumulate(key_id, name, delta);
        self.persist(key_id, name, delta);
    }

    /// 只做内存累加：纳秒级、无 IO，用于让 `/admin/usage`（读的正是这份内存计数）
    /// 在响应返回时立即一致。
    pub(crate) fn accumulate(&self, key_id: &str, name: &str, delta: &UsageDelta) {
        let mut usage = self.usage.write().unwrap();
        let rec = usage.entry(key_id.to_string()).or_default();
        if rec.current.name.is_empty() {
            rec.current.name = name.to_string();
        }
        rec.current.prompt_tokens += delta.prompt_tokens;
        rec.current.completion_tokens += delta.completion_tokens;
        rec.current.requests += 1;
        if delta.estimated {
            rec.current.estimated_requests += 1;
        }
        rec.current.last_used_at = now_secs();
    }

    /// 是否有"内存值尚未落库"的 key（静默期返回 false，调用方可跳过整轮 flush）。
    pub(crate) fn has_pending(&self) -> bool {
        self.usage
            .read()
            .unwrap()
            .values()
            .any(|r| !r.ever_flushed || r.current != r.flushed)
    }

    /// 把内存里的用量**绝对累计值**批量落库（一个事务，每个 key 一行）。
    ///
    /// 这是量到量级差异的关键改动：原来每个请求都要 spawn 一个阻塞任务去抢全局 `db`
    /// 锁写一行，实测把 2 vCPU 的上限摁在约 190 QPS（云端 515 个线程里 514 个卡在
    /// futex 等这把锁）。改成"按周期把各 key 的最新值覆盖写一次"之后，写库次数从
    /// 每请求一次降到每周期一次，且写的是绝对值——幂等、丢不掉、重启不重复累加。
    ///
    /// 记录里维护 `flushed` 副本作为"已落库"标记：只写 `current != flushed` 的 key，
    /// 且**成功后才更新标记**，所以落库失败会在下一轮自动重试。
    ///
    /// 返回本轮写入的 key 数；`force = true` 时忽略"是否变化"（用于关闭前落库）。
    pub(crate) fn flush_once(&self, force: bool) -> usize {
        // 准备阶段只在内存锁内做，不碰 SQLite。
        let batch: Vec<(String, UsageSnapshot)> = {
            let usage = self.usage.read().unwrap();
            usage
                .iter()
                .filter(|(_, r)| force || !r.ever_flushed || r.current != r.flushed)
                .map(|(k, r)| (k.clone(), r.current.clone()))
                .collect()
        };
        if batch.is_empty() {
            return 0;
        }

        let mut conn = self.db.lock().unwrap();
        let Some(conn) = conn.as_mut() else {
            return 0; // 无持久化（内存模式）：没有库可写
        };
        let tx = match conn.transaction() {
            Ok(tx) => tx,
            Err(e) => {
                tracing::warn!("usage flush: begin transaction failed: {e}");
                return 0;
            }
        };
        let mut written = 0usize;
        for (key_id, snap) in &batch {
            let r = tx.execute(
                "INSERT INTO key_usage
                 (key_id, name, prompt_tokens, completion_tokens, requests, estimated_requests, last_used_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(key_id) DO UPDATE SET
                   name = excluded.name,
                   prompt_tokens = excluded.prompt_tokens,
                   completion_tokens = excluded.completion_tokens,
                   requests = excluded.requests,
                   estimated_requests = excluded.estimated_requests,
                   last_used_at = excluded.last_used_at",
                rusqlite::params![
                    key_id,
                    snap.name,
                    snap.prompt_tokens as i64,
                    snap.completion_tokens as i64,
                    snap.requests as i64,
                    snap.estimated_requests as i64,
                    snap.last_used_at as i64
                ],
            );
            match r {
                Ok(_) => written += 1,
                Err(e) => {
                    tracing::warn!(key_id = %key_id, "usage flush failed: {e}");
                    return written; // 事务未提交，标记不动 → 下一轮重试
                }
            }
        }
        if let Err(e) = tx.commit() {
            tracing::warn!("usage flush: commit failed: {e}");
            return 0;
        }
        // 提交成功后才更新"已落库"标记。
        let mut usage = self.usage.write().unwrap();
        for (key_id, snap) in batch {
            if let Some(rec) = usage.get_mut(&key_id) {
                rec.flushed = snap;
                rec.ever_flushed = true;
            }
        }
        written
    }

    /// 关闭前落库：把全部 key 的当前值无条件写一次（可能包含未变化的，代价可忽略）。
    pub(crate) fn flush_blocking(&self) -> usize {
        self.flush_once(true)
    }

    /// 把一次用量**增量**写穿到 SQLite（旧的每请求写库路径，仅测试用）。
    ///
    /// 生产路径已改为 `flush_once`：按周期把各 key 的**绝对累计值**批量写一次。
    /// 增量写在热点上每次都要抢全局 `db` 锁 + 提交一次事务，实测把 2 vCPU 的吞吐
    /// 摁在约 190 QPS（云端 515 线程 / 514 个卡在 futex 等锁），所以这里只留给测试
    /// 构造"库里已有某值"的场景。**阻塞调用**，不要放回请求路径。
    #[cfg(test)]
    pub(crate) fn persist(&self, key_id: &str, name: &str, delta: &UsageDelta) {
        if let Some(conn) = self.db.lock().unwrap().as_mut() {
            let r = conn.execute(
                "INSERT INTO key_usage
                 (key_id, name, prompt_tokens, completion_tokens, requests, estimated_requests, last_used_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(key_id) DO UPDATE SET
                   name = excluded.name,
                   prompt_tokens = key_usage.prompt_tokens + excluded.prompt_tokens,
                   completion_tokens = key_usage.completion_tokens + excluded.completion_tokens,
                   requests = key_usage.requests + excluded.requests,
                   estimated_requests = key_usage.estimated_requests + excluded.estimated_requests,
                   last_used_at = excluded.last_used_at",
                rusqlite::params![
                    key_id,
                    name,
                    delta.prompt_tokens as i64,
                    delta.completion_tokens as i64,
                    1i64,
                    delta.estimated as i64,
                    now_secs() as i64
                ],
            );
            if let Err(e) = r {
                tracing::warn!("usage persist failed: {e}");
            }
        }
    }

    /// 单个 key 的用量快照（无记录 → None）。
    pub(crate) fn of(&self, key_id: &str) -> Option<KeyUsageInfo> {
        let usage = self.usage.read().unwrap();
        let rec = usage.get(key_id)?;
        Some(cell_to_info(key_id, &rec.current))
    }

    /// 全部 key 的用量快照（按 key_id 排序）。
    pub(crate) fn snapshot(&self) -> Vec<KeyUsageInfo> {
        let usage = self.usage.read().unwrap();
        let mut out: Vec<KeyUsageInfo> = usage
            .iter()
            .map(|(id, rec)| cell_to_info(id, &rec.current))
            .collect();
        out.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        out
    }
}

/// 把原子单元转成可序列化的明细。
fn cell_to_info(key_id: &str, snap: &UsageSnapshot) -> KeyUsageInfo {
    KeyUsageInfo {
        key_id: key_id.to_string(),
        name: snap.name.clone(),
        prompt_tokens: snap.prompt_tokens,
        completion_tokens: snap.completion_tokens,
        total_tokens: snap.prompt_tokens + snap.completion_tokens,
        requests: snap.requests,
        estimated_requests: snap.estimated_requests,
        last_used_at: snap.last_used_at,
    }
}

/// 从 SQLite 加载用量（key = key_id）。
fn load_usage(conn: &Connection) -> rusqlite::Result<HashMap<String, UsageRecord>> {
    let mut out = HashMap::new();
    let mut stmt = conn.prepare(
        "SELECT key_id, name, prompt_tokens, completion_tokens, requests, estimated_requests, last_used_at
         FROM key_usage",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            UsageSnapshot {
                name: r.get::<_, String>(1)?,
                prompt_tokens: r.get::<_, i64>(2)?.max(0) as u64,
                completion_tokens: r.get::<_, i64>(3)?.max(0) as u64,
                requests: r.get::<_, i64>(4)?.max(0) as u64,
                estimated_requests: r.get::<_, i64>(5)?.max(0) as u64,
                last_used_at: r.get::<_, i64>(6)?.max(0) as u64,
            },
        ))
    })?;
    for row in rows {
        let (key_id, snap) = row?;
        // 库里的值既是"当前累计"的起点，也正好是"已落库"状态。
        out.insert(
            key_id,
            UsageRecord {
                current: snap.clone(),
                flushed: snap,
                ever_flushed: true,
            },
        );
    }
    Ok(out)
}
