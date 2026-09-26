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
use crate::sync::{lock_or_recover, read_or_recover, write_or_recover};

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
    /// 库是否可用。**构造时定死**：`db` 里的 `Option` 一旦建成就不再变（打不开的库降级成
    /// `None`，而 `None` 不会被重新填上），所以"有没有库"是这个模块的**静态事实**。
    /// 缓存它让 [`Self::has_pending`] 不必去抢那把同步 `db` 锁——见那里的说明（复扫 C2-2）。
    has_db: bool,
    /// [`Self::flush_once`] 的串行化闸门（复扫 C1）。
    ///
    /// 周期任务与关闭路径可以**并发**进来，而 `flush_once` 在拿 `db` 锁之前就取快照 ⇒
    /// "先取快照、后拿到 `db` 锁"的那次会用**旧值覆盖新值**。闸门把"取快照 → 提交 → 回写
    /// `flushed` 标记"整段串起来，于是后到的 flush 一定看到最新的快照。
    flush_gate: Mutex<()>,
}

impl UsageStore {
    /// 建实例：库可用则从 `key_usage` 载入（失败只告警、按空账本继续，与凭据存储同风格），
    /// 库不可用（`None`）则纯内存记账。
    pub(crate) fn new(db: Arc<Mutex<Option<Connection>>>) -> Self {
        let (usage, has_db) = {
            let guard = lock_or_recover(&db);
            match guard.as_ref() {
                Some(conn) => {
                    let usage = match load_usage(conn) {
                        Ok(map) => map,
                        Err(e) => {
                            tracing::warn!("usage db load failed: {e}; using empty usage store");
                            HashMap::new()
                        }
                    };
                    (usage, true)
                }
                None => (HashMap::new(), false),
            }
        };
        Self {
            usage: RwLock::new(usage),
            db,
            has_db,
            flush_gate: Mutex::new(()),
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
        let mut usage = write_or_recover(&self.usage);
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
    ///
    /// **内存模式（没有 `keys_file`）恒为 false**（SL-P3-13）：那种部署没有库可写，`flush_once`
    /// 会在"没有库"处提前返回、永不推进 `flushed`/`ever_flushed` 标记，于是这里会**永远**报
    /// "有待落库" —— 1s 的 flush 任务每轮都白做一次 `spawn_blocking` 往返，并把每个 key 的用量
    /// 快照克隆进 batch 后原样丢掉。
    ///
    /// 判据放在这里而不是让 `flush_once` 假装落过库：**"有没有库"是这个模块的静态事实**，让
    /// `flushed` 标记去说谎会污染"库里已经是这个值"的语义（那是崩溃安全的关键不变量）。
    pub(crate) fn has_pending(&self) -> bool {
        // **不碰 `db` 互斥锁**（复扫 C2-2）：本函数跑在 **async worker** 上（`usage_flush::spawn`
        // 的任务），而 `db` 会被 `flush_once` 的**整个事务**持有（busy 重试最长 5s）——
        // 同步等它会把 runtime 线程按住，与那个模块"任务本身不做阻塞 IO"的说明矛盾。
        // "有没有库"是构造时定死的静态事实（见 `has_db`），所以这里根本不需要那把锁。
        //
        // `usage` 那把锁只护内存读写、不跨 IO，保留。
        if !self.has_db {
            return false;
        }
        read_or_recover(&self.usage)
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
    /// 返回本轮**已提交**的 key 数（任何一行失败 ⇒ 整批回滚 ⇒ 返回 0）；`force = true` 时
    /// 忽略"是否变化"（用于关闭前落库）。
    pub(crate) fn flush_once(&self, force: bool) -> usize {
        // 串行化闸门（复扫 C1）：关闭路径的强制 flush 与周期任务可以**并发**（周期任务跑在
        // `spawn_blocking` 上，而 `run_bounded` 的超时**不取消**它）。闸门必须落在**取快照
        // 之前**——否则"先取快照、后拿到 `db` 锁"的那次会用旧的绝对累计值覆盖新值，而进程
        // 随即退出，这段差值永久丢失。谁先开始谁先结束，于是后到的一定看到最新快照。
        let _serialized = lock_or_recover(&self.flush_gate);
        // 内存模式没有库可写：**先**判断再建批，别把 O(keys) 的快照克隆出来又丢掉（SL-P3-13）。
        // 周期任务现在会被 `has_pending` 挡住，但关闭路径仍会调到这里。
        if !self.has_db {
            return 0;
        }
        // 准备阶段只在内存锁内做，不碰 SQLite。
        let batch: Vec<(String, UsageSnapshot)> = {
            let usage = read_or_recover(&self.usage);
            usage
                .iter()
                .filter(|(_, r)| force || !r.ever_flushed || r.current != r.flushed)
                .map(|(k, r)| (k.clone(), r.current.clone()))
                .collect()
        };
        if batch.is_empty() {
            return 0;
        }

        let mut conn = lock_or_recover(&self.db);
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
                    // 这条语句失败 ⇒ 事务不会提交 ⇒ **整个批都会被回滚**。
                    // 所以不能把此前已经执行成功的行数报出去：调用方（周期任务与关闭路径）
                    // 会照着这个数打"已落库"的日志（`usage flushed before shutdown keys=N`），
                    // 于是"静默丢用量 + 日志报成功"。返回 0 = 本轮什么都没落下。
                    // 标记也没动（下面那段只在 commit 成功后执行）→ 下一轮会重试。
                    return 0;
                }
            }
        }
        if let Err(e) = tx.commit() {
            tracing::warn!("usage flush: commit failed: {e}");
            return 0;
        }
        // 提交成功后才更新"已落库"标记。
        let mut usage = write_or_recover(&self.usage);
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
        if let Some(conn) = lock_or_recover(&self.db).as_mut() {
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
        let usage = read_or_recover(&self.usage);
        let rec = usage.get(key_id)?;
        Some(cell_to_info(key_id, &rec.current))
    }

    /// 全部 key 的用量快照（按 key_id 排序）。
    pub(crate) fn snapshot(&self) -> Vec<KeyUsageInfo> {
        let usage = read_or_recover(&self.usage);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 规格：**事务回滚了就一行都不能报成"已写入"**（评估报告 §5 H1，既有记录 P1-5）。
    ///
    /// 造一个必然失败的批：给 `key_usage` 加一个触发器，让它在**本次事务内已有 2 行时** ABORT。
    /// 于是无论批的遍历顺序如何，恒有 2 行成功、第 3 行失败 ⇒ 事务整体回滚。
    /// 修好之前 `flush_once` 会返回 2（那两行已经不在库里了），而调用方会照着它打
    /// "usage flushed before shutdown keys=2"——静默丢用量、日志却报成功。
    #[test]
    fn flush_reports_nothing_when_the_transaction_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let store = crate::storage::KeyStore::new(Some(path.clone()));
        let delta = UsageDelta {
            prompt_tokens: 1,
            completion_tokens: 2,
            estimated: false,
        };
        let ids: Vec<String> = ["a", "b", "c"]
            .iter()
            .map(|n| {
                let c = store.create((*n).into()).unwrap();
                store.accumulate_usage(&c.record.id, n, &delta);
                c.record.id
            })
            .collect();
        assert_eq!(store.usage_snapshot().len(), 3, "前提：批里有 3 个 key");

        // 让第 3 行必然失败（事务内计数达到 2 就 ABORT）
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER dbg_fail_third BEFORE INSERT ON key_usage
             WHEN (SELECT COUNT(*) FROM key_usage) >= 2
             BEGIN SELECT RAISE(ABORT, 'debug: forced row failure'); END;",
        )
        .unwrap();
        drop(conn);

        assert_eq!(
            store.flush_usage_once(false),
            0,
            "事务回滚了，就不能把已回滚的行数报成已写入（修好前这里是 2）"
        );
        assert!(
            store.usage_has_pending(),
            "失败后标记不能推进，下一轮必须还会重试"
        );

        let conn = Connection::open(&path).unwrap();
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM key_usage", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0, "整事务回滚，库里不该有任何一行");
        for id in &ids {
            assert!(
                store.usage_of(id).is_some(),
                "内存账本不受落库失败影响（/admin/usage 仍要能读到）"
            );
        }
    }

    /// 规格（SL-P3-13）：**内存模式（没有 `keys_file`）永远不该报告"有待落库数据"。**
    ///
    /// 那种部署没有库可写：`flush_once` 在"没有库"处提前返回，`flushed`/`ever_flushed` 标记
    /// 永不推进，于是 `has_pending()` 恒为 true —— 固定 1s 的 flush 任务便**永远**每轮都做一次
    /// `spawn_blocking` 往返，并把每个 key 的用量快照克隆进 batch（`O(keys)` 分配）之后原样丢掉。
    #[test]
    fn a_memory_only_store_never_reports_pending_usage() {
        let store = crate::storage::KeyStore::new(None);
        let key = store.create("p3-13".into()).unwrap();
        store.accumulate_usage(
            &key.record.id,
            "p3-13",
            &UsageDelta {
                prompt_tokens: 3,
                completion_tokens: 4,
                estimated: false,
            },
        );

        assert_eq!(
            store.usage_of(&key.record.id).unwrap().requests,
            1,
            "前提：内存计数照常累加（/admin/usage 要读得到）"
        );
        assert!(
            !store.usage_has_pending(),
            "内存模式没有库可写，不该让 1s 的 flush 任务永远认为有待落库数据（修好前这里是 true）"
        );
        assert_eq!(
            store.flush_usage_once(false),
            0,
            "内存模式 flush 仍是空操作"
        );
    }

    /// 规格（2026-09-25 复扫 C2-2）：`has_pending()` **不能**去抢那把同步 `db` 锁。
    ///
    /// 它跑在 **async worker** 上（`usage_flush::spawn` 的任务），而 `db` 会被 `flush_once` 的
    /// **整个事务**持有（busy 重试最长 5s）⇒ 同步等它就是把 runtime 线程按住，与
    /// `usage_flush` 说的"任务本身不做阻塞 IO"矛盾。
    ///
    /// 控制点：测试自己握住 `db` 锁（扮演"一次 flush 正在提交"），再在**另一个线程**上问一次
    /// `has_pending`。修复后它立刻回答（判据是构造时定死的 `has_db`）；老实现会在那里等锁，
    /// 于是只能等超时 ⇒ 红。放在另一个线程并带超时，是为了让它**失败**而不是把测试挂死。
    #[test]
    fn has_pending_never_waits_for_the_db_lock() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::storage::KeyStore::new(Some(dir.path().join("keys.db")));
        let key = store.create("c2-2".into()).unwrap();
        store.accumulate_usage(
            &key.record.id,
            "c2-2",
            &UsageDelta {
                prompt_tokens: 1,
                completion_tokens: 0,
                estimated: false,
            },
        );

        let guard = lock_or_recover(&store.inner.db);
        let probe = store.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(probe.usage_has_pending());
        });
        match rx.recv_timeout(std::time::Duration::from_secs(2)) {
            Ok(pending) => assert!(pending, "有库 + 有未落库数据 ⇒ 必须报 pending"),
            Err(_) => panic!("has_pending 卡在 db 锁上 —— 它会阻塞 async worker（复扫 C2-2）"),
        }
        drop(guard);
    }

    /// 对照：**有库时**累加后必须报告待落库 —— 防止上面那条被修成"永远 false"。
    #[test]
    fn a_file_backed_store_still_reports_pending_usage() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::storage::KeyStore::new(Some(dir.path().join("keys.db")));
        let key = store.create("p3-13-control".into()).unwrap();
        store.accumulate_usage(
            &key.record.id,
            "p3-13-control",
            &UsageDelta {
                prompt_tokens: 1,
                completion_tokens: 1,
                estimated: false,
            },
        );

        assert!(store.usage_has_pending(), "有库时累加后必须报告待落库");
        assert_eq!(store.flush_usage_once(false), 1);
        assert!(!store.usage_has_pending(), "落库后不该再 pending");
    }

    /// 规格（2026-09-25 复扫 C1）：周期 flush 与关闭 flush 必须**串起来**。
    ///
    /// 为什么：两者可以并发（周期任务跑在 `spawn_blocking` 上，而关闭路径 `run_bounded` 的
    /// 超时**不取消**它），而 `flush_once` 原先在**拿 `db` 锁之前**就取了快照 ⇒ "先取快照、
    /// 后拿到 `db` 锁"的那次会用**旧值覆盖新值**，紧接着进程退出，这段差值永久丢失——与
    /// `usage_flush` 承诺的"正常关闭不丢已结算的用量"冲突。
    ///
    /// 这条测试用一个**确定的**控制点钉住它：测试自己握住串行化锁来扮演"一次 flush 正在
    /// 进行"，再从另一个线程发起第二次 flush。修复后第二次会停在**取快照之前**；期间内存
    /// 继续增长，所以放开锁之后它必须把增量带上。修复前（或把那次加锁删掉时）第二次会立刻
    /// 取一份旧快照落库，库就落在内存后面 —— 红是确定的，不依赖调度运气。
    ///
    /// 注：第一版试图靠"两次 flush 抢 `db` 锁"来复现，结果两次都 park 之后是 FIFO 唤醒、
    /// 主线程抢锁也被移交给了等待者，**缺陷根本触发不了**。所以这里改成显式控制串行化锁。
    #[test]
    fn a_flush_waits_for_the_previous_one_instead_of_snapshotting_early() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let store = crate::storage::KeyStore::new(Some(path.clone()));
        let key = store.create("c1".into()).unwrap();
        let id = key.record.id.clone();

        let delta = |tokens: u64| UsageDelta {
            prompt_tokens: tokens,
            completion_tokens: 0,
            estimated: false,
        };
        store.accumulate_usage(&id, "c1", &delta(1));

        // 扮演"上一次 flush 正在进行"：直接握住串行化锁。
        let guard = crate::sync::lock_or_recover(&store.inner.usage.flush_gate);

        // 第二次 flush（= 关闭路径）必须**等**这把锁，而不是先取快照、再去等 `db` 锁。
        let flushing = store.clone();
        let t = std::thread::spawn(move || flushing.flush_usage_once(true));

        // 排队期间内存继续涨；只有"快照发生在取锁之后"才可能带上它。
        std::thread::sleep(std::time::Duration::from_millis(30));
        store.accumulate_usage(&id, "c1", &delta(1000));

        drop(guard);
        t.join().unwrap();

        let in_memory = store.usage_of(&id).unwrap().prompt_tokens;
        assert_eq!(in_memory, 1001, "前提：内存账本是 1 + 1000");
        let conn = Connection::open(&path).unwrap();
        let db: i64 = conn
            .query_row(
                "SELECT prompt_tokens FROM key_usage WHERE key_id = ?1",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            db as u64, in_memory,
            "第二次 flush 取了旧快照 ⇒ 库里落后于内存（复扫 C1：绝对累计值被旧值覆盖）"
        );
    }
}
