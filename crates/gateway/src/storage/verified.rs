//! 已验证身份的缓存 + 单飞：把 argon2 从"每请求一次"降到"每(凭据版本)一次"。
//!
//! ## 为什么需要它
//!
//! `argon2` 是**内存硬**的：`Argon2::default()` 的 m_cost = 19456 KiB = **19 MiB**，
//! 每次校验都要**同时**占用一块 19MiB 工作内存。而网关原本对每个请求都完整校验一次
//! （`verify_argon2`），于是内存峰值 ≈ `并发请求数 × 19MiB`：
//!
//! - 实测（release，8 并发同 key 请求）：RSS 从 8.7MB 涨到 160.8MB，其中 vmmap 可见
//!   **正好 8 块 `MALLOC_LARGE` × 19.0MB**；
//! - 换用**无效** key（sha256 未命中 → 不跑 argon2）：同一压力下 **零增长**；
//! - 云端 2 核/1.6G 机器上 32 并发 → 654MB，正是 `32 × 20MB`。
//!
//! ## 这个模块做什么
//!
//! 1. **缓存**：`sha256(token) → (key_id, key_name, cred_version)`。只键于 sha256，
//!    **不存明文 token**；容量有界（默认 1650，见 `super::DEFAULT_VERIFIED_MAX`），满时淘汰最旧的一项。
//! 2. **单飞（single-flight）**：同一个 token 的并发请求**串行化**，只有第一个跑
//!    argon2，其余等它的结果 —— 这才是把峰值从 `并发数 × 19MiB` 压到
//!    `同时首用的不同 token 数 × 19MiB` 的关键；只缓存不单飞的话，一波并发仍各算一次。
//! 3. **凭据版本校验**：每个请求仍要 O(1) 地核对当前记录 `enabled` 与 `cred_version`，
//!    因此**吊销/禁用是即时生效的**（不需要等 TTL，也不靠遍历清缓存）。
//!
//! ## 安全性
//!
//! - 校验通过的判据 = 缓存版本 == 当前记录版本 且 `enabled`；删除 key 会让记录从
//!   `runtime` 表消失 → 直接 miss → 401，与版本号无关。
//! - 唯一的语义变化：**同一凭据在被缓存的这段时间内不再重算 argon2**。若将来新增
//!   "改 key 但不 bump 版本"的写路径，缓存会静默失效——所以 `KeyStore` 里每次
//!   凭据变更都必须走 [`crate::storage::KeyStore`] 的版本自增（见 `bump`）。测试
//!   `credential_change_invalidates_for_immediately` 守住这条。

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use super::KeyRecord;

/// 缓存中的一条已验证身份：**整条记录 + 校验时间**。
///
/// 存整条记录（而不是只存 id/name）是为了让热路径拿到 enabled/cred_version 时
/// 与缓存快照来自**同一份数据**，避免"读表得到的版本"和"缓存里的版本"分属两次读取。
#[derive(Clone, Debug)]
struct Verified {
    record: KeyRecord,
    verified_at: Instant,
}

/// 未命中时用于串行化同一 token 的并发校验。
type FlightSlot = std::sync::Arc<Mutex<()>>;

/// 已验证身份缓存：命中即跳过 argon2 校验，未命中时按 token 串行化（单飞）。
///
/// 只缓存**校验结论**，凭据版本（`cred_version`）不一致或记录消失时立即失效，所以吊销
/// 依然即时生效、不依赖 TTL。峰值内存由 argon2 的并发校验决定（每次 19 MiB），
/// 见 `TODO.md` 的《argon2 使用方式重构》。
#[derive(Default)]
pub(crate) struct VerifiedCache {
    entries: Mutex<HashMap<String, Verified>>,
    inflight: Mutex<HashMap<String, FlightSlot>>,
    /// 命中缓存、**没有跑 argon2** 的次数（指标 `hlmg_key_verify_hits_total`）。
    hits: std::sync::atomic::AtomicU64,
    /// **真跑过 argon2 的次数**（指标 `hlmg_key_verify_misses_total`）。
    ///
    /// 为什么它不叫"缓存未命中"：自增点在"将要跑 argon2"那一处（[`Self::note_argon2`]），
    /// 而不是在 [`Self::put`]。差别只在一种配置上，但那正是最需要这个计数器的配置——
    /// `verified_cache_max: 0` 时走"每请求完整校验"，**根本不经过 `put`**，若把自增点放在
    /// `put`，这个计数器在持续烧 argon2 的场景下会恒为 0（指标 HELP 一直写的是"ran argon2"）。
    ///
    /// 注意错 token 不在其中：它的 `sha256` 不同 ⇒ `runtime` 查不到 ⇒ 按设计**不跑 argon2**。
    argon2_runs: std::sync::atomic::AtomicU64,
}

impl VerifiedCache {
    /// 命中（记录启用中、凭据版本一致、未过期）→ 返回该记录；否则 None。
    ///
    /// 版本比对是**吊销即时性**的保证：凭据一变，代数自增，旧条目版本对不上 → 立即重验。
    pub(crate) fn get(&self, lookup: &str, cred_version: u64, ttl: Duration) -> Option<KeyRecord> {
        let entries = self.entries.lock().unwrap();
        let hit = entries.get(lookup)?;
        if hit.record.enabled
            && hit.record.cred_version == cred_version
            && hit.verified_at.elapsed() < ttl
        {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Some(hit.record.clone());
        }
        None
    }

    /// 记一次"真的跑了 argon2"。由 `KeyStore::verify_and_count` 在**调用 argon2 之前**调用。
    pub(crate) fn note_argon2(&self) {
        self.argon2_runs
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// 校验成功后写入（容量满时淘汰最旧一条）。
    pub(crate) fn put(&self, lookup: &str, record: KeyRecord, max_entries: usize) {
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= max_entries && !entries.contains_key(lookup) {
            // 淘汰最旧（verified_at 最小）的一条；缓存很小，线性扫描足够
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, v)| v.verified_at)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            lookup.to_string(),
            Verified {
                record,
                verified_at: Instant::now(),
            },
        );
    }

    /// 按 key id 失效（删除 key 时调用；记录从 runtime 表消失本身已能拦住，这里是双保险）。
    pub(crate) fn invalidate_by_id(&self, key_id: &str) {
        self.entries
            .lock()
            .unwrap()
            .retain(|_, v| v.record.id != key_id);
    }

    /// 取该 token 的单飞槽位：同一 token 的并发校验会串行执行。
    pub(crate) fn flight(&self, lookup: &str) -> FlightSlot {
        self.inflight
            .lock()
            .unwrap()
            .entry(lookup.to_string())
            .or_default()
            .clone()
    }

    /// 单飞槽位用完即清（避免 inflight 表随 key 数量无限增长）。
    pub(crate) fn release_flight(&self, lookup: &str) {
        self.inflight.lock().unwrap().remove(lookup);
    }

    /// `(缓存命中数, 真跑 argon2 的次数)`：供 `/metrics` 观察 argon2 复用情况。
    ///
    /// 对应指标 `hlmg_key_verify_hits_total` 与 `hlmg_key_verify_misses_total`
    /// （后者的名字是历史包袱，口径见 [`Self::note_argon2`]）。
    pub(crate) fn counters(&self) -> (u64, u64) {
        (
            self.hits.load(std::sync::atomic::Ordering::Relaxed),
            self.argon2_runs.load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// 当前缓存条目数（测试用）。
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}
