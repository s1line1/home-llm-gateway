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
//!    槽位是**有归属**的：收尾只删自己那一个（`Arc::ptr_eq`），等锁者拿到锁之后还要
//!    重新确认自己拿的仍是当前槽——缺了任何一处，迟到者就能与新来者同时跑 argon2（评估 §5 H3）。
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
//!   `credential_version_bump_invalidates_cache`（`storage::verified_tests`）守住这条。

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use super::KeyRecord;
use crate::sync::lock_or_recover;

/// 缓存中的一条已验证身份：**整条记录 + 校验时间**。
///
/// 存整条记录（而不是只存 id/name）是为了让热路径拿到 enabled/cred_version 时
/// 与缓存快照来自**同一份数据**，避免"读表得到的版本"和"缓存里的版本"分属两次读取。
#[derive(Clone)]
struct Verified {
    record: KeyRecord,
    verified_at: Instant,
}

/// 未命中时用于串行化同一 token 的并发校验。
type FlightSlot = Arc<Mutex<()>>;

/// 已验证身份缓存：命中即跳过 argon2 校验，未命中时按 token 串行化（单飞）。
///
/// 只缓存**校验结论**，凭据版本（`cred_version`）不一致或记录消失时立即失效，所以吊销
/// 依然即时生效、不依赖 TTL。峰值内存由 argon2 的并发校验决定（每次 19 MiB），
/// 见 `TODO.md` 的《argon2 使用方式重构》。
///
/// **协议住在这里**（评估 §7 步骤 4 / C2）：快路径 → 单飞 → 双检 → 校验 → 写缓存
/// 的五步次序只在 [`Self::verify_or_cached`] 里写了一遍；调用方（`KeyStore`）只提供
/// "按 lookup 取记录"与"真跑一次 argon2"两个动作。容量与有效期也是本模块的状态，
/// 不再由调用点每次传进来。
pub(crate) struct VerifiedCache {
    entries: Mutex<HashMap<String, Verified>>,
    inflight: Mutex<HashMap<String, FlightSlot>>,
    /// 容量上限（0 = 关闭缓存，退回"每请求完整校验"）。
    max_entries: usize,
    /// 已验证条目的有效期。
    ttl: Duration,
    /// 命中缓存、**没有跑 argon2** 的次数（指标 `hlmg_key_verify_hits_total`）。
    hits: std::sync::atomic::AtomicU64,
    /// **真跑过 argon2 的次数**（指标 `hlmg_key_verify_misses_total`）。
    ///
    /// 为什么它不叫"缓存未命中"：自增点在"将要跑 argon2"那一处（[`Self::note_argon2`]），
    /// 而不是在 `put`。差别只在一种配置上，但那正是最需要这个计数器的配置——
    /// `verified_cache_max: 0` 时走"每请求完整校验"，**根本不经过 `put`**，若把自增点放在
    /// `put`，这个计数器在持续烧 argon2 的场景下会恒为 0（指标 HELP 一直写的是"ran argon2"）。
    ///
    /// 注意错 token 不在其中：它的 `sha256` 不同 ⇒ `runtime` 查不到 ⇒ 按设计**不跑 argon2**。
    argon2_runs: std::sync::atomic::AtomicU64,
}

/// 单飞槽的**归属守卫**：只删自己那一个槽（评估 §5 H3）。
///
/// 交错是真实存在的：A 跑完 argon2 放掉槽位的锁、还没删表项的那一小段里，B 可以从表里
/// 拿到**同一个** `Arc` 并开始用它；A 若"按 key 名无条件删除"，删掉的就是 B 正在用的活槽
/// —— 接着 C 到达会新建一个槽，于是 B 与 C 并发跑 argon2，峰值内存从
/// `同时首用的不同 token 数 × 19MiB` 变成它 +1，违反模块头第 2 条声明的不变量。
///
/// 守卫（而不是在正常路径末尾手写一次删除）还兜住另外两件事：早退分支（记录消失/被禁用）
/// 与**校验里 panic** —— 两种情况下槽位都照样归还，不会把表项留给下一个请求。
struct FlightGuard<'a> {
    cache: &'a VerifiedCache,
    lookup: &'a str,
    slot: &'a FlightSlot,
}

impl Drop for FlightGuard<'_> {
    fn drop(&mut self) {
        self.cache.remove_if_current(self.lookup, self.slot);
    }
}

impl VerifiedCache {
    /// 建一个缓存：`max_entries = 0` 表示**关闭缓存**（每次请求都完整校验）。
    ///
    /// 容量与有效期由缓存自己持有（而不是每个调用点各传一次）：它们是这个模块的
    /// **策略**，把 `usize` + `Duration` 一路传到 `get`/`put` 只是把 `KeyStore` 的字段
    /// 借过来用，还给了"传错顺序"的机会。
    pub(crate) fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            inflight: Mutex::new(HashMap::new()),
            max_entries,
            ttl,
            hits: std::sync::atomic::AtomicU64::new(0),
            argon2_runs: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// 认证的**三段协议**（快路径 → 单飞 → 双检 → 校验 → 写缓存），全仓库只此一处。
    ///
    /// - `load`：按 lookup 取**当前记录**（`KeyStore` 从 `runtime` 读）；`None` = 这个
    ///   lookup 根本不存在（未知 token / 已吊销）→ 直接拒绝。
    /// - `probe`：真跑一次 argon2，回答"这个 token 与这条记录的哈希匹配吗"。
    ///
    /// 两个闭包都交出**自己拥有的数据**，这不是随手的选择：协议每一步之间都要放开
    /// `runtime` 的读锁，而"读锁跨过一次 10–30ms 的 argon2"正是评估里的 N1（建/吊销
    /// 这种写操作得排在冷校验后面）。把记录的所有权收进闭包，调用方就**没有**让守卫
    /// 活过闭关的机会——这条约束由签名强制，而不是靠记得 `drop`。
    ///
    /// 缓存语义：`probe` 通过才写缓存（`max_entries = 0` 时不写、每次请求都会 `probe`）；
    /// 不通过**绝不**写——否则一个错误 token 会被记成"通过"。
    pub(crate) fn verify_or_cached<L, P>(
        &self,
        lookup: &str,
        load: L,
        probe: P,
    ) -> Option<KeyRecord>
    where
        L: Fn() -> Option<KeyRecord>,
        P: FnOnce(&KeyRecord) -> bool,
    {
        // ① 缓存关闭：每次请求都完整校验（与改造前语义一致），刻意不做单飞——
        //    这一档的目的就是"每次都真校验"。
        if self.max_entries == 0 {
            let rec = load()?;
            return if rec.enabled && self.probe_once(probe, &rec) {
                Some(rec)
            } else {
                None
            };
        }

        // ② 快路径：记录在、启用中，且缓存里有同版本未过期的一条 → 直接放行（不跑 argon2，
        //    也不碰单飞表）。
        let fresh = load()?;
        if !fresh.enabled {
            return None;
        }
        if self.is_cached(lookup, fresh.cred_version) {
            // 返回**刚刚读到的那条**（而不是缓存里的副本）：两者按 `cred_version` 等价
            // （版本一致就意味着同一份凭据），但它是 `runtime` 的权威快照，还省一次克隆。
            return Some(fresh);
        }

        // ③ 未命中：单飞 + 双检 + 校验 + 写缓存。
        let mut probe = Some(probe);
        loop {
            let slot = self.flight(lookup);
            let _guard = lock_or_recover(&slot);
            // 拿到锁之后**先确认这个槽还是当前那一个**：等锁期间前一个持有者可能已经
            // 收尾并删掉表项（甚至已有别人新建了槽）。这时必须重取当前槽再进临界区，
            // 否则"我"与"新槽的持有者"会同时跑 argon2——这正是 H3 的另一半。
            if !self.is_current(lookup, &slot) {
                continue;
            }
            // 从这里起的任何出口（早退、panic）都由守卫归还槽位。声明在 `_guard` 之后
            // ⇒ 先于解锁执行：表项先消失、锁后放开，等锁者醒来时会看到"不是当前槽"
            // 并重取，而不是继续用这个已经被删掉的槽。
            let _cleanup = FlightGuard {
                cache: self,
                lookup,
                slot: &slot,
            };
            // 双检：等锁期间可能已被同 token 的并发请求填好了
            let rec = load()?;
            if !rec.enabled {
                return None;
            }
            if self.is_cached(lookup, rec.cred_version) {
                return Some(rec);
            }
            let probe = probe.take().expect("probe 在退出循环前只会被取走一次");
            if !self.probe_once(probe, &rec) {
                return None;
            }
            self.put(lookup, rec.clone());
            return Some(rec);
        }
    }

    /// 跑一次 `probe` 并计入"真跑了 argon2"（口径见 [`Self::argon2_runs`]）。
    ///
    /// `probe` 在生产里就是 argon2 校验，所以"调用 probe"与"跑了 argon2"是同一件事；
    /// 计数收在这里，调用方不必（也无法）自己记。
    fn probe_once<P: FnOnce(&KeyRecord) -> bool>(&self, probe: P, rec: &KeyRecord) -> bool {
        self.note_argon2();
        probe(rec)
    }

    /// 缓存里是否有一条**同版本、启用中、未过期**的条目；命中即累加 `hits`。
    ///
    /// 只回答"能不能放行"，不返回记录本身——记录由调用方交给 [`Self::verify_or_cached`]
    /// 的 `load` 提供，所以这里不需要克隆，调用方也拿不到过期的副本。
    fn is_cached(&self, lookup: &str, cred_version: u64) -> bool {
        let entries = lock_or_recover(&self.entries);
        let Some(hit) = entries.get(lookup) else {
            return false;
        };
        if hit.record.enabled
            && hit.record.cred_version == cred_version
            && hit.verified_at.elapsed() < self.ttl
        {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return true;
        }
        false
    }

    /// 记一次"真的跑了 argon2"（只由 [`Self::probe_once`] 调用）。
    fn note_argon2(&self) {
        self.argon2_runs
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// 校验成功后写入（容量满时淘汰最旧一条）。只在缓存开启时被调用。
    fn put(&self, lookup: &str, record: KeyRecord) {
        let mut entries = lock_or_recover(&self.entries);
        if entries.len() >= self.max_entries && !entries.contains_key(lookup) {
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
        lock_or_recover(&self.entries).retain(|_, v| v.record.id != key_id);
    }

    /// 取该 token 的单飞槽位：同一 token 的并发校验会串行执行。
    fn flight(&self, lookup: &str) -> FlightSlot {
        lock_or_recover(&self.inflight)
            .entry(lookup.to_string())
            .or_default()
            .clone()
    }

    /// 表项是否**仍是**这一个槽（[`Self::verify_or_cached`] 等锁之后要重新确认）。
    fn is_current(&self, lookup: &str, slot: &FlightSlot) -> bool {
        lock_or_recover(&self.inflight)
            .get(lookup)
            .is_some_and(|cur| Arc::ptr_eq(cur, slot))
    }

    /// 只在表项**仍是** `slot` 时删除：迟到的释放绝不动别人的活槽（评估 §5 H3）。
    fn remove_if_current(&self, lookup: &str, slot: &FlightSlot) {
        let mut inflight = lock_or_recover(&self.inflight);
        if inflight
            .get(lookup)
            .is_some_and(|cur| Arc::ptr_eq(cur, slot))
        {
            inflight.remove(lookup);
        }
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
        lock_or_recover(&self.entries).len()
    }

    /// 当前在用的单飞槽数（测试用）：正常收尾后必须归零，否则 `inflight` 随调用无界增长。
    #[cfg(test)]
    pub(crate) fn inflight_len(&self) -> usize {
        lock_or_recover(&self.inflight).len()
    }

    /// 当前缓存里的键（测试用）：用来钉"缓存只键于 `sha256(token)`、从不存明文"。
    #[cfg(test)]
    pub(crate) fn keys(&self) -> Vec<String> {
        lock_or_recover(&self.entries).keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyRecord, VerifiedCache};
    use std::{
        panic::{catch_unwind, AssertUnwindSafe},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Barrier,
        },
        time::Duration,
    };

    fn cache() -> VerifiedCache {
        VerifiedCache::new(16, Duration::from_secs(60))
    }

    fn record(cred_version: u64) -> KeyRecord {
        KeyRecord {
            id: "id-1".into(),
            key_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
            lookup: "lookup-1".into(),
            name: "n".into(),
            created_at: 0,
            enabled: true,
            cred_version,
        }
    }

    /// 规格（评估 §5 H3）：**释放只删自己那一个槽**。
    ///
    /// 交错是真实存在的：A 跑完 argon2 放掉槽位的锁、还没把表项删掉的那一小段里，
    /// B 可以从表里拿到**同一个** `Arc` 并开始用它；A 若"按 key 名无条件删除"，
    /// 删掉的就是 B 正在用的活槽 —— 接着 C 到达会新建一个槽，于是 B 与 C 并发跑
    /// argon2，峰值内存从 `同时首用的不同 token 数 × 19MiB` 变成它 **+1**，
    /// 违反模块自己声明的不变量（`verified.rs` 模块头第 2 条）。
    #[test]
    fn a_late_release_never_removes_a_slot_it_does_not_own() {
        let cache = cache();
        // A 拿到槽并跑完校验（此时表项 = a）
        let a = cache.flight("k");
        // A 正常收尾：删掉自己的表项，槽位表里没有 k 了
        cache.remove_if_current("k", &a);
        assert_eq!(cache.inflight_len(), 0, "自己的槽应当删掉");
        // B 随后拿到一个新槽（表项 = b），正在用它跑 argon2
        let b = cache.flight("k");
        assert_eq!(cache.inflight_len(), 1, "B 的槽应当在表里");
        // A 的**迟到释放**：不得删掉别人的活槽
        cache.remove_if_current("k", &a);
        assert_eq!(
            cache.inflight_len(),
            1,
            "迟到释放把别人的活槽删掉了：C 会因此与 B 并发跑 argon2"
        );
        assert!(cache.is_current("k", &b), "b 必须仍是当前槽");
        // 收尾（B 自己释放）：表必须回到空
        cache.remove_if_current("k", &b);
        assert_eq!(cache.inflight_len(), 0);
    }

    /// 单飞的**核心契约**（模块头第 2 条）：同一个 lookup 的并发校验绝不重叠。
    ///
    /// 这里用最难的形状——`probe` **永不通过**（所以什么都不写缓存，"靠缓存命中
    /// 短路掉后来者"这条退路不存在），只能靠串行化本身不重叠。
    #[test]
    fn concurrent_checks_of_one_lookup_never_overlap() {
        let cache = cache();
        let inside = AtomicUsize::new(0);
        let max_inside = AtomicUsize::new(0);
        let began = Barrier::new(8);
        let done = AtomicUsize::new(0);

        let results: Vec<Option<KeyRecord>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        began.wait();
                        cache.verify_or_cached(
                            "k",
                            || Some(record(1)),
                            |_| {
                                let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                                max_inside.fetch_max(now, Ordering::SeqCst);
                                std::thread::sleep(Duration::from_millis(2));
                                inside.fetch_sub(1, Ordering::SeqCst);
                                done.fetch_add(1, Ordering::SeqCst);
                                false
                            },
                        )
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        assert!(
            results.iter().all(Option::is_none),
            "probe 不通过时不得放行"
        );
        assert_eq!(done.load(Ordering::SeqCst), 8, "每个调用都要真跑一次校验");
        assert_eq!(
            max_inside.load(Ordering::SeqCst),
            1,
            "同一个 lookup 的校验重叠了：argon2 峰值内存会成倍上涨"
        );
        assert_eq!(cache.inflight_len(), 0, "收尾后槽位表必须归零");
    }

    /// 通过校验 → 第二次直接命中缓存（不再 `probe`），且两次都不留槽位。
    #[test]
    fn a_verified_lookup_is_served_from_the_cache_and_leaves_no_slot() {
        let cache = cache();
        let probes = AtomicUsize::new(0);
        let probe = |_: &KeyRecord| {
            probes.fetch_add(1, Ordering::SeqCst);
            true
        };

        let first = cache.verify_or_cached("k", || Some(record(1)), probe);
        assert!(first.is_some());
        assert_eq!(cache.inflight_len(), 0, "正常路径必须归还槽位");
        assert_eq!(cache.len(), 1, "通过校验后应写入缓存");

        let second = cache.verify_or_cached("k", || Some(record(1)), probe);
        assert!(second.is_some());
        assert_eq!(probes.load(Ordering::SeqCst), 1, "第二次必须命中缓存");
        assert_eq!(cache.counters(), (1, 1), "(命中, 真跑 argon2)");
    }

    /// 早退分支（lookup 查不到）也必须归还槽位：否则该 token 的槽位永久卡住。
    #[test]
    fn a_rejected_lookup_leaves_no_slot_behind() {
        let cache = cache();
        assert!(cache
            .verify_or_cached("k", || Some(record(1)), |_| false)
            .is_none());
        assert_eq!(cache.inflight_len(), 0, "校验不通过也必须归还槽位");

        // 记录消失（吊销）这条早退路径同样不能留槽位
        assert!(cache.verify_or_cached("k", || None, |_| true).is_none());
        assert_eq!(cache.inflight_len(), 0, "记录消失也必须归还槽位");
    }

    /// H3 的**另一半**：等锁者醒来时，槽可能已经被前一任持有者删掉（甚至被别人换了新的）。
    /// 这时必须重取当前槽再进临界区——否则它与新槽的持有者会同时跑 argon2。
    ///
    /// 用测试线程扮演"前一任"来制造确定性的交错：
    /// 1. 测试自己持有第 1 个槽的锁（= 正在跑 argon2 的前一任）；
    /// 2. B 到达同一个槽，被锁挡在门外（`Arc::strong_count` 涨到 3 就说明它已经拿到了槽）；
    /// 3. 前一任收尾：**先删表项、再放锁**（与协议里的次序一致）；
    /// 4. B 醒来时表项已经没了；等它真的开始 probe，再放 C 进来新建一个槽。
    ///
    /// 少了"醒来后重新确认槽"这一步时，B 与 C 会重叠（`max_inside == 2`）。
    #[test]
    fn a_stale_slot_holder_never_probes_beside_the_new_owner() {
        use std::sync::Arc;

        let cache = cache();
        let inside = AtomicUsize::new(0);
        let max_inside = AtomicUsize::new(0);
        let entered = AtomicUsize::new(0);

        // ① 测试 = 前一任：持有第 1 个槽（表项 = stale）
        let stale = cache.flight("k");
        let held = stale.lock().unwrap();

        let probe = |_: &KeyRecord| {
            let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
            max_inside.fetch_max(now, Ordering::SeqCst);
            entered.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(20));
            inside.fetch_sub(1, Ordering::SeqCst);
            false
        };

        std::thread::scope(|scope| {
            // ② B：走到同一个槽上排队（此时还没进 probe）
            let b = scope.spawn(|| cache.verify_or_cached("k", || Some(record(1)), probe));
            while Arc::strong_count(&stale) < 3 {
                std::thread::yield_now();
            }

            // ③ 前一任收尾：先删表项，再放锁
            cache.remove_if_current("k", &stale);
            drop(held);

            // ④ 等 B 真的进了 probe，再放 C 进来（C 会新建一个槽）
            while entered.load(Ordering::SeqCst) == 0 {
                std::thread::yield_now();
            }
            let c = scope.spawn(|| cache.verify_or_cached("k", || Some(record(1)), probe));
            assert!(b.join().unwrap().is_none());
            assert!(c.join().unwrap().is_none());
        });

        assert_eq!(
            max_inside.load(Ordering::SeqCst),
            1,
            "过期的槽持有者与新槽的持有者同时跑了 argon2"
        );
        assert_eq!(cache.inflight_len(), 0, "收尾后槽位表必须归零");
    }

    /// `probe` 里 panic（H4/H7 的触发链）也要归还槽位：守卫在 unwind 时照样跑。
    ///
    /// 这里只钉"槽位表不泄漏"；槽位互斥量本身被毒化后怎么办是评估 §7 步骤 6（H4）的范围。
    #[test]
    fn a_panicking_probe_still_returns_the_slot() {
        let cache = cache();
        let panicked = catch_unwind(AssertUnwindSafe(|| {
            cache.verify_or_cached("k", || Some(record(1)), |_| panic!("argon2 之前就炸了"));
        }));
        assert!(panicked.is_err(), "probe 的 panic 必须照常传播");
        assert_eq!(cache.inflight_len(), 0, "unwind 也要归还槽位");

        // 而且这把 key 不能就此永久失败：下一次校验照常完成
        // （守卫已把表项清掉，所以这里拿到的是新槽；"中毒的锁也能用"由下一条用例覆盖）
        assert!(
            cache
                .verify_or_cached("k", || Some(record(1)), |_| true)
                .is_some(),
            "一次 panic 之后，同一个 lookup 必须还能校验"
        );
    }

    /// H4（评估 §7 步骤 6）：`entries` / `inflight` 中毒后也必须能继续服务。
    ///
    /// 锁里只是缓存映射与槽位表，守卫内 panic 不会让它们变成非法状态；而 `.unwrap()`
    /// 会让一次 panic 变成"之后每次认证都 500"（`entries`）或"这把 key 永久卡死"
    /// （`inflight`）。
    #[test]
    fn a_poisoned_cache_lock_does_not_take_authentication_down() {
        let cache = cache();
        let poison = |f: &dyn Fn()| {
            assert!(
                catch_unwind(AssertUnwindSafe(f)).is_err(),
                "前提：panic 发生了"
            );
        };
        poison(&|| {
            let _g = cache.entries.lock().unwrap();
            panic!("poison entries");
        });
        poison(&|| {
            let _g = cache.inflight.lock().unwrap();
            panic!("poison inflight");
        });
        assert!(
            cache.entries.is_poisoned() && cache.inflight.is_poisoned(),
            "前提：两把锁都中毒了"
        );

        assert!(
            cache
                .verify_or_cached("k", || Some(record(1)), |_| true)
                .is_some(),
            "锁中毒后仍应能校验并写缓存"
        );
        assert_eq!(cache.len(), 1, "写缓存这条路径也要走通");
        assert_eq!(cache.inflight_len(), 0, "槽位照常归还");
        assert_eq!(cache.counters(), (0, 1));
    }
}
