//! API Key 存储：所有动态 key 持久化在 SQLite（无静态 key 列表）。
//! key 通过 Admin API 创建/吊销，立即生效，无需重启网关。
//!
//! 安全模型（argon2 哈希存储，不再存明文）：
//! - 明文 key 仅创建时返回一次，此后**只存 argon2 哈希**（PHC 格式）。拖库拿到的
//!   是哈希，不是可用的 key；且默认参数（Argon2id m=19456/t=2/p=1，OWASP 建议）
//!   让离线暴破成本极高。
//! - 授权热路径：`sha256(token)` 作为快速索引（lookup）O(1) 定位记录，再对**单条**
//!   记录做 argon2 校验——避免对每条记录都做昂贵的 argon2 验证。明文 key 是 192 位
//!   随机数，lookup 索引哈希本身不构成泄露；argon2 哈希才是防离线暴破的主体。
//! - 架构：内存索引（runtime HashMap，key=lookup）保证 `authorize()` 热路径零 IO；
//!   SQLite 负责持久化，创建/吊销时写穿（write-through）。
//!
//! 注意：argon2 校验每次约耗时 10-30ms，且**同时占用 19MiB 工作内存**（m=19456）。
//! 早期实现对**每个请求**都完整校验一次，于是内存峰值 ≈ `并发请求数 × 19MiB`
//! （实测：8 并发同 key 请求 → RSS 8.7MB→160.8MB；vmmap 里正好 8 块 19.0MB；
//! 换用无效 key（sha256 未命中、不跑 argon2）则零增长）。云端 2 核/1.6G 上 32 并发
//! 到 654MB 即由此而来，并因此被 OOM 杀掉。
//!
//! 现在走 `verified::VerifiedCache`：**缓存 + 单飞 + 凭据版本校验**——
//! argon2 降到"每(凭据版本)一次"，每请求只做 O(1) 的 enabled/版本核对，
//! 且吊销依然即时生效（版本不一致或记录消失即拒）。`verified_cache_max: 0` 可关闭。

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};

use rusqlite::Connection;

use crate::error::GatewayError;

pub mod hash;
mod usage;
pub mod verified;

/// 用量记账/落库的类型由 [`usage`] 定义，路径 `crate::storage::UsageDelta` 保持不变。
pub use usage::{KeyUsageInfo, UsageDelta};

use crate::storage::hash::{generate_id_key, hash_argon2, lookup_of, now_secs, verify_argon2};

#[derive(Clone)]
pub struct KeyStore {
    inner: Arc<KeyStoreInner>,
}

struct KeyStoreInner {
    /// 动态 key，key = lookup（sha256(token) 十六进制），value = 记录。
    runtime: RwLock<HashMap<String, KeyRecord>>,
    /// SQLite 持久化连接（None = 仅内存，如 db 打开失败时降级）。
    ///
    /// **与用量记账共享**（`Arc`）：连接是**资源**（凭据写穿与用量落库都用它），
    /// 而状态刻意不共享——`runtime` 归凭据、`usage` 归 [`usage::UsageStore`]。
    db: Arc<Mutex<Option<Connection>>>,
    /// per-key 用量：记账 + 批量落库（独立模块，见 [`usage`]）。
    usage: usage::UsageStore,
    /// 已验证身份缓存（argon2 结果复用）+ 单飞；容量 0 = 关闭（每请求都校验）。
    verified: verified::VerifiedCache,
    /// 已验证缓存的容量上限与有效期。
    verified_max: usize,
    verified_ttl: Duration,
    /// 本实例真正跑过多少次 argon2。
    ///
    /// 刻意做成**每实例**计数而不是全局静态：全局计数会被同一个测试进程里其他测试
    /// 的 argon2 调用污染（实测并行跑全量 lib 时，一个只应 1 次的断言会被顶到 2 次）。
    /// 每实例计数天然隔离，测试也就不必串行化。开销可忽略——每次自增都伴随一次
    /// argon2（毫秒级），一个原子加不构成噪声。
    argon2_runs: AtomicUsize,
    /// 凭据代数：**只在凭据相关变更时**自增（创建/吊销/轮换）。
    /// 每条记录带一个 `cred_version`，变更后旧缓存条目的版本对不上 → 立即失效。
    cred_generation: AtomicU64,
}

#[derive(Clone, Debug)]
pub struct KeyRecord {
    pub id: String,
    /// argon2 哈希（PHC 格式，如 `$argon2id$v=19$m=19456,t=2,p=1$...`），非明文。
    pub key_hash: String,
    /// 快速索引：sha256(明文 key) 的十六进制，授权时 O(1) 定位记录。
    pub lookup: String,
    pub name: String,
    pub created_at: u64,
    pub enabled: bool,
    /// 凭据版本：写入时取当时代数。任何凭据相关变更（吊销/轮换）都会让代数自增，
    /// 从而让基于旧版本建立的已验证缓存**立即失效**（见 `verified` 模块）。
    pub cred_version: u64,
}

/// `create()` 的返回：记录 + 仅此一次的明文 key（之后不再可获取）。
pub struct CreatedKey {
    pub record: KeyRecord,
    pub plaintext: String,
}

/// 已验证身份缓存的默认容量：每条 ~100 字节，1650 条约 165KB。
pub const DEFAULT_VERIFIED_MAX: usize = 1650;
/// 已验证身份的默认有效期。注意：**吊销不依赖它**（版本校验优先），
/// 它只决定"多久之后重新付一次 argon2 的钱"。
const DEFAULT_VERIFIED_TTL: Duration = Duration::from_secs(30 * 60);

const API_KEY_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    lookup TEXT NOT NULL UNIQUE,
    key_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    cred_version INTEGER NOT NULL DEFAULT 1
)";

const USAGE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS key_usage (
    key_id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    requests INTEGER NOT NULL DEFAULT 0,
    estimated_requests INTEGER NOT NULL DEFAULT 0,
    last_used_at INTEGER NOT NULL DEFAULT 0
)";

impl KeyStore {
    /// 默认：1650 条缓存、30 分钟有效期（够覆盖"同一批客户端持续打"的场景；
    /// 吊销仍然是即时的——版本校验在缓存之前，不依赖 TTL）。
    pub fn new(file: Option<PathBuf>) -> Self {
        Self::with_verified(file, DEFAULT_VERIFIED_MAX, DEFAULT_VERIFIED_TTL)
    }

    pub fn default_verified_ttl() -> Duration {
        DEFAULT_VERIFIED_TTL
    }

    pub fn default_verified_max() -> usize {
        DEFAULT_VERIFIED_MAX
    }

    /// 指定已验证缓存容量与有效期；`max = 0` 关闭缓存（恢复"每请求都跑 argon2"的旧行为）。
    pub fn with_verified(file: Option<PathBuf>, max: usize, ttl: Duration) -> Self {
        let db = match &file {
            Some(path) => match Connection::open(path) {
                Ok(mut conn) => {
                    // ② 顺带做的持久化设置：WAL + synchronous=NORMAL。
                    // 落库已经改成"按周期批量"，提交次数从每请求一次降到每周期一次；
                    // 这两条让剩下的那几次提交不必每次都 fsync 主库（云端实测每次
                    // 同步提交约 3.5ms）。journal_mode 是持久属性，设一次即可；
                    // 失败只告警（例如文件系统不支持 WAL），不影响功能。
                    if let Err(e) = conn.pragma_update(None, "journal_mode", "WAL") {
                        tracing::warn!("sqlite: enable WAL failed (non-fatal): {e}");
                    }
                    if let Err(e) = conn.pragma_update(None, "synchronous", "NORMAL") {
                        tracing::warn!("sqlite: set synchronous=NORMAL failed (non-fatal): {e}");
                    }
                    let init = (|| {
                        conn.execute_batch(API_KEY_SCHEMA)?;
                        conn.execute_batch(USAGE_SCHEMA)?;
                        // 老库（无 cred_version 列）→ 补列；新库上 API_KEY_SCHEMA 已建好，这里跳过。
                        if !table_has_column(&conn, "api_keys", "cred_version")? {
                            conn.execute_batch(
                                "ALTER TABLE api_keys ADD COLUMN cred_version INTEGER NOT NULL DEFAULT 1",
                            )?;
                        }
                        Ok::<_, rusqlite::Error>(())
                    })();
                    match init {
                        Ok(()) => {
                            // 旧版库（明文 key 表，无 lookup 列）→ 无损迁移为 argon2 哈希
                            match migrate_legacy_keys(&mut conn) {
                                Ok(0) => {}
                                Ok(n) => tracing::info!(
                                    count = n,
                                    "migrated legacy plaintext keys to argon2 hashes"
                                ),
                                Err(e) => {
                                    tracing::warn!(
                                        "keys db migration failed: {e}; using empty store"
                                    );
                                }
                            }
                            Some(conn)
                        }
                        Err(e) => {
                            tracing::warn!(
                                "keys db {:?} init failed: {e}; using memory only",
                                path
                            );
                            None
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("keys db {:?} open failed: {e}; using memory only", path);
                    None
                }
            },
            None => None,
        };
        let runtime = match &db {
            Some(conn) => match load_keys(conn) {
                Ok(map) => map,
                Err(e) => {
                    tracing::warn!("keys db load failed: {e}; using empty store");
                    HashMap::new()
                }
            },
            None => HashMap::new(),
        };
        // 连接是**资源**：凭据写穿与用量落库共用它，因此包一层 `Arc`；
        // 而状态各自独占——`runtime` 留在这里，用量账本交给 `usage::UsageStore`
        //（它在构造时自己从 `key_usage` 载入，失败只告警并按空账本继续）。
        let db = Arc::new(Mutex::new(db));
        let usage = usage::UsageStore::new(db.clone());
        Self {
            inner: Arc::new(KeyStoreInner {
                runtime: RwLock::new(runtime),
                db,
                usage,
                verified: verified::VerifiedCache::default(),
                verified_max: max,
                verified_ttl: ttl,
                argon2_runs: AtomicUsize::new(0),
                cred_generation: AtomicU64::new(1),
            }),
        }
    }

    /// 推进凭据代数并返回新值。**任何**改变"某个 key 是否有效/其哈希"的写路径
    /// 都必须调用它，否则已验证缓存会继续放行旧身份（见 `verified` 模块的安全性说明）。
    fn bump_cred_generation(&self) -> u64 {
        self.inner
            .cred_generation
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1)
    }

    /// 校验 token 是否为启用中的动态 key（sha256 定位 + argon2 校验）。
    pub fn authorize(&self, token: &str) -> bool {
        self.authorize_record(token).is_some()
    }

    /// 校验并返回 key id（argon2 一次；authorize 的带返回值版本）。
    pub fn authorize_id(&self, token: &str) -> Option<String> {
        self.authorize_record(token).map(|r| r.id.clone())
    }

    /// 校验并返回 key 记录。
    ///
    /// 热路径（有缓存时）只做三件事：`sha256(token)` → O(1) 查表 → 比对凭据版本，
    /// **不跑 argon2**；只有缓存未命中（首次见到该 token、版本变了、或缓存关闭）才校验。
    ///
    /// 单飞：同一个 token 的并发请求串行化，只有第一个真正跑 argon2，其余等它的结果——
    /// 这是把内存峰值从 `并发数 × 19MiB` 压到 `同时首用的不同 token 数 × 19MiB` 的关键。
    pub fn authorize_record(&self, token: &str) -> Option<KeyRecord> {
        let lookup = lookup_of(token);

        // ① 快路径：记录在、启用中、缓存里有同版本的身份 → 直接放行（不跑 argon2）
        if self.inner.verified_max > 0 {
            let runtime = self.inner.runtime.read().unwrap();
            let rec = runtime.get(&lookup)?;
            if !rec.enabled {
                return None;
            }
            let version = rec.cred_version;
            drop(runtime);
            if let Some(hit) = self
                .inner
                .verified
                .get(&lookup, version, self.inner.verified_ttl)
            {
                return Some(hit);
            }
        }

        // ② 缓存关闭：保持旧语义（每次请求都完整校验）
        if self.inner.verified_max == 0 {
            let runtime = self.inner.runtime.read().unwrap();
            return match runtime.get(&lookup) {
                Some(rec) if rec.enabled && self.verify_and_count(token, &rec.key_hash) => {
                    Some(rec.clone())
                }
                _ => None,
            };
        }

        // ③ 未命中：单飞 + 校验
        let slot = self.inner.verified.flight(&lookup);
        let out = {
            let _guard = slot.lock().unwrap();
            // 双检：等锁期间可能已被同 token 的并发请求填好了
            let runtime = self.inner.runtime.read().unwrap();
            let rec = match runtime.get(&lookup) {
                Some(r) if r.enabled => r,
                _ => {
                    drop(runtime);
                    self.inner.verified.release_flight(&lookup);
                    return None;
                }
            };
            if let Some(hit) =
                self.inner
                    .verified
                    .get(&lookup, rec.cred_version, self.inner.verified_ttl)
            {
                Some(hit)
            } else if self.verify_and_count(token, &rec.key_hash) {
                let rec = rec.clone();
                drop(runtime);
                self.inner
                    .verified
                    .put(&lookup, rec.clone(), self.inner.verified_max);
                Some(rec)
            } else {
                None
            }
        };
        self.inner.verified.release_flight(&lookup);
        out
    }

    /// (缓存命中, 未命中/校验次数)：供 `/metrics` 观察 argon2 复用情况。
    pub fn verified_counters(&self) -> (u64, u64) {
        self.inner.verified.counters()
    }

    /// 创建动态 key 并持久化；返回记录与仅此一次的明文 key。
    ///
    /// **顺序是"先落库、后进内存"**：落库失败就返回 `Err`，内存与库都不变——否则会出现
    /// "管理页显示一把重启后就消失的 key"（评估 §5 H2 / 记录 P2-9），而且那把 key 的明文
    /// 已经交给了调用方，收不回来。
    ///
    /// 纯内存模式（`db = None`，库打不开时的降级）没有可落库的对象，直接成功。
    pub fn create(&self, name: String) -> Result<CreatedKey, GatewayError> {
        let (id, plaintext) = generate_id_key();
        let lookup = lookup_of(&plaintext);
        let key_hash = hash_argon2(&plaintext);
        let record = KeyRecord {
            id,
            key_hash,
            lookup,
            name,
            created_at: now_secs(),
            enabled: true,
            cred_version: self.bump_cred_generation(),
        };
        // ① 先落库。失败 → 直接把错误交给调用方（admin 映射 500），内存一个字都不改。
        if let Some(conn) = self.inner.db.lock().unwrap().as_mut() {
            conn.execute(
                "INSERT OR REPLACE INTO api_keys (id, lookup, key_hash, name, created_at, enabled)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    record.id,
                    record.lookup,
                    record.key_hash,
                    record.name,
                    record.created_at as i64,
                    1i64
                ],
            )?;
        }
        // ② 再进内存：此后授权立即可用。
        self.inner
            .runtime
            .write()
            .unwrap()
            .insert(record.lookup.clone(), record.clone());
        tracing::info!(id = %record.id, name = %record.name, "api key created");
        Ok(CreatedKey { record, plaintext })
    }

    /// 列出动态 key（不含明文；由调用方决定展示形式）。
    pub fn list(&self) -> Vec<KeyRecord> {
        let mut v: Vec<KeyRecord> = self
            .inner
            .runtime
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect();
        v.sort_by_key(|r| r.created_at);
        v
    }

    /// 吊销动态 key：`Ok(true)` = 真的删掉了，`Ok(false)` = 本来就不存在；
    /// `Err` = **没能落库，什么都没变**（key 仍然可用）。
    ///
    /// **顺序是"先落库、后改内存"**，理由与 [`Self::create`] 对称：内存先删的话，落库失败时
    /// 会出现"内存说没了、库还在"——重启后 `load_keys` 把 key 复活（评估 §5 H2 / 记录 P1-4）；
    /// 更糟的是**重试也救不回来**：内存里已经查不到它，重试只会返回"不存在"，而库里那行还在。
    /// 先落库之后，失败时内存原样（key 仍可用），重试会重新尝试删除并最终自愈。
    pub fn delete(&self, id: &str) -> Result<bool, GatewayError> {
        // 先看它在不在：不在就是 404，且**不碰库**（与旧语义一致）。
        if !self
            .inner
            .runtime
            .read()
            .unwrap()
            .values()
            .any(|r| r.id == id)
        {
            return Ok(false);
        }
        // ① 先落库。失败 → Err，内存原样。
        if let Some(conn) = self.inner.db.lock().unwrap().as_mut() {
            conn.execute("DELETE FROM api_keys WHERE id = ?1", rusqlite::params![id])?;
        }
        // ② 再改内存 + 失效缓存 + 推进代数（并发双删时只有一个拿到 true）。
        let mut removed = false;
        {
            let mut runtime = self.inner.runtime.write().unwrap();
            runtime.retain(|_, r| {
                if r.id == id {
                    removed = true;
                    false
                } else {
                    true
                }
            });
        }
        if removed {
            // 记录已从 runtime 表消失（查找直接 miss），这里再失效缓存并推进代数：
            // 双保险，且保证"任何凭据变更都会让旧身份失效"这条不变量成立。
            self.inner.verified.invalidate_by_id(id);
            self.bump_cred_generation();
            tracing::info!(id = %id, "api key revoked");
        }
        Ok(removed)
    }

    /// 记录一次用量并**立即同步落库**（= 内存累加 + 落库）。
    /// 吊销的 key 也有可能在途请求刚结束——按 key_id 独立累计，记录保留可审计。
    ///
    /// 仅测试使用：生产路径只做内存累加，见 [`Self::accumulate_usage`]。
    #[cfg(test)]
    pub fn record_usage(&self, key_id: &str, name: &str, delta: &UsageDelta) {
        self.inner.usage.record(key_id, name, delta);
    }

    /// 校验一次 argon2，并在测试构建下记一次本实例的调用数。
    fn verify_and_count(&self, token: &str, key_hash: &str) -> bool {
        self.inner.argon2_runs.fetch_add(1, Ordering::SeqCst);
        verify_argon2(token, key_hash)
    }

    /// 本实例累计跑过多少次 argon2（测试断言用；每实例隔离，不受其他测试影响）。
    #[cfg(test)]
    pub fn argon2_runs(&self) -> usize {
        self.inner.argon2_runs.load(Ordering::SeqCst)
    }

    /// 只做内存累加：纳秒级、无 IO，用于让 `/admin/usage`（读的正是这份内存计数）
    /// 在响应返回时立即一致。
    ///
    /// 实现与契约见 [`usage::UsageStore::accumulate`]：**这里只是转发**，不保留独立逻辑。
    pub fn accumulate_usage(&self, key_id: &str, name: &str, delta: &UsageDelta) {
        self.inner.usage.accumulate(key_id, name, delta);
    }

    /// 是否有"内存值尚未落库"的 key（静默期返回 false，调用方可跳过整轮 flush）。
    pub fn usage_has_pending(&self) -> bool {
        self.inner.usage.has_pending()
    }

    /// 把内存里的用量**绝对累计值**批量落库（实现与契约见 [`usage::UsageStore::flush_once`]：
    /// 绝对值 → 幂等、重启不重复累加；成功提交后才更新"已落库"标记 → 失败下轮重试）。
    ///
    /// 返回本轮写入的 key 数；`force = true` 时忽略"是否变化"（用于关闭前落库）。
    pub fn flush_usage_once(&self, force: bool) -> usize {
        self.inner.usage.flush_once(force)
    }

    /// 关闭前落库：把全部 key 的当前值无条件写一次（可能包含未变化的，代价可忽略）。
    pub fn flush_usage_blocking(&self) -> usize {
        self.inner.usage.flush_blocking()
    }

    /// 把一次用量**增量**写穿到 SQLite（旧的每请求写库路径，**仅测试用**）。
    ///
    /// 生产路径已改为 [`Self::flush_usage_once`]：按周期把各 key 的绝对累计值批量写一次。
    /// 增量写每次都要抢全局 `db` 锁并提交事务，实测把 2 vCPU 的吞吐摁在约 190 QPS，
    /// 所以只留给测试构造"库里已有某值"的场景。**阻塞调用**，不要放回请求路径。
    #[cfg(test)]
    pub fn persist_usage(&self, key_id: &str, name: &str, delta: &UsageDelta) {
        self.inner.usage.persist(key_id, name, delta);
    }

    /// 单个 key 的用量快照（无记录 → None）。
    pub fn usage_of(&self, key_id: &str) -> Option<KeyUsageInfo> {
        self.inner.usage.of(key_id)
    }

    /// 全部 key 的用量快照（按 key_id 排序）。
    pub fn usage_snapshot(&self) -> Vec<KeyUsageInfo> {
        self.inner.usage.snapshot()
    }
}

/// 迁移旧版库（明文 key 表，无 lookup/key_hash 列）为 argon2 哈希存储。
/// 旧库存的是明文，可无损重哈希；迁移后删除明文表。已是新 schema 时直接跳过。
/// 返回迁移的 key 条数。
///
/// 注意：同步执行 + 全量读入 + 单一大事务，**仅适合小数据量**（个人/小团队、不介意
/// 极端情况下重发 key）；大规模升级请走离线迁移（见 DEPLOY.md §10 与 TODO.md P1）。
fn migrate_legacy_keys(conn: &mut Connection) -> rusqlite::Result<usize> {
    if table_has_column(conn, "api_keys", "lookup")? {
        return Ok(0); // 已是新 schema
    }

    // 读取旧行（明文 key → 重哈希）；旧表可能为空，也要重建结构
    let mut rows = Vec::new();
    {
        let mut stmt = conn.prepare("SELECT id, key, name, created_at, enabled FROM api_keys")?;
        let iter = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?;
        for row in iter {
            let (id, plaintext, name, created_at, enabled) = row?;
            rows.push((
                id,
                lookup_of(&plaintext),
                hash_argon2(&plaintext),
                name,
                created_at,
                enabled,
            ));
        }
    }

    let tx = conn.transaction()?;
    tx.execute("ALTER TABLE api_keys RENAME TO api_keys_legacy", [])?;
    tx.execute_batch(API_KEY_SCHEMA)?;
    {
        let mut ins = tx.prepare(
            "INSERT INTO api_keys (id, lookup, key_hash, name, created_at, enabled)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for (id, lookup, key_hash, name, created_at, enabled) in &rows {
            ins.execute(rusqlite::params![
                id, lookup, key_hash, name, created_at, enabled
            ])?;
        }
    }
    tx.execute("DROP TABLE api_keys_legacy", [])?;
    tx.commit()?;
    // 回收 freelist：DROP 后旧明文页可能仍残留在文件中，VACUUM 重写数据库以清除
    if let Err(e) = conn.execute_batch("VACUUM") {
        tracing::warn!("keys db vacuum after migration failed: {e}");
    }
    Ok(rows.len())
}

/// 检查表是否包含指定列（表名来自代码常量，不拼接用户输入）。
fn table_has_column(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for c in cols {
        if c? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// 从 SQLite 加载全部动态 key（key = lookup）。
fn load_keys(conn: &Connection) -> rusqlite::Result<HashMap<String, KeyRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, lookup, key_hash, name, created_at, enabled, cred_version FROM api_keys",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(KeyRecord {
            id: r.get(0)?,
            lookup: r.get(1)?,
            key_hash: r.get(2)?,
            name: r.get(3)?,
            created_at: r.get::<_, i64>(4)? as u64,
            enabled: r.get::<_, i64>(5)? != 0,
            // 迁移前的老行是 NULL → 0；0 不是合法代数（代数从 1 起），归一到 1
            cred_version: r.get::<_, Option<i64>>(6)?.unwrap_or(1).max(1) as u64,
        })
    })?;
    let mut map = HashMap::new();
    for row in rows {
        let rec = row?;
        map.insert(rec.lookup.clone(), rec);
    }
    Ok(map)
}

/// argon2id 哈希（默认参数 m=19456/t=2/p=1，OWASP 建议）。
/// 失败仅可能发生在参数非法时——默认参数必然合法，故 expect。
#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::tempdir;

    #[test]
    fn persist_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let store = KeyStore::new(Some(path.clone()));
        let created = store.create("dsh".into()).unwrap();
        assert!(
            store.authorize(&created.plaintext),
            "new key should authorize"
        );
        assert!(!store.authorize("nope"));
        drop(store);

        let reloaded = KeyStore::new(Some(path.clone()));
        assert!(
            reloaded.authorize(&created.plaintext),
            "persisted key should survive reload"
        );
    }

    #[test]
    fn plaintext_never_persisted() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let store = KeyStore::new(Some(path.clone()));
        let created = store.create("sec".into()).unwrap();
        drop(store); // 确保落盘

        let bytes = std::fs::read(&path).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains(&created.plaintext),
            "plaintext key must not be persisted"
        );
        assert!(
            text.contains("$argon2id$"),
            "argon2 hash should be persisted"
        );
        // 明文不落盘后，重启依然能通过哈希校验授权
        let reloaded = KeyStore::new(Some(path.clone()));
        assert!(reloaded.authorize(&created.plaintext));
        assert!(!reloaded.authorize("wrong"));
    }

    #[test]
    fn delete_revokes_and_persists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let store = KeyStore::new(Some(path.clone()));
        let created = store.create("x".into()).unwrap();
        assert!(store.authorize(&created.plaintext));
        assert!(store.delete(&created.record.id).unwrap());
        assert!(
            !store.authorize(&created.plaintext),
            "revoked key must be rejected"
        );
        assert!(
            !store.delete(&created.record.id).unwrap(),
            "deleting twice returns false"
        );

        // 吊销同样持久化：重载后 key 依然失效
        let reloaded = KeyStore::new(Some(path.clone()));
        assert!(
            !reloaded.authorize(&created.plaintext),
            "revocation should survive reload"
        );
    }

    #[test]
    fn corrupt_keys_db_ignored() {
        // 文件存在但不是合法 SQLite → 警告并当作空库
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        std::fs::write(&path, "{ not a sqlite database !!!").unwrap();
        let store = KeyStore::new(Some(path.clone()));
        assert!(!store.authorize("anything"));
    }

    #[test]
    fn unreadable_keys_db_ignored() {
        // 路径存在但无法打开（是目录）→ 警告并当作空库
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        std::fs::create_dir(&path).unwrap();
        let store = KeyStore::new(Some(path.clone()));
        assert!(!store.authorize("anything"));
        // 降级为仅内存后，动态 key 仍可用
        let created = store.create("mem".into()).unwrap();
        assert!(store.authorize(&created.plaintext));
    }

    #[test]
    fn usage_accumulates_and_persists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let store = KeyStore::new(Some(path.clone()));
        let created = store.create("usage-test".into()).unwrap();
        let id = created.record.id.clone();

        // 3 次请求：2 次精确 usage + 1 次估算
        store.record_usage(
            &id,
            "usage-test",
            &UsageDelta {
                prompt_tokens: 10,
                completion_tokens: 20,
                estimated: false,
            },
        );
        store.record_usage(
            &id,
            "usage-test",
            &UsageDelta {
                prompt_tokens: 5,
                completion_tokens: 5,
                estimated: false,
            },
        );
        store.record_usage(
            &id,
            "usage-test",
            &UsageDelta {
                prompt_tokens: 100,
                completion_tokens: 50,
                estimated: true,
            },
        );
        let info = store.usage_of(&id).unwrap();
        assert_eq!(info.prompt_tokens, 115);
        assert_eq!(info.completion_tokens, 75);
        assert_eq!(info.total_tokens, 190);
        assert_eq!(info.requests, 3);
        assert_eq!(info.estimated_requests, 1);
        assert_eq!(info.name, "usage-test");
        assert!(info.last_used_at > 0);

        // 持久化：重载后用量仍在（吊销 key 也不丢记录，可审计）
        drop(store);
        let reloaded = KeyStore::new(Some(path.clone()));
        let again = reloaded.usage_of(&id).unwrap();
        assert_eq!(again.prompt_tokens, 115);
        assert_eq!(again.completion_tokens, 75);
        assert_eq!(again.requests, 3);
        assert_eq!(again.estimated_requests, 1);

        // 吊销 key 后 usage 记录仍保留（key 删了，用量表独立）
        let store2 = KeyStore::new(Some(path.clone()));
        store2.delete(&id).unwrap();
        drop(store2);
        let store3 = KeyStore::new(Some(path));
        let kept = store3.usage_of(&id).unwrap();
        assert_eq!(kept.requests, 3, "usage survives key revocation");
    }

    #[test]
    fn usage_accumulates_in_memory_and_flushes_in_one_batch() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let store = KeyStore::new(Some(path.clone()));
        let a = store.create("batch-a".into()).unwrap();
        let b = store.create("batch-b".into()).unwrap();
        let delta = UsageDelta {
            prompt_tokens: 10,
            completion_tokens: 20,
            estimated: false,
        };

        for _ in 0..100 {
            store.accumulate_usage(&a.record.id, "batch-a", &delta);
        }
        for _ in 0..50 {
            store.accumulate_usage(&b.record.id, "batch-b", &delta);
        }

        // ① 累加本身不碰库：/admin/usage 读内存，立即一致（这是原有语义，不能退步）
        assert_eq!(store.usage_of(&a.record.id).unwrap().requests, 100);
        assert_eq!(store.usage_of(&b.record.id).unwrap().requests, 50);
        assert!(store.usage_has_pending(), "累加后应报告有待落库数据");
        let fresh = KeyStore::new(Some(path.clone()));
        assert!(
            fresh.usage_of(&a.record.id).is_none(),
            "未 flush 前不应有库记录"
        );

        // ② 一个周期把两个 key 各写一行
        assert_eq!(store.flush_usage_once(false), 2);
        assert!(!store.usage_has_pending(), "flush 后不应再有待落库数据");

        // ③ 幂等：没有新用量时再 flush 是空操作（不会重复累加）
        assert_eq!(store.flush_usage_once(false), 0);
        assert_eq!(
            store.flush_usage_once(true),
            2,
            "force 会无条件重写，值仍应是绝对值"
        );

        // ④ 重启（新建 store 读同一个库）后用量仍在，且不重复累加
        let reloaded = KeyStore::new(Some(path.clone()));
        let info = reloaded.usage_of(&a.record.id).unwrap();
        assert_eq!(info.requests, 100);
        assert_eq!(info.prompt_tokens, 1000);
        assert_eq!(info.completion_tokens, 2000);
        assert_eq!(reloaded.usage_of(&b.record.id).unwrap().requests, 50);
    }

    #[test]
    fn shutdown_flush_writes_without_waiting_for_the_period() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let store = KeyStore::new(Some(path.clone()));
        let created = store.create("shutdown".into()).unwrap();
        store.accumulate_usage(
            &created.record.id,
            "shutdown",
            &UsageDelta {
                prompt_tokens: 7,
                completion_tokens: 8,
                estimated: false,
            },
        );

        // 关闭前的强制落库：不等 flush 周期，立刻可见
        let store2 = store.clone();
        assert_eq!(store2.flush_usage_blocking(), 1);

        let fresh = KeyStore::new(Some(path));
        let info = fresh.usage_of(&created.record.id).unwrap();
        assert_eq!(info.requests, 1);
        assert_eq!(info.total_tokens, 15);
    }

    #[test]
    fn usage_in_memory_only_store() {
        let store = KeyStore::new(None);
        store.record_usage(
            "mem-key",
            "m",
            &UsageDelta {
                prompt_tokens: 1,
                completion_tokens: 2,
                estimated: false,
            },
        );
        let info = store.usage_of("mem-key").unwrap();
        assert_eq!(info.total_tokens, 3);
        assert_eq!(store.usage_snapshot().len(), 1);
        assert!(store.usage_of("ghost").is_none());
    }

    #[test]
    fn creates_sqlite_db_and_schema() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let store = KeyStore::new(Some(path.clone()));
        let created = store.create("y".into()).unwrap();
        assert!(store.authorize(&created.plaintext));
        assert_eq!(store.list().len(), 1);
        assert!(path.exists(), "sqlite db file should be created");
        drop(store);
        // 文件确实是 SQLite 格式（magic 头 "SQLite format 3"）
        let head = std::fs::read(&path).unwrap();
        assert_eq!(
            &head[..16],
            b"SQLite format 3\x00",
            "expected sqlite header"
        );
    }

    #[test]
    fn authorize_rejects_unknown_lookup_without_argon2() {
        // lookup 不在表中直接拒绝，不做无意义的 argon2 计算
        let store = KeyStore::new(None);
        assert!(!store.authorize("sk-not-a-real-key"));
    }

    #[test]
    #[serial]
    fn migrates_db_without_cred_version_column() {
        // 本次改动给 api_keys 加了 cred_version 列：已部署的库没有它，
        // 启动时必须**自动补列**，且旧 key 仍能通过校验（不能因为迁移把用户锁在门外）。
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let hash = {
            // 用同一套 argon2 参数造一条"升级前"的记录（表里没有 cred_version 列）
            let h = crate::storage::hash::hash_argon2("sk-upgrade-secret");
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE api_keys (
                    id TEXT PRIMARY KEY,
                    lookup TEXT NOT NULL UNIQUE,
                    key_hash TEXT NOT NULL,
                    name TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1
                 );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO api_keys (id, lookup, key_hash, name, created_at, enabled)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1)",
                rusqlite::params![
                    "old-id",
                    crate::storage::hash::lookup_of("sk-upgrade-secret"),
                    h,
                    "old",
                    1700000000i64
                ],
            )
            .unwrap();
            let cols: Vec<String> = Connection::open(&path)
                .unwrap()
                .prepare("PRAGMA table_info(api_keys)")
                .unwrap()
                .query_map([], |r| r.get::<_, String>(1))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            assert!(
                !cols.iter().any(|c| c == "cred_version"),
                "前提：旧库确实没有 cred_version 列，实际列 {cols:?}"
            );
            h
        };
        drop(hash);

        // 用新代码打开旧库 → 应自动补列，且旧 key 依旧可用
        let store = KeyStore::new(Some(path.clone()));
        assert!(
            store.authorize("sk-upgrade-secret"),
            "升级后旧 key 必须仍然有效"
        );
        assert!(!store.authorize("sk-wrong"));
        {
            let conn = Connection::open(&path).unwrap();
            assert!(
                table_has_column(&conn, "api_keys", "cred_version").unwrap(),
                "启动时应自动给旧库补上 cred_version 列"
            );
        }
        // 迁移后的记录代数有效（0 会被当成"从未校验过"，这里必须是 >=1）
        let rec = store
            .inner
            .runtime
            .read()
            .unwrap()
            .get(&lookup_of("sk-upgrade-secret"))
            .cloned()
            .unwrap();
        assert!(rec.cred_version >= 1, "cred_version 应为有效代数");
    }

    #[test]
    fn verify_rejects_malformed_hash() {
        // 存储的哈希不是合法 PHC 格式 → 校验直接拒绝（不 panic）
        assert!(!verify_argon2("sk-anything", "not-a-phc-hash"));
        assert!(!verify_argon2("sk-anything", ""));
    }

    #[test]
    fn migrates_legacy_plaintext_db() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        // 构造旧 schema 库（明文 key 列）+ 一条明文 key
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE api_keys (
                    id TEXT PRIMARY KEY,
                    key TEXT NOT NULL,
                    name TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1
                 );
                 INSERT INTO api_keys (id, key, name, created_at, enabled)
                 VALUES ('abc123', 'sk-legacy-secret', 'old', 1700000000, 1);",
            )
            .unwrap();
        }

        let store = KeyStore::new(Some(path.clone()));
        assert!(
            store.authorize("sk-legacy-secret"),
            "migrated plaintext key should still authorize"
        );
        assert!(!store.authorize("sk-other"));

        // 迁移后：旧明文列已删除、lookup 列存在（确定性断言，不扫描文件字节）
        {
            let conn = Connection::open(&path).unwrap();
            assert!(
                !table_has_column(&conn, "api_keys", "key").unwrap(),
                "legacy plaintext column must be dropped"
            );
            assert!(table_has_column(&conn, "api_keys", "lookup").unwrap());
            assert!(table_has_column(&conn, "api_keys", "key_hash").unwrap());
        }

        // 重载后依然有效，且不再重复迁移
        let reloaded = KeyStore::new(Some(path.clone()));
        assert!(reloaded.authorize("sk-legacy-secret"));
        let list = reloaded.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "old");
    }

    #[test]
    fn migrates_empty_legacy_table_structure() {
        // 旧表存在但无数据：也要重建结构（否则 load_keys 仍会失败）
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE api_keys (
                    id TEXT PRIMARY KEY,
                    key TEXT NOT NULL,
                    name TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1
                 );",
            )
            .unwrap();
        }
        let store = KeyStore::new(Some(path.clone()));
        assert_eq!(store.list().len(), 0);
        // 结构已修复：新 key 可正常创建并持久化
        let created = store.create("new".into()).unwrap();
        drop(store);
        let reloaded = KeyStore::new(Some(path.clone()));
        assert!(reloaded.authorize(&created.plaintext));
    }

    /// 规格：**持久化失败时不能声称"创建成功"**（评估报告 §5 H2 / 记录 P2-9）。
    ///
    /// 触发方式：给 `api_keys` 加一个必然 ABORT 的 INSERT 触发器——磁盘满 / I/O 错误 /
    /// `SQLITE_BUSY` 在真实世界里就是这一支。今天 `create` 先写内存、后落库，落库失败只
    /// `warn!` 然后照常返回 → 管理页显示一把**重启后就消失**的 key。
    #[test]
    fn create_that_fails_to_persist_leaves_no_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let store = KeyStore::new(Some(path.clone()));
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TRIGGER dbg_reject_insert BEFORE INSERT ON api_keys
                 BEGIN SELECT RAISE(ABORT, 'debug: persist refused'); END;",
            )
            .unwrap();
        }

        assert!(
            store.create("cannot-persist".into()).is_err(),
            "落库失败必须让调用方知道（admin 要回 500，而不是 201 + 一把假 key）"
        );
        assert!(
            store.list().is_empty(),
            "落库失败就不该留下任何条目——重启后它会消失，等于发了一把假 key"
        );
        let conn = Connection::open(&path).unwrap();
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM api_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0, "库里当然也没有");
    }

    /// 规格：**吊销落库失败时 key 必须仍然可用**（评估报告 §5 H2 / 记录 P1-4）。
    ///
    /// 与上一条对称：今天 `delete` 先删内存、后落库，落库失败只 `warn!` 却仍返回 `true`
    /// → admin 回 204、日志写 "api key revoked"，而重启后 `load_keys` 会把 key 复活。
    /// 正确语义只有两种：内存与库**一起变**，或**都不变**——绝不能"内存说没了、库还在"。
    #[test]
    fn delete_that_fails_to_persist_keeps_the_key_usable() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let store = KeyStore::new(Some(path.clone()));
        let created = store.create("cannot-delete".into()).unwrap();
        assert!(store.authorize(&created.plaintext), "前提：这把 key 可用");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TRIGGER dbg_reject_delete BEFORE DELETE ON api_keys
                 BEGIN SELECT RAISE(ABORT, 'debug: persist refused'); END;",
            )
            .unwrap();
        }

        assert!(
            store.delete(&created.record.id).is_err(),
            "吊销没能落库必须让调用方知道（admin 要回 500）"
        );
        assert!(
            store.authorize(&created.plaintext),
            "吊销没能落库时 key 必须仍然可用——否则操作员看到 204、重启后它又活了"
        );
        let conn = Connection::open(&path).unwrap();
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM api_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1, "库里那一行也还在");
    }
}

#[cfg(test)]
mod verified_tests {
    use super::*;
    use crate::storage::hash::CheapArgon2;
    use serial_test::serial;
    use std::sync::{Arc, Barrier};

    // 这些测试都要读**进程级**的 argon2 调用计数器，彼此会互相污染 →
    // 全部标 `#[serial]`（仓库 e2e 也是同一套约定）。

    /// 并发压同一个 token；返回 (argon2 调用次数增量, 全部请求的结果)。
    /// `cache_max = 0` 时代表"关闭缓存"（旧行为）。
    fn hammer(store: &KeyStore, token: &str, threads: usize) -> (usize, Vec<bool>) {
        let before = store.argon2_runs();
        let barrier = Arc::new(Barrier::new(threads));
        let results = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for _ in 0..threads {
            let store = store.clone();
            let token = token.to_string();
            let barrier = barrier.clone();
            let results = results.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let ok = store.authorize(&token);
                results.lock().unwrap().push(ok);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let calls = store.argon2_runs() - before;
        let out = results.lock().unwrap().clone();
        (calls, out)
    }

    #[test]
    #[serial]
    fn concurrent_same_token_hashes_once() {
        let _cheap = CheapArgon2::install();
        // 这是把内存峰值从 `并发数 × 19MiB` 压到 `1 × 19MiB` 的核心契约
        let store = KeyStore::new(None);
        let key = store.create("one".into()).unwrap();
        let (calls, results) = hammer(&store, &key.plaintext, 8);
        assert_eq!(calls, 1, "同一个 token 的 8 个并发请求只应跑 1 次 argon2");
        assert!(results.iter().all(|ok| *ok), "所有并发请求都应当通过");
    }

    #[test]
    #[serial]
    fn warm_token_never_hashes_again() {
        let _cheap = CheapArgon2::install();
        let store = KeyStore::new(None);
        let key = store.create("warm".into()).unwrap();
        assert!(store.authorize(&key.plaintext)); // 首次：算一次（create 那次不算）
        let before = store.argon2_runs();
        for _ in 0..50 {
            assert!(store.authorize(&key.plaintext));
        }
        assert_eq!(store.argon2_runs() - before, 0, "命中缓存不应再跑 argon2");
        let (hits, _) = store.verified_counters();
        assert!(hits >= 50, "命中计数应当累加，实际 {hits}");
    }

    #[test]
    #[serial]
    fn disabled_cache_keeps_old_behaviour() {
        let _cheap = CheapArgon2::install();
        // cache_max = 0 → 每个请求都完整校验（与改造前语义一致）
        let key = KeyStore::with_verified(None, 0, DEFAULT_VERIFIED_TTL);
        let token = key.create("nocache".into()).unwrap().plaintext;
        let before = key.argon2_runs();
        for _ in 0..3 {
            assert!(key.authorize(&token));
        }
        let off = key.argon2_runs() - before;

        // 对照：开启缓存时，首个请求填缓存（1 次 argon2），之后不再跑
        let warm = KeyStore::new(None);
        let token2 = warm.create("cached".into()).unwrap().plaintext;
        assert!(warm.authorize(&token2)); // 预热：这一次是缓存未命中
        let before2 = warm.argon2_runs();
        for _ in 0..3 {
            assert!(warm.authorize(&token2));
        }
        let on = warm.argon2_runs() - before2;

        assert_eq!(off, 3, "关闭缓存时每请求各跑一次，实际 {off}");
        assert_eq!(on, 0, "开启缓存且已预热后不应再跑 argon2，实际 {on}");
    }

    #[test]
    #[serial]
    fn revoke_takes_effect_immediately() {
        let _cheap = CheapArgon2::install();
        // 缓存**不得**延长吊销窗口：delete 后必须立刻 401
        let store = KeyStore::new(None);
        let key = store.create("revoke".into()).unwrap();
        assert!(store.authorize(&key.plaintext));
        assert!(store.authorize(&key.plaintext)); // 已进缓存
        assert!(store.delete(&key.record.id).unwrap());
        assert!(
            !store.authorize(&key.plaintext),
            "吊销后必须立即失效（不允许缓存放行）"
        );
        assert!(
            !store.authorize_id(&key.plaintext).is_some(),
            "吊销后 authorize_id 同样应为 None"
        );
    }

    #[test]
    #[serial]
    fn credential_version_bump_invalidates_cache() {
        let _cheap = CheapArgon2::install();
        // 模拟"改 key 但不 bump 版本"以外的正确路径：bump 之后旧缓存条目必须失效
        let store = KeyStore::new(None);
        let key = store.create("bump".into()).unwrap();
        assert!(store.authorize(&key.plaintext));
        let before = store.argon2_runs();
        assert!(store.authorize(&key.plaintext));
        assert_eq!(store.argon2_runs() - before, 0, "命中缓存");

        // 直接改记录里的 cred_version（等价于"凭据变更走了正确路径"）
        {
            let mut runtime = store.inner.runtime.write().unwrap();
            let rec = runtime.get_mut(&key.record.lookup).unwrap();
            rec.cred_version += 1;
        }
        let before = store.argon2_runs();
        assert!(
            store.authorize(&key.plaintext),
            "版本变了应当重新校验，而不是拒绝"
        );
        assert_eq!(
            store.argon2_runs() - before,
            1,
            "版本变更后必须重跑一次 argon2"
        );
    }

    #[test]
    #[serial]
    fn expired_entry_is_revalidated() {
        let _cheap = CheapArgon2::install();
        // TTL 到期后重算（不改变"吊销即时"这条，只影响多久重付一次 argon2 的钱）
        let store = KeyStore::with_verified(None, DEFAULT_VERIFIED_MAX, Duration::from_millis(50));
        let key = store.create("ttl".into()).unwrap();
        assert!(store.authorize(&key.plaintext));
        std::thread::sleep(Duration::from_millis(80));
        let before = store.argon2_runs();
        assert!(store.authorize(&key.plaintext));
        assert_eq!(store.argon2_runs() - before, 1, "TTL 到期应重算一次");
    }

    #[test]
    #[serial]
    fn cache_is_bounded_and_never_stores_plaintext() {
        let _cheap = CheapArgon2::install();
        let store = KeyStore::with_verified(None, 2, DEFAULT_VERIFIED_TTL);
        let mut tokens = Vec::new();
        for i in 0..5 {
            let k = store.create(format!("k{i}")).unwrap();
            assert!(store.authorize(&k.plaintext));
            tokens.push(k.plaintext);
        }
        assert!(
            store.inner.verified.len() <= 2,
            "缓存条目数不得超过配置上限，实际 {}",
            store.inner.verified.len()
        );
        // 缓存**只键于 sha256(token)**：拿明文 token 当键永远查不到，也不该存明文
        for t in &tokens {
            assert!(
                store
                    .inner
                    .verified
                    .get(t, 1, DEFAULT_VERIFIED_TTL)
                    .is_none(),
                "缓存不得以明文 token 为键"
            );
        }
    }

    #[test]
    #[serial]
    fn wrong_token_still_rejected_with_cache() {
        let _cheap = CheapArgon2::install();
        // 命中路径不得绕过校验：拿别人的 token 永远进不去
        let store = KeyStore::new(None);
        let good = store.create("good".into()).unwrap();
        assert!(store.authorize(&good.plaintext));
        assert!(!store.authorize("sk-deadbeef"));
        assert!(!store.authorize(&format!("{}x", good.plaintext)));
    }
}
