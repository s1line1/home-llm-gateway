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
//! 现在走 [`verified::VerifiedCache`]：**缓存 + 单飞 + 凭据版本校验**——
//! argon2 降到"每(凭据版本)一次"，每请求只做 O(1) 的 enabled/版本核对，
//! 且吊销依然即时生效（版本不一致或记录消失即拒）。`verified_cache_max: 0` 可关闭。

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};

use rusqlite::Connection;
use serde::Serialize;

pub mod hash;
pub mod verified;

use crate::keystore::hash::{generate_id_key, hash_argon2, lookup_of, now_secs, verify_argon2};

#[derive(Clone)]
pub struct KeyStore {
    inner: Arc<KeyStoreInner>,
}

struct KeyStoreInner {
    /// 动态 key，key = lookup（sha256(token) 十六进制），value = 记录。
    runtime: RwLock<HashMap<String, KeyRecord>>,
    /// SQLite 持久化连接（None = 仅内存，如 db 打开失败时降级）。
    db: Mutex<Option<Connection>>,
    /// per-key 用量（key = key id；吊销 key 后记录保留，可审计）。
    usage: RwLock<HashMap<String, Arc<KeyUsageCell>>>,
    /// 已验证身份缓存（argon2 结果复用）+ 单飞；容量 0 = 关闭（每请求都校验）。
    verified: verified::VerifiedCache,
    /// 已验证缓存的容量上限与有效期。
    verified_max: usize,
    verified_ttl: Duration,
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

/// 用量累计单元：原子字段，热路径无锁累加。name 为创建时快照（吊销后仍可审计）。
pub struct KeyUsageCell {
    name: Mutex<String>,
    prompt_tokens: AtomicU64,
    completion_tokens: AtomicU64,
    requests: AtomicU64,
    estimated_requests: AtomicU64,
    last_used_at: AtomicU64,
}

impl Default for KeyUsageCell {
    fn default() -> Self {
        Self {
            name: Mutex::new(String::new()),
            prompt_tokens: AtomicU64::new(0),
            completion_tokens: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            estimated_requests: AtomicU64::new(0),
            last_used_at: AtomicU64::new(0),
        }
    }
}

/// 一次请求的用量增量（usage 提取见 `crate::usage`）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsageDelta {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    /// 是否估算来源（上游未提供 usage）。
    pub estimated: bool,
}

/// 已验证身份缓存的默认容量：每条 ~100 字节，1650 条约 165KB。
pub const DEFAULT_VERIFIED_MAX: usize = 1650;
/// 已验证身份的默认有效期。注意：**吊销不依赖它**（版本校验优先），
/// 它只决定"多久之后重新付一次 argon2 的钱"。
pub const DEFAULT_VERIFIED_TTL: Duration = Duration::from_secs(30 * 60);

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS api_keys (
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

    /// 指定已验证缓存容量与有效期；`max = 0` 关闭缓存（恢复"每请求都跑 argon2"的旧行为）。
    pub fn with_verified(file: Option<PathBuf>, max: usize, ttl: Duration) -> Self {
        let db = match &file {
            Some(path) => match Connection::open(path) {
                Ok(mut conn) => {
                    let init = (|| {
                        conn.execute_batch(SCHEMA)?;
                        conn.execute_batch(USAGE_SCHEMA)?;
                        // 老库（无 cred_version 列）→ 补列；新库上 SCHEMA 已建好，这里跳过。
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
        let usage = match &db {
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
            inner: Arc::new(KeyStoreInner {
                runtime: RwLock::new(runtime),
                db: Mutex::new(db),
                usage: RwLock::new(usage),
                verified: verified::VerifiedCache::default(),
                verified_max: max,
                verified_ttl: ttl,
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
                Some(rec) if rec.enabled && verify_argon2(token, &rec.key_hash) => {
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
            } else if verify_argon2(token, &rec.key_hash) {
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
    pub fn create(&self, name: String) -> CreatedKey {
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
        self.inner
            .runtime
            .write()
            .unwrap()
            .insert(record.lookup.clone(), record.clone());
        if let Some(conn) = self.inner.db.lock().unwrap().as_mut() {
            let r = conn.execute(
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
            );
            if let Err(e) = r {
                tracing::warn!("api key persist failed: {e}");
            }
        }
        tracing::info!(id = %record.id, name = %record.name, "api key created");
        CreatedKey { record, plaintext }
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

    /// 吊销动态 key；成功返回 true。
    pub fn delete(&self, id: &str) -> bool {
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
            if let Some(conn) = self.inner.db.lock().unwrap().as_mut() {
                let r = conn.execute("DELETE FROM api_keys WHERE id = ?1", rusqlite::params![id]);
                if let Err(e) = r {
                    tracing::warn!("api key delete persist failed: {e}");
                }
            }
            tracing::info!(id = %id, "api key revoked");
        }
        removed
    }

    /// 记录一次请求的用量（内存原子累加 + SQLite 写穿，同步）。
    /// 吊销的 key 也有可能在途请求刚结束——按 key_id 独立累计，记录保留可审计。
    ///
    /// 仅测试使用：它是 `accumulate_usage` + `persist_usage` 的同步组合，而
    /// `persist_usage` **会阻塞**（SQLite busy 重试可达数秒）。请求路径必须走
    /// 「内存累加 + 阻塞线程池落库」，见 `http_proxy::UsageCollector::finish`——
    /// 所以这里用 `cfg(test)` 把它挡在生产代码之外，避免再被误用到热路径上。
    #[cfg(test)]
    pub fn record_usage(&self, key_id: &str, name: &str, delta: &UsageDelta) {
        self.accumulate_usage(key_id, name, delta);
        self.persist_usage(key_id, name, delta);
    }

    /// 只做内存累加：纳秒级、无 IO，用于让 `/admin/usage`（读的正是这份内存计数）
    /// 在响应返回时立即一致。
    pub fn accumulate_usage(&self, key_id: &str, name: &str, delta: &UsageDelta) {
        let cell = {
            let usage = self.inner.usage.read().unwrap();
            usage.get(key_id).cloned()
        };
        let cell = match cell {
            Some(c) => c,
            None => {
                let c = Arc::new(KeyUsageCell::default());
                self.inner
                    .usage
                    .write()
                    .unwrap()
                    .entry(key_id.to_string())
                    .or_insert_with(|| c.clone());
                c
            }
        };
        {
            let mut n = cell.name.lock().unwrap();
            if n.is_empty() {
                *n = name.to_string();
            }
        }
        cell.prompt_tokens
            .fetch_add(delta.prompt_tokens, Ordering::Relaxed);
        cell.completion_tokens
            .fetch_add(delta.completion_tokens, Ordering::Relaxed);
        cell.requests.fetch_add(1, Ordering::Relaxed);
        if delta.estimated {
            cell.estimated_requests.fetch_add(1, Ordering::Relaxed);
        }
        cell.last_used_at.store(now_secs(), Ordering::Relaxed);
    }

    /// 把一次用量写穿到 SQLite（增量 UPSERT）。
    ///
    /// **阻塞调用**：SQLite busy 重试可能让它等上数秒（rusqlite 默认 busy timeout 5s），
    /// 且全程持有 `db` 互斥锁。因此调用方必须把它放到阻塞线程池上，绝不要放在
    /// async worker 上，也不要放在响应流的收尾路径上（会变成客户端的尾延迟）。
    pub fn persist_usage(&self, key_id: &str, name: &str, delta: &UsageDelta) {
        if let Some(conn) = self.inner.db.lock().unwrap().as_mut() {
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
    pub fn usage_of(&self, key_id: &str) -> Option<KeyUsageInfo> {
        let usage = self.inner.usage.read().unwrap();
        let cell = usage.get(key_id)?;
        Some(cell_to_info(key_id, cell))
    }

    /// 全部 key 的用量快照（按 key_id 排序）。
    pub fn usage_snapshot(&self) -> Vec<KeyUsageInfo> {
        let usage = self.inner.usage.read().unwrap();
        let mut out: Vec<KeyUsageInfo> = usage
            .iter()
            .map(|(id, cell)| cell_to_info(id, cell))
            .collect();
        out.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        out
    }
}

/// 把原子单元转成可序列化的明细。
fn cell_to_info(key_id: &str, cell: &KeyUsageCell) -> KeyUsageInfo {
    let prompt = cell.prompt_tokens.load(Ordering::Relaxed);
    let completion = cell.completion_tokens.load(Ordering::Relaxed);
    KeyUsageInfo {
        key_id: key_id.to_string(),
        name: cell.name.lock().unwrap().clone(),
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: prompt + completion,
        requests: cell.requests.load(Ordering::Relaxed),
        estimated_requests: cell.estimated_requests.load(Ordering::Relaxed),
        last_used_at: cell.last_used_at.load(Ordering::Relaxed),
    }
}

/// 从 SQLite 加载用量（key = key_id）。
fn load_usage(conn: &Connection) -> rusqlite::Result<HashMap<String, Arc<KeyUsageCell>>> {
    let mut stmt = conn.prepare(
        "SELECT key_id, name, prompt_tokens, completion_tokens, requests, estimated_requests, last_used_at
         FROM key_usage",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)? as u64,
            r.get::<_, i64>(3)? as u64,
            r.get::<_, i64>(4)? as u64,
            r.get::<_, i64>(5)? as u64,
            r.get::<_, i64>(6)? as u64,
        ))
    })?;
    let mut map = HashMap::new();
    for row in rows {
        let (id, name, prompt, completion, requests, estimated, last_used) = row?;
        let cell = Arc::new(KeyUsageCell {
            name: Mutex::new(name),
            prompt_tokens: AtomicU64::new(prompt),
            completion_tokens: AtomicU64::new(completion),
            requests: AtomicU64::new(requests),
            estimated_requests: AtomicU64::new(estimated),
            last_used_at: AtomicU64::new(last_used),
        });
        map.insert(id, cell);
    }
    Ok(map)
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
    tx.execute_batch(SCHEMA)?;
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
        let created = store.create("dsh".into());
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
        let created = store.create("sec".into());
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
        let created = store.create("x".into());
        assert!(store.authorize(&created.plaintext));
        assert!(store.delete(&created.record.id));
        assert!(
            !store.authorize(&created.plaintext),
            "revoked key must be rejected"
        );
        assert!(
            !store.delete(&created.record.id),
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
        let created = store.create("mem".into());
        assert!(store.authorize(&created.plaintext));
    }

    #[test]
    fn usage_accumulates_and_persists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let store = KeyStore::new(Some(path.clone()));
        let created = store.create("usage-test".into());
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
        store2.delete(&id);
        drop(store2);
        let store3 = KeyStore::new(Some(path));
        let kept = store3.usage_of(&id).unwrap();
        assert_eq!(kept.requests, 3, "usage survives key revocation");
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
        let created = store.create("y".into());
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
            let h = crate::keystore::hash::hash_argon2("sk-upgrade-secret");
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
                    crate::keystore::hash::lookup_of("sk-upgrade-secret"),
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
        let created = store.create("new".into());
        drop(store);
        let reloaded = KeyStore::new(Some(path.clone()));
        assert!(reloaded.authorize(&created.plaintext));
    }
}

#[cfg(test)]
mod verified_tests {
    use super::*;
    use crate::keystore::hash::{argon2_calls, CheapArgon2};
    use serial_test::serial;
    use std::sync::{Arc, Barrier};

    // 这些测试都要读**进程级**的 argon2 调用计数器，彼此会互相污染 →
    // 全部标 `#[serial]`（仓库 e2e 也是同一套约定）。

    /// 并发压同一个 token；返回 (argon2 调用次数增量, 全部请求的结果)。
    /// `cache_max = 0` 时代表"关闭缓存"（旧行为）。
    fn hammer(store: &KeyStore, token: &str, threads: usize) -> (usize, Vec<bool>) {
        let before = argon2_calls();
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
        let calls = argon2_calls() - before;
        let out = results.lock().unwrap().clone();
        (calls, out)
    }

    #[test]
    #[serial]
    fn concurrent_same_token_hashes_once() {
        let _cheap = CheapArgon2::install();
        // 这是把内存峰值从 `并发数 × 19MiB` 压到 `1 × 19MiB` 的核心契约
        let store = KeyStore::new(None);
        let key = store.create("one".into());
        let (calls, results) = hammer(&store, &key.plaintext, 8);
        assert_eq!(calls, 1, "同一个 token 的 8 个并发请求只应跑 1 次 argon2");
        assert!(results.iter().all(|ok| *ok), "所有并发请求都应当通过");
    }

    #[test]
    #[serial]
    fn warm_token_never_hashes_again() {
        let _cheap = CheapArgon2::install();
        let store = KeyStore::new(None);
        let key = store.create("warm".into());
        assert!(store.authorize(&key.plaintext)); // 首次：算一次（create 那次不算）
        let before = argon2_calls();
        for _ in 0..50 {
            assert!(store.authorize(&key.plaintext));
        }
        assert_eq!(argon2_calls() - before, 0, "命中缓存不应再跑 argon2");
        let (hits, _) = store.verified_counters();
        assert!(hits >= 50, "命中计数应当累加，实际 {hits}");
    }

    #[test]
    #[serial]
    fn disabled_cache_keeps_old_behaviour() {
        let _cheap = CheapArgon2::install();
        // cache_max = 0 → 每个请求都完整校验（与改造前语义一致）
        let key = KeyStore::with_verified(None, 0, DEFAULT_VERIFIED_TTL);
        let token = key.create("nocache".into()).plaintext;
        let before = argon2_calls();
        for _ in 0..3 {
            assert!(key.authorize(&token));
        }
        let off = argon2_calls() - before;

        // 对照：开启缓存时，首个请求填缓存（1 次 argon2），之后不再跑
        let warm = KeyStore::new(None);
        let token2 = warm.create("cached".into()).plaintext;
        assert!(warm.authorize(&token2)); // 预热：这一次是缓存未命中
        let before2 = argon2_calls();
        for _ in 0..3 {
            assert!(warm.authorize(&token2));
        }
        let on = argon2_calls() - before2;

        assert_eq!(off, 3, "关闭缓存时每请求各跑一次，实际 {off}");
        assert_eq!(on, 0, "开启缓存且已预热后不应再跑 argon2，实际 {on}");
    }

    #[test]
    #[serial]
    fn revoke_takes_effect_immediately() {
        let _cheap = CheapArgon2::install();
        // 缓存**不得**延长吊销窗口：delete 后必须立刻 401
        let store = KeyStore::new(None);
        let key = store.create("revoke".into());
        assert!(store.authorize(&key.plaintext));
        assert!(store.authorize(&key.plaintext)); // 已进缓存
        assert!(store.delete(&key.record.id));
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
        let key = store.create("bump".into());
        assert!(store.authorize(&key.plaintext));
        let before = argon2_calls();
        assert!(store.authorize(&key.plaintext));
        assert_eq!(argon2_calls() - before, 0, "命中缓存");

        // 直接改记录里的 cred_version（等价于"凭据变更走了正确路径"）
        {
            let mut runtime = store.inner.runtime.write().unwrap();
            let rec = runtime.get_mut(&key.record.lookup).unwrap();
            rec.cred_version += 1;
        }
        let before = argon2_calls();
        assert!(
            store.authorize(&key.plaintext),
            "版本变了应当重新校验，而不是拒绝"
        );
        assert_eq!(argon2_calls() - before, 1, "版本变更后必须重跑一次 argon2");
    }

    #[test]
    #[serial]
    fn expired_entry_is_revalidated() {
        let _cheap = CheapArgon2::install();
        // TTL 到期后重算（不改变"吊销即时"这条，只影响多久重付一次 argon2 的钱）
        let store = KeyStore::with_verified(None, DEFAULT_VERIFIED_MAX, Duration::from_millis(50));
        let key = store.create("ttl".into());
        assert!(store.authorize(&key.plaintext));
        std::thread::sleep(Duration::from_millis(80));
        let before = argon2_calls();
        assert!(store.authorize(&key.plaintext));
        assert_eq!(argon2_calls() - before, 1, "TTL 到期应重算一次");
    }

    #[test]
    #[serial]
    fn cache_is_bounded_and_never_stores_plaintext() {
        let _cheap = CheapArgon2::install();
        let store = KeyStore::with_verified(None, 2, DEFAULT_VERIFIED_TTL);
        let mut tokens = Vec::new();
        for i in 0..5 {
            let k = store.create(format!("k{i}"));
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
        let good = store.create("good".into());
        assert!(store.authorize(&good.plaintext));
        assert!(!store.authorize("sk-deadbeef"));
        assert!(!store.authorize(&format!("{}x", good.plaintext)));
    }
}
