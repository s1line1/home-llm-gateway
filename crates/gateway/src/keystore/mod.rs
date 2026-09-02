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
//! 注意：argon2 校验每次请求约耗时 10-30ms（19MiB 内存、t=2）。edge 网关低 QPS 下
//! 可接受；若需更高吞吐，可调低参数（如 Params::new(4096, 3, 1)）或用登录式缓存。

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
};

use rusqlite::Connection;

pub mod hash;

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
}

/// `create()` 的返回：记录 + 仅此一次的明文 key（之后不再可获取）。
pub struct CreatedKey {
    pub record: KeyRecord,
    pub plaintext: String,
}

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    lookup TEXT NOT NULL UNIQUE,
    key_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1
)";

impl KeyStore {
    pub fn new(file: Option<PathBuf>) -> Self {
        let db = match &file {
            Some(path) => match Connection::open(path) {
                Ok(mut conn) => match conn.execute_batch(SCHEMA) {
                    Ok(()) => {
                        // 旧版库（明文 key 表，无 lookup 列）→ 无损迁移为 argon2 哈希
                        match migrate_legacy_keys(&mut conn) {
                            Ok(0) => {}
                            Ok(n) => tracing::info!(
                                count = n,
                                "migrated legacy plaintext keys to argon2 hashes"
                            ),
                            Err(e) => {
                                tracing::warn!("keys db migration failed: {e}; using empty store");
                            }
                        }
                        Some(conn)
                    }
                    Err(e) => {
                        tracing::warn!("keys db {:?} init failed: {e}; using memory only", path);
                        None
                    }
                },
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
        Self {
            inner: Arc::new(KeyStoreInner {
                runtime: RwLock::new(runtime),
                db: Mutex::new(db),
            }),
        }
    }

    /// 校验 token 是否为启用中的动态 key（sha256 定位 + argon2 校验）。
    pub fn authorize(&self, token: &str) -> bool {
        let lookup = lookup_of(token);
        let runtime = self.inner.runtime.read().unwrap();
        match runtime.get(&lookup) {
            Some(rec) => rec.enabled && verify_argon2(token, &rec.key_hash),
            None => false,
        }
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
    let mut stmt =
        conn.prepare("SELECT id, lookup, key_hash, name, created_at, enabled FROM api_keys")?;
    let rows = stmt.query_map([], |r| {
        Ok(KeyRecord {
            id: r.get(0)?,
            lookup: r.get(1)?,
            key_hash: r.get(2)?,
            name: r.get(3)?,
            created_at: r.get::<_, i64>(4)? as u64,
            enabled: r.get::<_, i64>(5)? != 0,
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
