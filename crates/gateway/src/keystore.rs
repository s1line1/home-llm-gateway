//! API Key 存储：静态 key（`--api-keys`）+ 运行时动态 key（SQLite 持久化）。
//! 动态 key 通过 Admin API 创建/吊销，立即生效，无需重启网关。
//!
//! 架构：内存索引（`runtime` HashMap）保证 `authorize()` 热路径零 IO；
//! SQLite 负责持久化，创建/吊销时写穿（write-through）。

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::Connection;
use serde::Serialize;

#[derive(Clone)]
pub struct KeyStore {
    inner: Arc<KeyStoreInner>,
}

struct KeyStoreInner {
    /// 静态 key（启动参数 --api-keys），不可运行时修改。
    static_keys: Vec<String>,
    /// 动态 key（Admin API 管理），id → 记录（内存索引）。
    runtime: RwLock<HashMap<String, KeyRecord>>,
    /// SQLite 持久化连接（None = 仅内存，如 db 打开失败时降级）。
    db: Mutex<Option<Connection>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct KeyRecord {
    pub id: String,
    /// 明文 key（仅创建时返回给调用方；数据库里也保存以便校验）。
    pub key: String,
    pub name: String,
    pub created_at: u64,
    pub enabled: bool,
}

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    key TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1
)";

impl KeyStore {
    pub fn new(static_keys: Vec<String>, file: Option<PathBuf>) -> Self {
        let db = match &file {
            Some(path) => match Connection::open(path) {
                Ok(conn) => match conn.execute_batch(SCHEMA) {
                    Ok(()) => Some(conn),
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
                static_keys,
                runtime: RwLock::new(runtime),
                db: Mutex::new(db),
            }),
        }
    }

    /// 校验 token 是否为有效 key（静态或动态、启用中）。
    pub fn authorize(&self, token: &str) -> bool {
        if self
            .inner
            .static_keys
            .iter()
            .any(|k| constant_time_eq(k.as_bytes(), token.as_bytes()))
        {
            return true;
        }
        let runtime = self.inner.runtime.read().unwrap();
        runtime
            .values()
            .any(|r| r.enabled && constant_time_eq(r.key.as_bytes(), token.as_bytes()))
    }

    /// 创建动态 key 并持久化；返回记录（含明文 key）。
    pub fn create(&self, name: String) -> KeyRecord {
        let (id, key) = generate_id_key();
        let record = KeyRecord {
            id,
            key,
            name,
            created_at: now_secs(),
            enabled: true,
        };
        self.inner
            .runtime
            .write()
            .unwrap()
            .insert(record.id.clone(), record.clone());
        if let Some(conn) = self.inner.db.lock().unwrap().as_mut() {
            let r = conn.execute(
                "INSERT OR REPLACE INTO api_keys (id, key, name, created_at, enabled)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![record.id, record.key, record.name, record.created_at as i64, 1i64],
            );
            if let Err(e) = r {
                tracing::warn!("api key persist failed: {e}");
            }
        }
        tracing::info!(id = %record.id, name = %record.name, "api key created");
        record
    }

    /// 列出动态 key（不含敏感信息由调用方决定如何展示）。
    pub fn list(&self) -> Vec<KeyRecord> {
        let mut v: Vec<KeyRecord> = self.inner.runtime.read().unwrap().values().cloned().collect();
        v.sort_by_key(|r| r.created_at);
        v
    }

    /// 吊销动态 key；成功返回 true。
    pub fn delete(&self, id: &str) -> bool {
        let removed = self.inner.runtime.write().unwrap().remove(id).is_some();
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

/// 从 SQLite 加载全部动态 key。
fn load_keys(conn: &Connection) -> rusqlite::Result<HashMap<String, KeyRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, key, name, created_at, enabled FROM api_keys",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(KeyRecord {
            id: r.get(0)?,
            key: r.get(1)?,
            name: r.get(2)?,
            created_at: r.get::<_, i64>(3)? as u64,
            enabled: r.get::<_, i64>(4)? != 0,
        })
    })?;
    let mut map = HashMap::new();
    for row in rows {
        let rec = row?;
        map.insert(rec.id.clone(), rec);
    }
    Ok(map)
}

fn generate_id_key() -> (String, String) {
    let mut id_buf = [0u8; 4];
    let mut key_buf = [0u8; 24];
    getrandom::fill(&mut id_buf).expect("os rng");
    getrandom::fill(&mut key_buf).expect("os rng");
    let id = format!("{:08x}", u32::from_be_bytes(id_buf));
    let key = format!("sk-{}", key_buf.iter().map(|b| format!("{b:02x}")).collect::<String>());
    (id, key)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 恒定时间比较，防时序侧信道。
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn persist_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let store = KeyStore::new(vec!["static-1".into()], Some(path.clone()));
        let rec = store.create("dsh".into());
        assert!(store.authorize(&rec.key), "new key should authorize");
        assert!(store.authorize("static-1"), "static key should authorize");
        assert!(!store.authorize("nope"));
        drop(store);

        let reloaded = KeyStore::new(vec![], Some(path.clone()));
        assert!(reloaded.authorize(&rec.key), "persisted key should survive reload");
        assert!(!reloaded.authorize("static-1"), "static keys are not persisted");
    }

    #[test]
    fn delete_revokes_and_persists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let store = KeyStore::new(vec![], Some(path.clone()));
        let rec = store.create("x".into());
        assert!(store.authorize(&rec.key));
        assert!(store.delete(&rec.id));
        assert!(!store.authorize(&rec.key), "revoked key must be rejected");
        assert!(!store.delete(&rec.id), "deleting twice returns false");

        // 吊销同样持久化：重载后 key 依然失效
        let reloaded = KeyStore::new(vec![], Some(path.clone()));
        assert!(!reloaded.authorize(&rec.key), "revocation should survive reload");
    }

    #[test]
    fn corrupt_keys_db_ignored() {
        // 文件存在但不是合法 SQLite → 警告并当作空库
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        std::fs::write(&path, "{ not a sqlite database !!!").unwrap();
        let store = KeyStore::new(vec!["static-1".into()], Some(path.clone()));
        assert!(!store.authorize("anything"));
        // 静态 key 不受影响
        assert!(store.authorize("static-1"));
    }

    #[test]
    fn unreadable_keys_db_ignored() {
        // 路径存在但无法打开（是目录）→ 警告并当作空库
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        std::fs::create_dir(&path).unwrap();
        let store = KeyStore::new(vec![], Some(path.clone()));
        assert!(!store.authorize("anything"));
        // 降级为仅内存后，动态 key 仍可用
        let rec = store.create("mem".into());
        assert!(store.authorize(&rec.key));
    }

    #[test]
    fn creates_sqlite_db_and_schema() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let store = KeyStore::new(vec![], Some(path.clone()));
        let rec = store.create("y".into());
        assert!(store.authorize(&rec.key));
        assert_eq!(store.list().len(), 1);
        assert!(path.exists(), "sqlite db file should be created");
        drop(store);
        // 文件确实是 SQLite 格式（magic 头 "SQLite format 3"）
        let head = std::fs::read(&path).unwrap();
        assert_eq!(&head[..16], b"SQLite format 3\x00", "expected sqlite header");
    }
}
