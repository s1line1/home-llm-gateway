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
//! 注意：argon2 校验每次请求约耗时 10-30ms（19MiB 内存、t=2）。家庭网关低 QPS 下
//! 可接受；若需更高吞吐，可调低参数（如 Params::new(4096, 3, 1)）或用登录式缓存。

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

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
        let mut v: Vec<KeyRecord> = self.inner.runtime.read().unwrap().values().cloned().collect();
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

/// 从 SQLite 加载全部动态 key（key = lookup）。
fn load_keys(conn: &Connection) -> rusqlite::Result<HashMap<String, KeyRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, lookup, key_hash, name, created_at, enabled FROM api_keys",
    )?;
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
fn hash_argon2(token: &str) -> String {
    // 盐用项目已有的 getrandom（0.3）生成，避免引入 rand_core 的 getrandom 版本纠缠；
    // 16 字节盐是 argon2 推荐长度。
    let mut salt_bytes = [0u8; 16];
    getrandom::fill(&mut salt_bytes).expect("os rng");
    let salt = SaltString::encode_b64(&salt_bytes).expect("16-byte salt is valid b64");
    Argon2::default()
        .hash_password(token.as_bytes(), &salt)
        .expect("argon2 hashing with default params cannot fail")
        .to_string()
}

/// 校验 token 是否匹配存储的 argon2 哈希（PHC 字符串内嵌参数，未来调参不影响旧记录）。
fn verify_argon2(token: &str, encoded: &str) -> bool {
    let parsed = match PasswordHash::new(encoded) {
        Ok(p) => p,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(token.as_bytes(), &parsed)
        .is_ok()
}

/// 快速索引：sha256(明文 key) 的十六进制。
fn lookup_of(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
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

/// 恒定时间比较，防时序侧信道（仍用于 admin token 比较）。
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
        let store = KeyStore::new(Some(path.clone()));
        let created = store.create("dsh".into());
        assert!(store.authorize(&created.plaintext), "new key should authorize");
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
        assert!(text.contains("$argon2id$"), "argon2 hash should be persisted");
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
        assert!(!store.delete(&created.record.id), "deleting twice returns false");

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
        assert_eq!(&head[..16], b"SQLite format 3\x00", "expected sqlite header");
    }

    #[test]
    fn authorize_rejects_unknown_lookup_without_argon2() {
        // lookup 不在表中直接拒绝，不做无意义的 argon2 计算
        let store = KeyStore::new(None);
        assert!(!store.authorize("sk-not-a-real-key"));
    }
}
