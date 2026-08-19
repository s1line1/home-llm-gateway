//! API Key 存储：静态 key（`--api-keys`）+ 运行时动态 key（`--keys-file` 持久化）。
//! 动态 key 通过 Admin API 创建/吊销，立即生效，无需重启网关。

use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct KeyStore {
    inner: Arc<KeyStoreInner>,
}

struct KeyStoreInner {
    /// 静态 key（启动参数 --api-keys），不可运行时修改。
    static_keys: Vec<String>,
    /// 动态 key（Admin API 管理），id → 记录。
    runtime: RwLock<HashMap<String, KeyRecord>>,
    /// 动态 key 持久化文件（None 表示仅内存）。
    file: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRecord {
    pub id: String,
    /// 明文 key（仅创建时返回给调用方；文件里也保存以便校验）。
    pub key: String,
    pub name: String,
    pub created_at: u64,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize)]
struct Persisted {
    keys: Vec<KeyRecord>,
}

impl KeyStore {
    pub fn new(static_keys: Vec<String>, file: Option<PathBuf>) -> Self {
        let runtime = match &file {
            Some(path) if path.exists() => match fs::read_to_string(path) {
                Ok(text) => match serde_json::from_str::<Persisted>(&text) {
                    Ok(p) => p.keys.into_iter().map(|k| (k.id.clone(), k)).collect(),
                    Err(e) => {
                        tracing::warn!("keys file {:?} parse error: {e}; ignoring", path);
                        HashMap::new()
                    }
                },
                Err(e) => {
                    tracing::warn!("keys file {:?} read error: {e}; ignoring", path);
                    HashMap::new()
                }
            },
            _ => HashMap::new(),
        };
        Self {
            inner: Arc::new(KeyStoreInner {
                static_keys,
                runtime: RwLock::new(runtime),
                file,
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
        self.save();
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
            self.save();
        }
        removed
    }

    fn save(&self) {
        let Some(path) = &self.inner.file else {
            return;
        };
        let snapshot = Persisted { keys: self.list() };
        match serde_json::to_string_pretty(&snapshot) {
            Ok(text) => {
                let tmp = path.with_extension("json.tmp");
                if let Err(e) = fs::write(&tmp, text) {
                    tracing::warn!("keys file write failed: {e}");
                    return;
                }
                if let Err(e) = fs::rename(&tmp, path) {
                    tracing::warn!("keys file rename failed: {e}");
                }
            }
            Err(e) => tracing::warn!("keys serialize failed: {e}"),
        }
    }
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
        let path = dir.path().join("keys.json");
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
    fn delete_revokes() {
        let store = KeyStore::new(vec![], None);
        let rec = store.create("x".into());
        assert!(store.authorize(&rec.key));
        assert!(store.delete(&rec.id));
        assert!(!store.authorize(&rec.key), "revoked key must be rejected");
        assert!(!store.delete(&rec.id), "deleting twice returns false");
    }
}
