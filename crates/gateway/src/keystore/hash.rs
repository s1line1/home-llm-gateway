//! 密钥哈希原语：argon2 哈希/校验、sha256 lookup 索引、key 生成、常量时间比较。
//! 与存储（KeyStore）分离，便于独立测试与复用。

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn hash_argon2(token: &str) -> String {
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
pub fn verify_argon2(token: &str, encoded: &str) -> bool {
    let parsed = match PasswordHash::new(encoded) {
        Ok(p) => p,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(token.as_bytes(), &parsed)
        .is_ok()
}

/// 快速索引：sha256(明文 key) 的十六进制。
pub fn lookup_of(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn generate_id_key() -> (String, String) {
    let mut id_buf = [0u8; 4];
    let mut key_buf = [0u8; 24];
    getrandom::fill(&mut id_buf).expect("os rng");
    getrandom::fill(&mut key_buf).expect("os rng");
    let id = format!("{:08x}", u32::from_be_bytes(id_buf));
    let key = format!(
        "sk-{}",
        key_buf
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    (id, key)
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 恒定时间比较，防时序侧信道（仍用于 admin token 比较）。
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
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

    #[test]
    fn hash_verify_roundtrip() {
        let hash = hash_argon2("sk-secret");
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_argon2("sk-secret", &hash));
        assert!(!verify_argon2("sk-wrong", &hash));
    }

    #[test]
    fn verify_rejects_malformed_hash() {
        assert!(!verify_argon2("sk-anything", "not-a-phc-hash"));
        assert!(!verify_argon2("sk-anything", ""));
    }

    #[test]
    fn lookup_is_stable_hex() {
        let a = lookup_of("sk-abc");
        let b = lookup_of("sk-abc");
        let c = lookup_of("sk-abd");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.len() == 64, "sha256 hex should be 64 chars");
    }

    #[test]
    fn generate_id_key_format() {
        let (id, key) = generate_id_key();
        assert_eq!(id.len(), 8);
        assert!(key.starts_with("sk-"));
        assert_eq!(key.len(), 3 + 48, "24 random bytes as hex");
        // 两次生成不同
        let (id2, key2) = generate_id_key();
        assert_ne!((id, key), (id2, key2));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
