//! 密钥哈希原语：argon2 哈希/校验、sha256 lookup 索引、key 生成、常量时间比较。
//! 与存储（KeyStore）分离，便于独立测试与复用。

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

#[cfg(test)]
use argon2::{Algorithm, Params, Version};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// 参数：`Argon2::default()` = Argon2id, m=19456 KiB, t=2, p=1（内存硬，19MiB）。
/// 哈希与校验都取 PHC 串里记着的参数，所以只要写入时用的是默认参数就没有兼容问题。
fn hasher() -> Argon2<'static> {
    Argon2::default()
}

/// 测试专用：把**本线程**的 argon2 成本降到最低（v1 版里 m=64KiB, t=1, p=1）。
///
/// 为什么需要：argon2 是内存硬的，debug 下一次约 0.4–0.6s，而缓存相关的测试要刻意
/// 制造多次校验（并发 8 个请求、关闭缓存时逐请求校验），于是光是这些测试就要 8s+。
/// 用线程局部（而不是 `#[cfg(test)]` 全局改参数）是因为有些测试**依赖 argon2 足够慢**——
/// 例如 `http::tests::key_verification_does_not_block_the_runtime` 就是靠"校验期间
/// 别的请求还能跑"来断言的；全局调快会让它变成空转的白盒测试。
///
/// 便宜参数下走的仍是同一条加密路径（argon2id + 真实哈希/校验），只是强度低；
/// 语义（单飞、凭据版本、吊销即时）一条不少地照测。
#[cfg(test)]
pub(crate) struct CheapArgon2;

#[cfg(test)]
thread_local! {
    static CHEAP: std::cell::RefCell<Option<Argon2<'static>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
impl CheapArgon2 {
    /// 安装到**当前线程**；返回的守卫 Drop 时自动还原。
    pub(crate) fn install() -> Self {
        let params = Params::new(64, 1, 1, None).expect("valid test params");
        let cheap = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        CHEAP.with(|c| c.borrow_mut().replace(cheap));
        Self
    }
}

#[cfg(test)]
impl Drop for CheapArgon2 {
    fn drop(&mut self) {
        CHEAP.with(|c| c.borrow_mut().take());
    }
}

/// 取本次调用要用的 hasher：测试线程若装了便宜参数就用它，否则用生产默认参数。
fn argon2_for_call() -> Argon2<'static> {
    #[cfg(test)]
    {
        if let Some(cheap) = CHEAP.with(|c| c.borrow().clone()) {
            return cheap;
        }
    }
    hasher()
}

pub fn hash_argon2(token: &str) -> String {
    // 盐用项目已有的 getrandom（0.3）生成，避免引入 rand_core 的 getrandom 版本纠缠；
    // 16 字节盐是 argon2 推荐长度。
    let mut salt_bytes = [0u8; 16];
    getrandom::fill(&mut salt_bytes).expect("os rng");
    let salt = SaltString::encode_b64(&salt_bytes).expect("16-byte salt is valid b64");
    let _in_flight = Argon2InFlight::enter();
    argon2_for_call()
        .hash_password(token.as_bytes(), &salt)
        .expect("argon2 hashing with default params cannot fail")
        .to_string()
}

/// RAII：标记"一次 argon2 正在运行"。
///
/// 保留它是因为它标出了并发校验的边界（argon2 内存硬，同时在跑几个 = 内存峰值）。
/// **注意不要再用全局计数断言调用次数**：计数器是进程级的，会被同一测试进程里其他
/// 测试的 argon2 调用污染（实测并行跑全量 lib 时，一个只应 1 次的断言被顶到 2 次）。
/// 调用次数改由 `KeyStore` 各实例自己统计（`KeyStore::argon2_runs`）。
#[derive(Default)]
struct Argon2InFlight;

impl Argon2InFlight {
    fn enter() -> Self {
        Self
    }
}

/// 校验 token 是否匹配存储的 argon2 哈希（PHC 字符串内嵌参数，未来调参不影响旧记录）。
pub fn verify_argon2(token: &str, encoded: &str) -> bool {
    let parsed = match PasswordHash::new(encoded) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let _in_flight = Argon2InFlight::enter();
    argon2_for_call()
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

    /// 校验必须**按 PHC 串里记的参数**（而不是编译进二进制的参数）执行。
    ///
    /// 为什么值得单独一条：测试构建把 hasher 换成了便宜参数（m=64KiB）。如果
    /// `verify_argon2` 哪天变成"用编译时参数校验"，那么它仍能在便宜哈希上通过，
    /// 却会让**所有生产参数（m=19456）写下的 key 全部失效**——一个测试全绿、
    /// 上线全崩的失效模式。这里用一份**更高参数**的哈希来证明校验尊重串里的参数。
    #[test]
    fn verify_honours_params_embedded_in_the_hash() {
        let token = "sk-params-probe";
        // 用明显不同于编译时参数（m=1024 vs 64/19456）的参数生成 PHC 串
        let other = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(1024, 1, 1, None).unwrap(),
        );
        let salt = SaltString::encode_b64(b"0123456789abcdef").unwrap();
        let encoded = other
            .hash_password(token.as_bytes(), &salt)
            .unwrap()
            .to_string();
        assert!(
            encoded.contains("m=1024"),
            "前提：PHC 串里确实记着 m=1024，实际 {encoded}"
        );
        assert!(
            verify_argon2(token, &encoded),
            "校验必须尊重 PHC 串里的参数，否则生产 key 会全部失效"
        );
        assert!(!verify_argon2("sk-wrong", &encoded), "错 token 仍须拒绝");
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
