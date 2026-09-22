//! 按 API Key 的令牌桶限流（无外部依赖）。
//!
//! **桶键是 [`KeyRecord::id`]，不是明文 key**（由 [`crate::auth`] 决定）：明文只该活在
//! 认证那一刻的栈上（keystore 只留 sha256 + argon2），而桶表是**只增不减**的内存状态——
//! 拿明文作键等于把它常驻到进程退出，还会随 key 轮换 / 吊销无上限增长。
//!
//! [`KeyRecord::id`]: crate::storage::KeyRecord

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::sync::lock_or_recover;

/// 空闲桶的存活上限。**满桶与新建桶等价**（补充按需算，满桶再被取用时行为一致），
/// 所以"已回满 + 空闲超时"的桶可以直接丢；10 分钟远大于"回满所需时间"
/// （容量 / 补充速率恒为 60 秒），正在用的 key 碰不到。
const IDLE_BUCKET_TTL: Duration = Duration::from_secs(10 * 60);

/// 清扫周期：取令牌必须 O(1)，所以清扫按时间摊——每 60 秒至多一次全表 `retain`。
const SWEEP_PERIOD: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<Buckets>>,
    /// 桶容量 = 每分钟配额（突发上限）。
    capacity: f64,
    /// 每秒补充的令牌数。
    refill_per_sec: f64,
}

/// 桶表 + 清扫记账。同锁保护：清扫要看到一致的（桶集，上次清扫时刻）。
struct Buckets {
    map: HashMap<String, Bucket>,
    /// 上次清扫时刻（None = 还没扫过）。
    last_sweep: Option<Instant>,
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl Buckets {
    /// 回收"现已回满 + 空闲超时"的桶，返回回收数。
    ///
    /// **只丢满桶**：没回满的桶丢掉等于白送配额。补充是按需算的（只在被取用时才按
    /// `elapsed` 补），所以判据里必须先把令牌补到 `now` 再比，不能只看存下来的 `tokens`
    /// ——后者对空闲桶永远停在"上次用完的样子"，会让所有桶都回收不掉。
    fn sweep(&mut self, now: Instant, idle: Duration, capacity: f64, refill_per_sec: f64) -> usize {
        let before = self.map.len();
        self.map.retain(|_, b| {
            let elapsed = now.duration_since(b.updated);
            let refilled = (b.tokens + elapsed.as_secs_f64() * refill_per_sec).min(capacity);
            elapsed < idle || refilled < capacity
        });
        self.last_sweep = Some(now);
        before - self.map.len()
    }
}

impl RateLimiter {
    /// `per_minute == 0` 表示不限流，返回 None。
    pub fn new(per_minute: u32) -> Option<Self> {
        if per_minute == 0 {
            return None;
        }
        Some(Self {
            inner: Arc::new(Mutex::new(Buckets {
                map: HashMap::new(),
                last_sweep: None,
            })),
            capacity: per_minute as f64,
            refill_per_sec: per_minute as f64 / 60.0,
        })
    }

    /// 尝试取一个令牌；成功返回 true，超限返回 false。
    pub fn try_acquire(&self, key: &str) -> bool {
        // 走 crate 统一的加锁方式（`sync.rs:15`）：桶锁中毒不该让此后每个带 key 的请求都
        // panic——锁里只是桶表，守卫内 panic 不会让它非法。
        let mut inner = lock_or_recover(&self.inner);
        let now = Instant::now();
        let bucket = inner.map.entry(key.to_string()).or_insert_with(|| Bucket {
            tokens: self.capacity,
            updated: now,
        });
        let elapsed = now.duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.updated = now;
        let allowed = bucket.tokens >= 1.0;
        if allowed {
            bucket.tokens -= 1.0;
        }
        // 空闲桶（吊销 / 轮换后再没人用的 key）不能永远占着内存。当前这个桶刚被 `updated`，
        // 不会被这次清扫丢掉。
        if inner
            .last_sweep
            .is_none_or(|t| now.duration_since(t) >= SWEEP_PERIOD)
        {
            inner.sweep(now, IDLE_BUCKET_TTL, self.capacity, self.refill_per_sec);
        }
        allowed
    }

    /// 丢掉某个 key 的桶，返回是否确有桶被丢掉。
    ///
    /// 吊销时显式调用（[`crate::admin::delete_key`]）：不等空闲清扫，立即回收。
    pub(crate) fn evict(&self, key: &str) -> bool {
        lock_or_recover(&self.inner).map.remove(key).is_some()
    }

    /// 按 `idle` 判据清扫一次，返回回收数（生产走 [`IDLE_BUCKET_TTL`]）。
    ///
    /// `#[cfg(test)]`：`try_acquire` 是**持锁内**直接调 [`Buckets::sweep`]（std 的锁不可重入），
    /// 这个自带加锁的入口只在测试里用——清扫判据（"只丢已回满 + 空闲"的桶）靠它才测得动。
    #[cfg(test)]
    fn sweep_idle(&self, idle: Duration) -> usize {
        let mut inner = lock_or_recover(&self.inner);
        let (capacity, refill) = (self.capacity, self.refill_per_sec);
        inner.sweep(Instant::now(), idle, capacity, refill)
    }
}

/// 测试专用的观测面：桶键 / 桶数是**内部状态**，生产代码不该看见。
///
/// `pub(crate)` 而不是私有，是因为要断言的规格在**调用方**（`auth.rs`：桶键必须来自
/// `key_id` 而非明文 token）——私有的话那条断言只能退化成"读源码"。
#[cfg(test)]
impl RateLimiter {
    /// 当前所有桶的键（顺序不定）。
    pub(crate) fn bucket_keys(&self) -> Vec<String> {
        lock_or_recover(&self.inner).map.keys().cloned().collect()
    }

    /// 当前桶数。
    pub(crate) fn bucket_count(&self) -> usize {
        lock_or_recover(&self.inner).map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::RateLimiter;
    use std::time::Duration;

    /// 规格（并集评估 §7 步骤 2 / `sync.rs:15`）：**桶锁中毒后仍要能限流**。
    ///
    /// 锁里只是一张桶表（`Buckets`：HashMap + 上次清扫时刻），守卫内 panic 不会让它变成
    /// 非法状态；而 `.lock().unwrap()` 会把一次 panic 放大成**永久**故障：`auth.rs` 的每个
    /// 带 key 请求都会在 `try_acquire` panic（401/429 都发不出，只能重启）。这是全 crate
    /// 最后一处未走 `sync::*_or_recover` 的生产加锁点——三份独立样本都命中了它。
    #[test]
    fn a_poisoned_bucket_lock_still_limits() {
        let rl = RateLimiter::new(1).expect("per_minute=1 应当建出限流器");
        assert!(rl.try_acquire("k"), "前提：第一次取令牌应当放行");

        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = rl.inner.lock().unwrap();
            panic!("poison the bucket map");
        }));
        assert!(poisoned.is_err(), "前提：panic 发生了");
        assert!(rl.inner.is_poisoned(), "前提：锁中毒了");

        // 中毒之后仍按配额判：容量 1、刚用掉一个令牌（补充速率 1/60 每秒，不会在测试内补满）
        assert!(
            !rl.try_acquire("k"),
            "中毒后仍应按配额拒绝；panic 就意味着此后每个带 key 的请求都 500"
        );
    }

    /// 特性（P2-19）：令牌**随时间补充**——这次改动动了桶的键与生命周期，这条钉住
    /// "限的是速率，不是总量"。容量 600（10 令牌/秒）：抽干 → 空闲 250ms → 又放行。
    #[test]
    fn tokens_refill_over_time_and_the_bucket_is_not_a_lifetime_quota() {
        let rl = RateLimiter::new(600).expect("per_minute=600 应当建出限流器");

        // 抽干到第一次拒绝为止（下限断言只保方向性，不受调度抖动影响）。
        let mut taken = 0;
        while rl.try_acquire("k") {
            taken += 1;
        }
        assert!(taken >= 599, "应当先放行接近整个容量（实际 {taken}）");

        std::thread::sleep(Duration::from_millis(250));
        assert!(
            rl.try_acquire("k"),
            "空闲 250ms × 10 令牌/秒 应当补出令牌：限的是速率，不是总量"
        );
    }

    /// 特性（P2-19）：限流是 **per-key** 的——一个 key 抽干不影响另一个。
    #[test]
    fn buckets_are_isolated_per_key() {
        let rl = RateLimiter::new(2).expect("per_minute=2 应当建出限流器");

        assert!(rl.try_acquire("id-a"));
        assert!(rl.try_acquire("id-a"));
        assert!(!rl.try_acquire("id-a"), "id-a 抽干了");

        assert!(rl.try_acquire("id-b"), "id-b 的桶应当不受 id-a 影响");
        assert!(rl.try_acquire("id-b"));
        assert!(!rl.try_acquire("id-b"));

        assert!(!rl.try_acquire("id-a"), "反之亦然：id-b 抽干也不影响 id-a");
        assert_eq!(rl.bucket_count(), 2, "两个 key 两个桶");
    }

    /// 规格（P2-19）：吊销时**立即**回收桶，不等空闲清扫。
    #[test]
    fn evict_drops_the_bucket_of_a_revoked_key() {
        let rl = RateLimiter::new(1).expect("per_minute=1 应当建出限流器");
        assert!(rl.try_acquire("gone"));
        assert!(!rl.try_acquire("gone"), "前提：配额已用完");
        assert_eq!(rl.bucket_count(), 1);

        assert!(rl.evict("gone"), "有桶时应当报告回收了");
        assert_eq!(rl.bucket_count(), 0);
        assert!(!rl.evict("gone"), "没有桶时应当报告没回收（可重复调用）");

        assert!(rl.try_acquire("gone"), "回收后是全新的桶：容量重新满");
    }

    /// 规格（P2-19）：清扫**只丢"已回满 + 空闲超时"的桶**。
    ///
    /// 丢掉没回满的桶等于白送配额——这是这条清扫唯一的风险点，两个条件缺一不可。
    #[test]
    fn sweep_reclaims_only_full_and_idle_buckets() {
        // ① 没回满：无论空闲多久都不丢。1 令牌/秒的档位让"还没回满"有 1 秒余量，
        //    不受调度抖动影响。
        let slow = RateLimiter::new(60).expect("per_minute=60 应当建出限流器");
        assert!(slow.try_acquire("k"), "前提：建出一个 59/60 的桶");
        assert_eq!(slow.sweep_idle(Duration::ZERO), 0, "未回满的桶不得回收");
        assert_eq!(
            slow.sweep_idle(Duration::from_secs(3600)),
            0,
            "未回满的桶即使空闲一小时也不得回收"
        );
        assert_eq!(slow.bucket_count(), 1);

        // ②③ 回满的判据：10 令牌/秒的档位，250ms 足够补满那 1 个令牌。
        let fast = RateLimiter::new(600).expect("per_minute=600 应当建出限流器");
        assert!(fast.try_acquire("k"), "前提：建出一个 599/600 的桶");
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(
            fast.sweep_idle(Duration::from_secs(3600)),
            0,
            "已回满但未到空闲阈值，不得回收"
        );
        assert_eq!(fast.sweep_idle(Duration::ZERO), 1, "回满且空闲的桶应当回收");
        assert_eq!(fast.bucket_count(), 0);
    }
}
