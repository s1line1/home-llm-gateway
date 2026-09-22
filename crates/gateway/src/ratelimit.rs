//! 按 API Key 的令牌桶限流（无外部依赖）。

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};

use crate::sync::lock_or_recover;

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, Bucket>>>,
    /// 桶容量 = 每分钟配额（突发上限）。
    capacity: f64,
    /// 每秒补充的令牌数。
    refill_per_sec: f64,
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl RateLimiter {
    /// `per_minute == 0` 表示不限流，返回 None。
    pub fn new(per_minute: u32) -> Option<Self> {
        if per_minute == 0 {
            return None;
        }
        Some(Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            capacity: per_minute as f64,
            refill_per_sec: per_minute as f64 / 60.0,
        })
    }

    /// 尝试取一个令牌；成功返回 true，超限返回 false。
    pub fn try_acquire(&self, key: &str) -> bool {
        // 走 crate 统一的加锁方式（`sync.rs:15`）：桶锁中毒不该让此后每个带 key 的请求都
        // panic——锁里只是 HashMap，守卫内 panic 不会让它非法。
        let mut inner = lock_or_recover(&self.inner);
        let now = Instant::now();
        let bucket = inner.entry(key.to_string()).or_insert_with(|| Bucket {
            tokens: self.capacity,
            updated: now,
        });
        let elapsed = now.duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.updated = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RateLimiter;

    /// 规格（并集评估 §7 步骤 2 / `sync.rs:15`）：**桶锁中毒后仍要能限流**。
    ///
    /// 锁里只是 `HashMap<String, Bucket>`，守卫内 panic 不会让它变成非法状态；而
    /// `.lock().unwrap()` 会把一次 panic 放大成**永久**故障：`auth.rs` 的每个带 key 请求
    /// 都会在 `try_acquire` panic（401/429 都发不出，只能重启）。这是全 crate 最后一处
    /// 未走 `sync::*_or_recover` 的生产加锁点——三份独立样本都命中了它。
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
}
