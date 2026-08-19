//! 按 API Key 的令牌桶限流（无外部依赖）。

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};

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
        let mut inner = self.inner.lock().unwrap();
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
