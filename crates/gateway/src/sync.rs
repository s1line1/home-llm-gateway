//! 加锁的统一入口：**忽略中毒**。
//!
//! 本 crate 的锁里装的都是内存映射——计数器、索引表、槽位表、`Option<Connection>`——
//! 守卫内 panic 不会把它们变成非法状态，继续用是安全的；而 `.lock().unwrap()` 会把
//! **一次** panic 放大成永久的局部或全站故障（评估 §5 H4）：
//!
//! - `storage` 的 `runtime` 中毒 ⇒ 之后每个 `/v1/*` 都 500；
//! - `registry` 的表中毒 ⇒ 注册/选路/准入永久失败，进程活着但全站 503；
//! - `metrics` 的 `status_counts` 等中毒 ⇒ `/metrics` 永久 500，**恰恰是排障时最需要它的时刻**；
//! - `storage` 的 `inflight` 中毒 ⇒ 那把 key 的单飞槽永久卡死。
//!
//! 触发链不必是"某段代码写错"：守卫内任何一次 panic（越界、`unwrap`、断言、第三方库）
//! 都会让那把锁永久中毒，所以这里是**兜底**，不是给某段代码开脱。
//!
//! 这三个函数是**唯一允许的加锁方式**：新代码走这里，别再写 `.lock().unwrap()`。
//! （测试里为了**制造**中毒而故意 `.lock().unwrap()` 的地方当然例外。）

use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// 加锁并忽略中毒（取值方式：`unwrap_or_else(|e| e.into_inner())`）。
pub(crate) fn lock_or_recover<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// 同 [`lock_or_recover`]，用于 `RwLock` 的读侧。
pub(crate) fn read_or_recover<T>(l: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|e| e.into_inner())
}

/// 同 [`lock_or_recover`]，用于 `RwLock` 的写侧。
pub(crate) fn write_or_recover<T>(l: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(|e| e.into_inner())
}
