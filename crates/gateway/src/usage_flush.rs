//! 用量批量落库：周期把各 key 的**绝对累计值**写一次 SQLite。
//!
//! 为什么不是"每请求写一次"：每条用量 UPSERT 都要抢同一把全局 `db` 互斥锁并提交一次
//! 事务，实测把 2 vCPU 的吞吐摁在约 190 QPS —— 云端 515 个线程里 514 个卡在 futex 等锁，
//! 而网关"CPU 吃满 2 核"里很大一部分就是这种争抢与线程池 churn。改成按周期批量写之后，
//! 写库次数从"每请求一次"变成"每周期一次"，且写的是绝对值：幂等、丢不掉、重启不重复累加。
//!
//! 关闭路径：`Gateway::shutdown` 会在进程退出前强制写一次，
//! 所以每次 flush 周期之间崩溃最多丢一个周期的用量，而**正常关闭不丢已结算的用量**
//! （`Gateway::shutdown` 先 flush 再 abort，flush 之后、abort 之前在途请求结算的用量会丢，见 `TODO.md` R12）。
//!
//! 为什么调度在这里而不在 `storage/` 里：`storage` 是**纯同步**的一层（它的目录里没有
//! 一处 `tokio` / `async` / `spawn_blocking`），落库原语 `flush_usage_once` 因此能同时服务
//! 两个调用者——本模块的周期任务（走 `spawn_blocking`，不占 async worker）与关闭时的同步
//! 强制 flush。本模块是**运行时适配层**：它决定"多久写一次、在哪个线程上写"，而
//! `storage` 只管"怎么写"。两者的改动理由不同（节奏 vs 表结构与落库语义），所以分开。

use std::time::Duration;

use crate::storage::KeyStore;

/// flush 周期。取 1s 是权衡：崩溃时最多丢 1s 的用量，而写库频率已经比"每请求一次"
/// 低三个数量级（190 QPS 时是 190 次/秒 → 1 次/秒）。
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);

/// 启动后台 flush 任务。它只在有变化时才真正碰 SQLite（`usage_has_pending`）。
///
/// 任务本身不做阻塞 IO：真正的写库丢到阻塞线程池上跑，避免占住 async worker。
pub fn spawn(store: KeyStore) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if !store.usage_has_pending() {
                continue;
            }
            let store = store.clone();
            match tokio::task::spawn_blocking(move || store.flush_usage_once(false)).await {
                Ok(n) if n > 0 => tracing::debug!(keys = n, "usage flushed"),
                Ok(_) => {}
                Err(e) => tracing::warn!("usage flush task failed: {e}"),
            }
        }
    })
}
