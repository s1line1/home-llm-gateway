//! 请求级 usage 记账：从上游响应里提取 token 用量，拿不到就估算并**标记来源**。
//!
//! 为什么它不留在 `proxy/mod.rs` 里：它是一个**有状态的小状态机**（累计已转发字节、
//! 缓冲非流式整包、记录是否已结算），而那个文件是转发编排。原先它住在 `proxy/mod.rs`，
//! 与 `usage_meter.rs` 自称"只含纯函数"、`OPTIMIZATION` 把 proxy 限定为"代理转发"三方
//! 说法互相矛盾——TODO 里登记过这一条。现在它自成一格：策略（何时提取、何时估算、何时结算）
//! 在这里，纯函数在 `usage_meter`，落库在 `storage`。
//!
//! 与 `storage` 的边界是硬性的：这里**只做内存累加**
//! （[`crate::storage::KeyStore::accumulate_usage`]），落库交给周期任务
//! （`usage_flush::spawn`）——SQLite 写可能因锁重试阻塞数秒，而 `finish` 在响应流关闭
//! **之前**执行，等它就会变成客户端的尾延迟。

use crate::storage::UsageDelta;

/// 请求级 usage 收集：SSE 流式逐块预过滤提取；非流式缓冲到 End 后整包解析；
/// 均拿不到 usage（上游未提供 / 取消 / 断流）→ 估算并标记。
pub(super) struct UsageCollector {
    key_store: crate::storage::KeyStore,
    key_id: String,
    key_name: String,
    /// 请求 body 的 prompt 估算（无 usage 时的 prompt 降级）。
    prompt_est: u64,
    /// SSE（content-type: text/event-stream）。
    is_stream: bool,
    /// 已提取的 usage（精确来源；流式多次出现取最后一次）。
    extracted: Option<crate::usage_meter::ExtractedUsage>,
    /// 非流式整包缓冲。
    buf: Vec<u8>,
    /// 已转发字节（估算 completion 用）。
    bytes_forwarded: u64,
    /// 是否已记录（防止提前返回路径重复记录）。
    recorded: bool,
}

impl UsageCollector {
    pub(super) fn new(
        key_store: crate::storage::KeyStore,
        key_id: String,
        key_name: String,
        prompt_est: u64,
        is_stream: bool,
    ) -> Self {
        Self {
            key_store,
            key_id,
            key_name,
            prompt_est,
            is_stream,
            extracted: None,
            buf: Vec::new(),
            bytes_forwarded: 0,
            recorded: false,
        }
    }

    /// 每块转发后调用：记录字节、尝试提取 usage。
    pub(super) fn observe(&mut self, chunk: &[u8]) {
        self.bytes_forwarded += chunk.len() as u64;
        if self.is_stream {
            if let Some(d) = crate::usage_meter::extract_usage(chunk) {
                self.extracted = Some(d);
            }
        } else if self.buf.len() < 32 * 1024 * 1024 {
            // 非流式：整包缓冲（End 后统一解析），避免 JSON 跨块时 usage 被切开。
            // 超 32MiB 停止缓冲（防御性；usage 通常尾随，丢失则估算降级）
            self.buf.extend_from_slice(chunk);
        }
    }

    /// 响应结束（End / 断流 / 超时 / 客户端断开）：结算用量并记录。
    ///
    /// **不得在这里等落库**：SQLite 写可能因锁重试阻塞数秒（rusqlite 默认 busy timeout 5s），
    /// 而本函数在响应流关闭**之前**执行——等它就会变成客户端的尾延迟（实测：DB 被独占锁
    /// 卡住 3s，客户端就要多等 3s 才拿到 body 结束）。所以这里**只做内存累加**
    /// （`/admin/usage` 读的正是这份内存计数，读一致性不受影响），落库交给后台周期任务
    /// （`usage_flush::spawn` → `KeyStore::flush_usage_once`），并由关闭前的强制 flush 兜底。
    ///
    /// 这里曾经是"每请求 spawn 一个阻塞任务写一次库"：那条路径让云端 515 个线程里 514 个
    /// 卡在 futex 等同一把 `db` 锁，把 2 vCPU 的吞吐摁在约 190 QPS。
    pub(super) fn finish(mut self) {
        if self.recorded {
            return;
        }
        self.recorded = true;
        let delta = self.resolve_delta();
        self.key_store
            .accumulate_usage(&self.key_id, &self.key_name, &delta);
    }

    fn resolve_delta(&mut self) -> UsageDelta {
        // 非流式：整包缓冲，End 后统一解析（避免 JSON 跨块切到 usage 字段）
        if !self.is_stream {
            if let Some(d) = crate::usage_meter::extract_usage(&self.buf) {
                self.extracted = Some(d);
            }
        }
        match &self.extracted {
            Some(d) => UsageDelta {
                prompt_tokens: d.prompt_tokens,
                completion_tokens: d.completion_tokens,
                estimated: false,
            },
            None => {
                // 估算降级（标记 estimated）：prompt 按请求体估算；
                // completion 按已转发字节 / 4（取消/断流/无 usage 上游均适用）
                let completion = self.bytes_forwarded.div_ceil(4);
                UsageDelta {
                    prompt_tokens: self.prompt_est,
                    completion_tokens: completion.max(1),
                    estimated: true,
                }
            }
        }
    }
}
