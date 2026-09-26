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

/// 非流式响应最多缓冲多少字节（记录 P3-14）：到顶就**停止缓冲**，`resolve_delta` 解析截断的
/// 前缀失败 → 退化成估算并标 `estimated`（不丢数据，只是不再精确）。
///
/// **真实上界 = 本值 − 1 + 单块上限**：守卫在 append **之前**判断，所以跨过边界的那一次
/// 仍会整块追加进来。单块上限是 [`proto::frame::MAX_RESPONSE_CHUNK`]（64 KiB），不是
/// `MAX_FRAME`——agent 侧切块、`forward.rs` 还会拒绝超块（四处 `observe` 全在那个检查之后）。
/// 流式响应**完全不缓冲**，只逐块尝试提取。
const MAX_NON_STREAM_BUFFER: usize = 32 * 1024 * 1024;

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
        }
    }

    /// 每块转发后调用：记录字节、尝试提取 usage。
    pub(super) fn observe(&mut self, chunk: &[u8]) {
        self.bytes_forwarded += chunk.len() as u64;
        if self.is_stream {
            if let Some(d) = crate::usage_meter::extract_usage(chunk) {
                self.extracted = Some(d);
            }
        } else if self.buf.len() < MAX_NON_STREAM_BUFFER {
            // 非流式：整包缓冲（End 后统一解析），避免 JSON 跨块时 usage 被切开。
            // 超上限停止缓冲（防御性；usage 通常尾随，丢失则估算降级）
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
        // 这里**没有**"防重复记录"的守卫：`finish` 按值取 `self`，一个收集器只可能结算一次。
        // 复扫 B4：原先有个 `recorded` 标志（注释写着"防止提前返回路径重复记录"），但它只在
        // 本函数内部被置位、**永不读出**——`finish` 一进来它必然是 `false`，那条分支不可达。
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::KeyStore;
    use proto::frame::MAX_RESPONSE_CHUNK;

    fn collector(is_stream: bool) -> UsageCollector {
        UsageCollector::new(
            KeyStore::new(None),
            "kid".into(),
            "kname".into(),
            7,
            is_stream,
        )
    }

    /// 上界的**期望字面量**：刻意与代码里的常量分开写死。
    ///
    /// 第一版测试直接拿 `MAX_NON_STREAM_BUFFER` 当循环与断言阈值，于是**把常量改成 64MiB
    /// 也照样绿**（测试自己跟着变了，实测如此）——现在写死 + 先断言两者相等，
    /// 任何"悄悄调大上界"的改动都会红。
    const EXPECTED_CAP: usize = 32 * 1024 * 1024;

    /// 规格（记录 P3-14）：**非流式缓冲的真正上界是 `MAX_NON_STREAM_BUFFER` + 一个块**，
    /// 到顶就停止追加，并退化成估算——原记录曾写成"32MiB + 一个 `MAX_FRAME`(64MiB) ≈ 96MiB"，
    /// 那是 R9 之前的世界（那时单块可以到 64MiB）。
    ///
    /// 用比一块略小的**非整除**块灌，才能真的踩到"跨过边界的那一次仍整块进来"这条路径
    /// （整除时正好停在边界上，测不到越过）。
    #[test]
    fn the_non_stream_buffer_stops_one_chunk_after_the_bound() {
        assert_eq!(
            MAX_NON_STREAM_BUFFER, EXPECTED_CAP,
            "非流式缓冲上界被改动：如果是有意的，请同步更新本测试与 P3-14 的记录"
        );
        let mut c = collector(false);
        // 用一个不整除的块大小：灌到 ≥ 上限时，最后一次必然**越过**边界
        let chunk_len = MAX_RESPONSE_CHUNK - 7;
        let chunk = vec![b'a'; chunk_len];
        let mut appends = 0usize;
        while c.buf.len() < EXPECTED_CAP {
            c.observe(&chunk);
            appends += 1;
            assert!(appends < 10_000, "守卫没生效：缓冲一直在涨");
        }

        // ① 越过边界是允许的（守卫在 append 之前判断），但**只能多出一块**
        assert!(
            c.buf.len() > EXPECTED_CAP,
            "构造前提：这一轮应当越过边界，实际 {}",
            c.buf.len()
        );
        assert!(
            c.buf.len() <= EXPECTED_CAP - 1 + chunk_len,
            "上界被突破：{} > {} − 1 + {chunk_len}",
            c.buf.len(),
            EXPECTED_CAP
        );

        // ② 越过之后必须**彻底停止**追加（不是"再涨一点点"）
        let frozen = c.buf.len();
        for _ in 0..4 {
            c.observe(&chunk);
        }
        assert_eq!(c.buf.len(), frozen, "越过上限后不得再缓冲");

        // ③ 截断的前缀解析不出 usage ⇒ 估算降级，且 prompt 用请求侧估算值
        let delta = c.resolve_delta();
        assert!(
            delta.estimated,
            "截断的 JSON 必须走估算降级，而不是谎报精确值"
        );
        assert_eq!(delta.prompt_tokens, 7);
        assert!(delta.completion_tokens >= 1, "估算的 completion 至少 1");

        // ④ 字节计数照旧（估算的输入是"已转发字节"，与是否缓冲无关）
        assert_eq!(
            c.bytes_forwarded,
            (appends * chunk_len) as u64 + 4 * chunk_len as u64
        );
    }

    /// 规格（记录 P3-14 的另一半）：**流式响应完全不缓冲**，只逐块尝试提取。
    ///
    /// 这条顺带钉住"缓冲只对非流式存在"——否则 32MiB 的账会被算到长 SSE 流头上。
    #[test]
    fn a_streaming_response_is_never_buffered_and_still_extracts_usage() {
        let mut c = collector(true);
        c.observe(b"data: {\"choices\":[]}\n\n");
        assert!(c.buf.is_empty(), "流式不得整包缓冲");

        c.observe(b"{\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4}}");
        assert!(c.buf.is_empty(), "流式即使命中 usage 也不缓冲");

        let delta = c.resolve_delta();
        assert!(!delta.estimated, "块里带 usage ⇒ 精确来源");
        assert_eq!((delta.prompt_tokens, delta.completion_tokens), (3, 4));
    }

    /// 对照：非流式**整包在界内**时照旧精确解析（别让上面那条把正常路径一起改坏）。
    #[test]
    fn a_non_stream_body_within_bounds_is_parsed_exactly() {
        let mut c = collector(false);
        // 分两块发，模拟 JSON 跨 chunk（这正是非流式要缓冲的原因）
        c.observe(b"{\"choices\":[],\"usa");
        c.observe(b"ge\":{\"prompt_tokens\":11,\"completion_tokens\":22}}");
        assert!(!c.buf.is_empty(), "界内应当缓冲整包");

        let delta = c.resolve_delta();
        assert!(!delta.estimated, "两块拼起来是合法 JSON ⇒ 精确来源");
        assert_eq!((delta.prompt_tokens, delta.completion_tokens), (11, 22));
    }
}
