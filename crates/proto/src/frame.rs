//! 隧道帧协议：网关与 edge-agent 之间通过 QUIC 双向流传输的轻量帧。

use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// 单个 [`Frame::ProxyResponseBody`] 允许携带的最大字节数。
///
/// 这是一条**内存边界**，不只是格式约定：网关把这些块交给一条 `mpsc::channel(32)` 再喂给
/// 客户端，而通道是按**条数**有界的。没有这个上限时"32 条"可能是 32 × `MAX_FRAME`（64MiB），
/// 一个慢客户端就足以让网关堆下 GB 级内存（记录 R9）。
///
/// 两侧的分工：**agent 负责切块**（[`take_chunk_piece`]，`Bytes::split_to` 零拷贝），
/// **网关负责拒绝**超标的块（纵深防御：坏 agent 或旧版本不该让这个上界失效）。
pub const MAX_RESPONSE_CHUNK: usize = 64 * 1024;

/// 从 `chunk` 头部切出一片（≤ [`MAX_RESPONSE_CHUNK`]）并把它从 `chunk` 中移除；空块返回 `None`。
///
/// 零拷贝：`Bytes::split_to` 只调整引用计数与偏移，不搬字节。已经足够小的块直接整体交出
/// （常见路径不产生额外分配）。
pub fn take_chunk_piece(chunk: &mut Bytes) -> Option<Bytes> {
    if chunk.is_empty() {
        return None;
    }
    Some(if chunk.len() > MAX_RESPONSE_CHUNK {
        chunk.split_to(MAX_RESPONSE_CHUNK)
    } else {
        std::mem::take(chunk)
    })
}

/// 隧道帧。所有帧经 postcard 序列化，由 [`crate::io::write_frame`] 加上长度前缀。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Frame {
    /// agent → cloud：注册，声明身份与能力。
    Register {
        agent_id: String,
        models: Vec<String>,
        max_concurrency: u32,
        version: String,
    },
    /// 双向：保活 + 健康状态。
    Heartbeat { agent_id: String, inflight: u32 },
    /// cloud → agent：一个 OpenAI 兼容请求。
    ProxyRequest {
        request_id: u64,
        method: String,
        path: String, // 含 query string，如 /v1/chat/completions?x=1
        headers: Vec<(String, String)>,
        /// 请求体。用 [`Bytes`] 而不是 `Vec<u8>`：它实现 `serialize_bytes`，postcard 因此
        /// **一次写整块**；而 `Vec<u8>` 是"元素序列"，会逐字节过一遍序列化器——16MiB 请求体
        /// 实测 **231ms vs ~1ms**，这是 H6 里最大的一笔。克隆是引用计数（重放/重试不再拷
        /// 16MiB），而且线上格式**逐字节不变**（两种编码都是 `varint 长度 + 原始字节`，
        /// 见 `tests::bytes_body_encodes_identically_to_a_plain_vec`）。
        body: Bytes,
    },
    /// agent → cloud：上游响应头。
    ProxyResponseHead {
        request_id: u64,
        status: u16,
        headers: Vec<(String, String)>,
    },
    /// agent → cloud：上游响应体分块（SSE 场景下逐块透传）。
    /// `chunk` 同 [`Frame::ProxyRequest::body`] 的理由用 [`Bytes`]：SSE 每个 chunk 都要过一遍
    /// 序列化，逐元素编码在长流上累积成可观开销，且能从 hyper 一路移动过来不拷贝。
    ProxyResponseBody { request_id: u64, chunk: Bytes },
    /// agent → cloud：响应结束。
    ProxyResponseEnd { request_id: u64, ok: bool },
    /// cloud → agent：客户端断开/超时，要求取消上游请求（避免白算 token）。
    Cancel { request_id: u64 },
    /// 双向：错误。
    Error {
        request_id: Option<u64>,
        code: u16,
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 规格（记录 R9）：响应块**切到 ≤ `MAX_RESPONSE_CHUNK`**，且切片拼回来与原文**逐字节相同**。
    ///
    /// 这条上界是网关侧内存的支点：通道按条数有界（32），所以单块大小决定了"32 条"能占多少内存。
    #[test]
    fn response_chunks_are_split_to_the_byte_bound_without_losing_bytes() {
        for total in [
            0usize,
            1,
            MAX_RESPONSE_CHUNK - 1,
            MAX_RESPONSE_CHUNK, // 恰好一块：不该白切一片
            MAX_RESPONSE_CHUNK + 1,
            MAX_RESPONSE_CHUNK * 3,     // 恰好整数倍
            MAX_RESPONSE_CHUNK * 3 + 7, // 带零头
        ] {
            let original = Bytes::from(vec![b'z'; total]);
            let mut rest = original.clone();
            let mut pieces = Vec::new();
            while let Some(piece) = take_chunk_piece(&mut rest) {
                assert!(
                    piece.len() <= MAX_RESPONSE_CHUNK,
                    "total={total} 时切出了 {} 字节的块（上限 {MAX_RESPONSE_CHUNK}）",
                    piece.len()
                );
                assert!(!piece.is_empty(), "total={total} 时切出了空块");
                pieces.push(piece);
            }
            assert!(rest.is_empty(), "切完之后剩余缓冲必须为空");
            let expected_pieces = total.div_ceil(MAX_RESPONSE_CHUNK);
            assert_eq!(
                pieces.len(),
                expected_pieces,
                "total={total} 的块数应当是 {expected_pieces}"
            );
            let rejoined: Vec<u8> = pieces.iter().flat_map(|p| p.to_vec()).collect();
            assert_eq!(rejoined, original.to_vec(), "total={total} 时字节被改动了");
        }
    }

    /// 规格：空块没有被切出任何东西（调用方据此结束循环）。
    #[test]
    fn an_empty_chunk_yields_no_piece() {
        let mut empty = Bytes::new();
        assert!(take_chunk_piece(&mut empty).is_none());
    }
}
