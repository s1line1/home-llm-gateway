//! 隧道帧协议：网关与 edge-agent 之间通过 QUIC 双向流传输的轻量帧。

use bytes::Bytes;
use serde::{Deserialize, Serialize};

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
