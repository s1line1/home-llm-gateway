//! 隧道帧协议：网关与家端 agent 之间通过 QUIC 双向流传输的轻量帧。

use serde::{Deserialize, Serialize};

/// 隧道帧。所有帧经 postcard 序列化，由 [`io::write_frame`] 加上长度前缀。
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
    Heartbeat {
        agent_id: String,
        inflight: u32,
    },
    /// cloud → agent：一个 OpenAI 兼容请求。
    ProxyRequest {
        request_id: u64,
        method: String,
        path: String, // 含 query string，如 /v1/chat/completions?x=1
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// agent → cloud：上游响应头。
    ProxyResponseHead {
        request_id: u64,
        status: u16,
        headers: Vec<(String, String)>,
    },
    /// agent → cloud：上游响应体分块（SSE 场景下逐块透传）。
    ProxyResponseBody {
        request_id: u64,
        chunk: Vec<u8>,
    },
    /// agent → cloud：响应结束。
    ProxyResponseEnd {
        request_id: u64,
        ok: bool,
    },
    /// cloud → agent：客户端断开/超时，要求取消上游请求（避免白算 token）。
    Cancel {
        request_id: u64,
    },
    /// 双向：错误。
    Error {
        request_id: Option<u64>,
        code: u16,
        message: String,
    },
}
