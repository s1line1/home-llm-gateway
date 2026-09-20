//! per-API-key token 用量计量：从上游响应提取 `usage`，缺失时估算降级。
//!
//! 数据来源（OpenAI 兼容）：
//! - 非流式：整个响应体是 JSON，`usage` 在顶层（可能跨多个隧道 chunk，
//!   因此非流式请求在网关侧缓冲完整 body 后一次性解析）。
//! - 流式（SSE）：usage 通常在最后一个 `data: {...}` 行；逐块转发时先
//!   `contains("usage")` 预过滤，命中才做行级 JSON 解析（99% chunk 零开销）。
//! - 上游无 usage（如 mock 的 SSE、超时/断流被 Cancel）→ 估算并标记来源。
//!
//! 本模块只含**纯函数**（提取/估算，便于单测）；存储与累加在 keystore。

/// 从上游响应提取到的用量（精确来源，非估算）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExtractedUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

/// 从**单个 JSON 对象**提取 usage（非流式整块 / SSE data 行的 payload）。
fn usage_from_json(value: &serde_json::Value) -> Option<ExtractedUsage> {
    let u = value.get("usage")?;
    let prompt = u.get("prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
    let completion = u
        .get("completion_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    // 两者都缺（或都为 0 且无 total）→ 视为没有可用 usage，交给估算
    if u.get("prompt_tokens").is_none() && u.get("completion_tokens").is_none() {
        return None;
    }
    Some(ExtractedUsage {
        prompt_tokens: prompt,
        completion_tokens: completion,
    })
}

/// 尝试把整块字节当作 JSON 解析并提取 usage（覆盖单块完整的非流式响应）。
fn try_whole_json(chunk: &[u8]) -> Option<ExtractedUsage> {
    let value: serde_json::Value = serde_json::from_slice(chunk).ok()?;
    usage_from_json(&value)
}

/// 从 SSE 文本块中找含 usage 的 `data:` 行并提取（流式最后一个 chunk）。
fn try_sse_lines(chunk: &[u8]) -> Option<ExtractedUsage> {
    let text = String::from_utf8_lossy(chunk);
    for line in text.lines() {
        let line = line.trim();
        if !line.contains("usage") {
            continue;
        }
        let payload = match line.strip_prefix("data:") {
            Some(p) => p.trim(),
            None => continue,
        };
        if payload == "[DONE]" {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) {
            if let Some(d) = usage_from_json(&value) {
                return Some(d);
            }
        }
    }
    None
}

/// 从一段隧道转发字节提取 usage。
/// 先做 `contains("usage")` 预过滤（快路径，绝大多数 chunk 不含 usage 直接返回 None），
/// 命中再尝试整块 JSON 或 SSE 行级解析。
pub fn extract_usage(chunk: &[u8]) -> Option<ExtractedUsage> {
    if !chunk.windows(7).any(|w| w == b"\"usage\"") {
        return None;
    }
    try_whole_json(chunk).or_else(|| try_sse_lines(chunk))
}

/// 估算 token 数：文本字符数 / 4（OpenAI 的粗粒度近似；中文按字符计，
/// 仍会低估——仅作无 usage 时的降级，标记 estimated 供审计区分）。
pub fn estimate_tokens(text: &str) -> u64 {
    (text.chars().count() as u64).div_ceil(4)
}

/// 估算请求侧 prompt：从请求体抽 messages 文本（content 拼接）后估算。
/// 无法解析（如非 chat 端点 / 非法 JSON）→ 按整个 body 文本估算。
pub fn estimate_prompt_tokens(body: &[u8]) -> u64 {
    let text = match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(value) => {
            let mut out = String::new();
            if let Some(msgs) = value.get("messages").and_then(|v| v.as_array()) {
                for m in msgs {
                    if let Some(c) = m.get("content") {
                        match c {
                            serde_json::Value::String(s) => out.push_str(s),
                            serde_json::Value::Array(parts) => {
                                for p in parts {
                                    if let Some(t) = p.get("text").and_then(|v| v.as_str()) {
                                        out.push_str(t);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            out
        }
        Err(_) => String::from_utf8_lossy(body).into_owned(),
    };
    estimate_tokens(&text).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_usage_from_single_chunk_json() {
        let body = br#"{"id":"x","choices":[],"usage":{"prompt_tokens":12,"completion_tokens":34,"total_tokens":46}}"#;
        let d = extract_usage(body).expect("usage in whole-chunk JSON");
        assert_eq!(d.prompt_tokens, 12);
        assert_eq!(d.completion_tokens, 34);
    }

    #[test]
    fn ignores_chunks_without_usage_key() {
        // 99% 的 SSE 块不含 usage → 预过滤直接 None（零解析开销）
        let chunk = b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
        assert!(extract_usage(chunk).is_none());
        // 普通非流式 JSON 但无 usage
        let no_usage = br#"{"id":"x","choices":[]}"#;
        assert!(extract_usage(no_usage).is_none());
    }

    #[test]
    fn extracts_usage_from_sse_data_line() {
        let chunk = b"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":7}}\n\ndata: [DONE]\n\n";
        let d = extract_usage(chunk).expect("usage in SSE data line");
        assert_eq!(d.prompt_tokens, 5);
        assert_eq!(d.completion_tokens, 7);
    }

    #[test]
    fn usage_missing_tokens_falls_back_to_none() {
        // usage 对象存在但既无 prompt 也无 completion → 交给估算
        let body = br#"{"usage":{"total_tokens":9}}"#;
        assert!(extract_usage(body).is_none());
        // usage 为 null / 非对象
        let body2 = br#"{"usage":null}"#;
        assert!(extract_usage(body2).is_none());
    }

    #[test]
    fn estimate_prompt_from_messages() {
        let body = br#"{"model":"m","messages":[{"role":"user","content":"12345678"},{"role":"assistant","content":"abcd"}]}"#;
        // 12 字符 → 12/4 = 3
        assert_eq!(estimate_prompt_tokens(body), 3);
        // 非法 JSON → 按 body 文本估算（>0）
        assert!(estimate_prompt_tokens(b"not json") >= 1);
    }
}
