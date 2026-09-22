//! per-API-key token 用量计量：从上游响应提取 `usage`，缺失时估算降级。
//!
//! 数据来源（OpenAI 兼容）：
//! - 非流式：整个响应体是 JSON，`usage` 在顶层（可能跨多个隧道 chunk，
//!   因此非流式请求在网关侧缓冲完整 body 后一次性解析）。
//! - 流式（SSE）：usage 通常在最后一个 `data: {...}` 行；逐块转发时先
//!   `contains("usage")` 预过滤，命中才做行级 JSON 解析（99% chunk 零开销）。
//! - 上游无 usage（如 mock 的 SSE、超时/断流被 Cancel）→ 估算并标记来源。
//!
//! 本模块只含**纯函数**（提取/估算，便于单测）；存储与累加在 storage。

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
    estimate_tokens_from_chars(text.chars().count() as u64)
}

/// 同 [`estimate_tokens`]，但输入已经是字符数。
///
/// 拆出来是为了 H6：请求侧的文本**不再拼成一个 `String` 再数**（16MiB 的 messages 拼一遍
/// 就是一次 16MiB 拷贝），直接累加各段的字符数——字符数在拼接下可加，结果逐字相同。
pub fn estimate_tokens_from_chars(chars: u64) -> u64 {
    chars.div_ceil(4)
}

/// [`request_facts`] 的失败：body 不是合法 JSON，或缺少非空字符串 `model`。
///
/// 两种情况对调用方是同一件事（400 + 同一句文案），所以只有一个变体；但**不用 `()`**——
/// workspace 开着 `clippy::result_unit_err`，而且具名类型让"为什么解析失败"在签名上看得见。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotRoutable;

/// 请求侧解析结果：路由要的 `model` + 无 `usage` 时估算 prompt 的字符数。
pub struct RequestFacts {
    /// 顶层 `model`（OpenAI 兼容语义，必填非空）。
    pub model: String,
    /// `messages[].content` 的字符数（口径见 [`request_facts`]）。
    pub prompt_chars: u64,
}

/// **一次** JSON 遍历同时得到 [`RequestFacts::model`] 与 [`RequestFacts::prompt_chars`]；
/// 非法 JSON / 缺 `model` / `model` 不是非空字符串 → `Err(())`（调用方回 400）。
///
/// （H6）以前是**两遍**全量解析：`proxy::extract_model` 一遍，`estimate_prompt_tokens` 又一遍。
/// 16MiB 合法 body 实测每遍 ~77ms，两遍都压在 async worker 上。现在只有一遍，且不再拼串。
///
/// 估算口径与拆分前逐字一致：只数 `messages[].content`（字符串本身；数组则取各元素的 `text`），
/// 字符数 / 4 向上取整、下限 1（下限由调用方 `max(1)` 施加，与 `resolve_delta` 的 completion
/// 估算同一写法）。非 chat 端点（没有 `messages`）得到 0 字符 → 估算 1，与拆分前相同。
pub fn request_facts(body: &[u8]) -> Result<RequestFacts, NotRoutable> {
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| NotRoutable)?;
    let model = match value.get("model") {
        Some(serde_json::Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return Err(NotRoutable),
    };
    let mut chars = 0u64;
    if let Some(msgs) = value.get("messages").and_then(|v| v.as_array()) {
        for m in msgs {
            if let Some(c) = m.get("content") {
                match c {
                    serde_json::Value::String(s) => chars += s.chars().count() as u64,
                    serde_json::Value::Array(parts) => {
                        for p in parts {
                            if let Some(t) = p.get("text").and_then(|v| v.as_str()) {
                                chars += t.chars().count() as u64;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(RequestFacts {
        model,
        prompt_chars: chars,
    })
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

    /// 规格（H6）：**一次**解析同时给出 model 与 prompt 字符数，口径与拆分前逐字一致。
    ///
    /// 拆分前是 `extract_model` 一遍 + `estimate_prompt_tokens` 一遍（两遍全量解析）；这条把
    /// "同一份 body 只解析一次"变成规格，同时钉住估算口径（含 content 数组里的 `text`、
    /// 非字符串 content 跳过、没有 messages → 0 字符 → 下限 1）。
    #[test]
    fn request_facts_parses_once_and_keeps_the_estimation_semantics() {
        let body = br#"{"model":"m","messages":[{"role":"user","content":"12345678"},{"role":"assistant","content":"abcd"}]}"#;
        let f = request_facts(body).expect("合法 body");
        assert_eq!(f.model, "m");
        assert_eq!(f.prompt_chars, 12, "8 + 4 字符");
        assert_eq!(estimate_tokens_from_chars(f.prompt_chars).max(1), 3, "12/4");

        // content 是"分片数组"：只取各分片的 text（与拆分前的 `p.get("text")` 一致）
        let parts = br#"{"model":"m","messages":[{"content":[{"type":"text","text":"abcdefgh"},{"type":"image_url","image_url":{"url":"x"}}]},{"content":123}]}"#;
        let f = request_facts(parts).expect("合法 body");
        assert_eq!(f.prompt_chars, 8, "只数 text 分片；数字 content 跳过");

        // 非 chat 端点（没有 messages）→ 0 字符 → 调用方 max(1)
        let f = request_facts(br#"{"model":"m","input":"hello"}"#).expect("合法 body");
        assert_eq!(f.prompt_chars, 0);
        assert_eq!(estimate_tokens_from_chars(f.prompt_chars).max(1), 1);

        // 缺 / 空 / 非字符串 model → Err（调用方 400），与拆分前的 extract_model 一致
        assert!(request_facts(br#"{"messages":[]}"#).is_err(), "缺 model");
        assert!(request_facts(br#"{"model":""}"#).is_err(), "空 model");
        assert!(
            request_facts(br#"{"model":123}"#).is_err(),
            "非字符串 model"
        );
        assert!(request_facts(b"not json").is_err(), "非法 JSON");
        // 顶层不是对象也一样（拆分前 `value.get("model")` 拿不到 → Err）
        assert!(request_facts(br#"[1,2,3]"#).is_err());
    }
}
