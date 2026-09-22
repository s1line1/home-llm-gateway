//! 上游路径的安全转发规则（gateway 与 agent 共享）。
//!
//! 为什么共享：这是**同一条判据的两道防线**——网关在转发前拒绝（客户端拿 `400`），agent 在
//! 拼上游 URL 前再拒绝一次（隧道另一端的输入不再受信时兜底）。两份实现会漂移，而漂移的方向
//! 恰好会是"agent 那道更松"，等于纵深防御静默失效。与 [`crate::headers`] 的两张过滤表同理。
//!
//! 判据是**保守拒绝**，而不是"归一后转发"：归一等于替客户端改写语义，而且拦不住
//! `%2e%2e` / `%2f` 这类**由上游解码**的形态（URL 归一不解码百分号编码，上游却可能解码）。

/// 入站路径是否可以**原样转发给上游**；不安全 → `None`（调用方拒绝该请求）。
///
/// 为什么必须自己判：`uri.path()` 是**原样**的（HTTP/1.1 与 h2 都不做点段归一），而它会被
/// 拼到上游 base 之后才交给 URL 解析器——WHATWG 归一的那一刻，`/v1/../api/delete` 就变成
/// `/api/delete`。**持 key 者因此能驱动上游任意端点**（Ollama 的 `/api/delete` 直接删模型，
/// 而 agent 的上游通常在同一台机器上），`PROJECT_SCAN` P1-2 记录了这条；修复前 e2e 实测网关
/// 确实把该路径转发了出去（上游回 404，因为归一后是它不认识的 `/api/delete`）。
///
/// 拒绝：不以 `/v1/` 开头、任一段为空 / `.` / `..`、路径含 `\`（WHATWG 在 http 下把 `\`
/// 当 `/`）或 `%2e`/`%2f`/`%5c`（大小写不敏感）。
///
/// 只判**路径**、不判 query：点段放不进 query，而 query 里合法地出现 `%2e` 是可能的——
/// 调用方必须先把 query 切掉（见 agent 侧 `upstream_url`），否则会比网关更严、拒掉合法请求。
pub fn safe_upstream_path(path: &str) -> Option<&str> {
    if !path.starts_with("/v1/") {
        return None;
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains('\\')
        || lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return None;
    }
    if path
        .split('/')
        .skip(1)
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return None;
    }
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 规格（`PROJECT_SCAN` P1-2）：只有"原样转发不会越权"的路径才放行。
    ///
    /// 拒绝面比"含 `..`"宽：`%2e`/`%2f`/`%5c` 由上游解码才成点段/分隔符，`\` 在 WHATWG
    /// 的 http 下本身就被当成 `/`——这几种都能构造出同一类越权，所以一起拒。
    #[test]
    fn safe_upstream_path_allows_only_verbatim_forwardable_paths() {
        for ok in [
            "/v1/chat/completions",
            "/v1/models",
            "/v1/embeddings",
            "/v1/a/b-c_d.e",
            "/v1/..hidden", // 以点开头但不是点段
        ] {
            assert_eq!(safe_upstream_path(ok), Some(ok), "{ok} 应当放行");
        }
        for bad in [
            "/v1/../api/delete", // e2e 里实测被转发过的 PoC
            "/v1/../../etc/passwd",
            "/v1/./models",
            "/v1//models",
            "/v1/",
            "/v1",          // 不在 `/v1/` 之下（前缀判定）
            "/api/delete",  // 越出 `/v1/`
            "/v2/chat",     // 邻近前缀不算
            "/v1/%2e%2e/x", // 上游解码后是 `..`
            "/v1/%2E%2E/x", // 大小写
            "/v1/%2fapi",   // 上游解码后是分隔符
            "/v1/a%5Cb",    // 编码的反斜杠
            "/v1/a\\..\\b", // WHATWG 在 http 下把 `\` 当 `/`
        ] {
            assert!(safe_upstream_path(bad).is_none(), "{bad} 必须被拒");
        }
    }
}
