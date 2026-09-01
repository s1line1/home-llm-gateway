//! HTTP 逐跳头（hop-by-hop）过滤（gateway 与 agent 共享）。

/// 转发时剔除的逐跳头（不得透传到下一跳）。
pub const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

/// 判断 HTTP 头名是否为逐跳头（输入应为小写规范化形式，如 axum/reqwest 的 HeaderName）。
pub fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_known_hop_by_hop() {
        for h in HOP_BY_HOP {
            assert!(is_hop_by_hop(h), "{h} should be filtered");
        }
    }

    #[test]
    fn keeps_end_to_end_headers() {
        for h in ["content-type", "authorization", "x-request-id", "accept"] {
            assert!(!is_hop_by_hop(h), "{h} should pass through");
        }
    }
}
