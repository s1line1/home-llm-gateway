//! HTTP 逐跳头（hop-by-hop）与调用方凭据头的过滤规则（gateway 与 agent 共享）。

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

/// 调用方凭据类头：只在「客户端 ↔ 网关」这一跳有意义，**不得**随隧道帧转发给 edge / 上游。
///
/// 为什么不混进 [`HOP_BY_HOP`]：`authorization` / `cookie` 在 RFC 语义上是**端到端**头，
/// 塞进"逐跳头"那张表会让它的语义自相矛盾、误导后来人。它们是另一条规则，单独一张表。
///
/// 为什么必须拦：客户端持有的是**网关签发**的 API key——对全部模型有效、且能打公网网关；
/// 而 edge 与上游属于另一个信任域，三种上游（Ollama / vLLM / llama.cpp）又都不认证。
/// 透传是零收益、纯风险：edge 一旦被攻破，攻击者白得一把可用的公网凭据；而且 edge 与
/// 上游的日志里会留下一份**吊销不掉**的副本（吊销客户端 key 也救不回来）。
/// 上游确实需要认证时，应在 **agent 侧**配置上游自己的凭据，而不是转发调用方的 key。
pub const CLIENT_CREDENTIAL_HEADERS: &[&str] = &["authorization", "cookie"];

/// 判断 HTTP 头名是否为逐跳头（输入应为小写规范化形式，如 axum/reqwest 的 HeaderName）。
pub fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.contains(&name)
}

/// 判断 HTTP 头名是否为调用方凭据类头（输入应为小写规范化形式）。
pub fn is_client_credential(name: &str) -> bool {
    CLIENT_CREDENTIAL_HEADERS.contains(&name)
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
        // 逐跳头之外的普通头必须透传；凭据类是另一条规则，见下面的测试
        for h in ["content-type", "x-request-id", "accept"] {
            assert!(!is_hop_by_hop(h), "{h} should pass through");
        }
    }

    #[test]
    fn client_credentials_recognized_and_kept_out_of_hop_by_hop() {
        for h in CLIENT_CREDENTIAL_HEADERS {
            assert!(is_client_credential(h), "{h} 应被识别为调用方凭据");
            // 语义上它们是端到端头：两张表必须互不重叠，否则会误导读者
            assert!(
                !is_hop_by_hop(h),
                "{h} 不是逐跳头，不该混进 HOP_BY_HOP（凭据有单独一张表）"
            );
        }
        for h in ["content-type", "accept", "x-request-id", "x-custom-trace"] {
            assert!(!is_client_credential(h), "{h} 不是凭据头");
        }
        for h in HOP_BY_HOP {
            assert!(!is_client_credential(h), "{h} 已在逐跳表里，不该重复列");
        }
    }
}
