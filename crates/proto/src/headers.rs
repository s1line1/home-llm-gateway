//! HTTP 逐跳头（hop-by-hop）与调用方凭据头的过滤规则（gateway 与 agent 共享）。

/// 转发时剔除的逐跳头（不得透传到下一跳）。
pub const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    // 非标准头（不在 RFC 的逐跳名单里），但由代理引入、只对单跳有意义。缺了它，请求方向会把
    // 它一路透传给上游、响应方向透传给客户端（复扫 B2）。
    "proxy-connection",
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

/// 判断 HTTP 头名是否为逐跳头。
///
/// **大小写无关**（复扫 B2）：帧里的头名来自对端，除了 `HeaderName` 那种已规范化的形式，还可能
/// 是坏/旧 agent 自己拼的字符串。按原串精确比大小写时，`Content-Length` 只消首字母大写就能
/// 绕过整张表——响应方向会把逐跳头交给客户端，请求方向会把它转给上游。所以调用方不需要、
/// 也不该被要求先规范化；这里统一按 ASCII 大小写无关比较。
pub fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// 判断 HTTP 头名是否为调用方凭据类头。大小写无关，理由同 [`is_hop_by_hop`]。
pub fn is_client_credential(name: &str) -> bool {
    CLIENT_CREDENTIAL_HEADERS
        .iter()
        .any(|h| name.eq_ignore_ascii_case(h))
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

    /// 规格（复扫 B2）：**头名比对必须大小写无关**。
    ///
    /// 帧里的头名来自对端——`HeaderName` 之外还可能是一个**坏/旧 agent 自己拼的字符串**。
    /// 按原串精确比大小写时，`Content-Length` 只消首字母大写就能绕过整张表，把逐跳头
    /// 一路透传给客户端（响应方向）或上游（请求方向）。所以调用方不该、也不能被要求先规范化。
    #[test]
    fn hop_by_hop_matching_ignores_case() {
        for h in HOP_BY_HOP {
            let h: &str = h;
            let mut first_upper = h.to_string();
            first_upper.replace_range(0..1, &h[0..1].to_ascii_uppercase());
            assert!(
                is_hop_by_hop(&first_upper),
                "{first_upper}（首字母大写）必须与 {h} 一样被剔除"
            );
            assert!(
                is_hop_by_hop(&h.to_ascii_uppercase()),
                "{} 全大写也必须被剔除",
                h.to_ascii_uppercase()
            );
        }
        // 对照：大小写无关不等于"全都命中"
        assert!(!is_hop_by_hop("Content-Type"));
        assert!(!is_hop_by_hop("X-Request-Id"));
    }

    /// 复扫 B2：非标准的 `proxy-connection` 也是逐跳语义。
    ///
    /// 它不在 RFC 的逐跳名单里，但由代理引入、只对单跳有意义；缺了它，请求方向会把它
    /// 一路透传给上游，响应方向会透传给客户端。
    #[test]
    fn proxy_connection_is_treated_as_hop_by_hop() {
        assert!(is_hop_by_hop("proxy-connection"));
        assert!(is_hop_by_hop("Proxy-Connection"), "大小写无关");
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
