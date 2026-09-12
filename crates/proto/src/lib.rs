pub mod frame;
pub mod headers;
pub mod io;
pub mod pem;

pub use frame::Frame;

/// 隧道 ALPN 标识（自定义协议，不必是真正的 h3）。
pub const ALPN: &[u8] = b"h3";

/// 安装进程级 rustls CryptoProvider（ring）。
///
/// **为什么必须显式安装**：本 workspace 同时链接了两个 rustls provider——ring（quinn /
/// tokio-rustls / 本仓库的 rustls 依赖）与 aws-lc-rs（`s2n-quic-rustls` 的 rustls feature，
/// 该 crate 的 Cargo.toml 硬开）。rustls 0.23 在"两个 provider 同时可用"时无法自动选择，
/// 任何 `ServerConfig::builder()` / `ClientConfig::builder()` 都会 panic：
/// "Could not automatically determine the process-level CryptoProvider from Rustls crate features"。
/// 显式安装一次即可（幂等：重复调用返回 Err，忽略）。
///
/// 调用点：两个二进制的启动路径，以及任何**绕过** `gateway::tls` / `agent::tls` 构造函数、
/// 自己直接 `rustls::…Config::builder()` 的地方（目前只有测试 helper）。
pub fn install_ring_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
