pub mod crypto;
pub mod frame;
pub mod headers;
pub mod io;
pub mod pem;

pub use frame::Frame;

/// 隧道 ALPN 标识（自定义协议，不必是真正的 h3）。
pub const ALPN: &[u8] = b"h3";
