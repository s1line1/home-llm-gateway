pub mod crypto;
pub mod frame;
pub mod headers;
pub mod io;
pub mod path;
pub mod pem;

pub use frame::Frame;

/// 隧道 ALPN 标识。
///
/// **这是一个借来的标签，不是 HTTP/3**（P3-1，2026-09-23 决定：先保留、迁移方案待定，登记在
/// `TODO.md`）：隧道跑的是自定义帧协议（`[u32 BE 长度][postcard]`）在裸 QUIC 上，项目里既没有
/// H3 客户端也没有 `h3` crate，所以这个名字**不给任何客户端带来兼容性**——代价只是"按 ALPN 判
/// 协议"的工具/中间盒/监控会把本端口认成 HTTP/3（真正的 H3 客户端还会被隧道 mTLS 挡在握手之外）。
///
/// 改名不是换一个字符串就完事：rustls 对 **QUIC** 走严格 ALPN（RFC 9001：协商不出应用协议即
/// 连接错误，`rustls/src/server/hs.rs` 里直接引了这条），只要任一端配置/提供了 ALPN 而最终没能
/// 协商出协议，握手就失败——所以"改名"与"干脆不设 ALPN"都会让新旧网关/agent **不能混跑**。
/// 真要改，得走三步重叠：① agent 先同时报 `[新值, h3]` ② 网关再同时广告两者 ③ 全部升完后删掉 `h3`。
pub const ALPN: &[u8] = b"h3";
