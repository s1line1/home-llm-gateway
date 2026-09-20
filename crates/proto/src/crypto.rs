//! rustls 进程级 CryptoProvider 的**唯一**安装点。
//!
//! **为什么必须显式安装**：本 workspace 同时链接了两个 rustls provider——ring（rustls /
//! tokio-rustls / hyper-rustls）与 aws-lc-rs（`s2n-quic-rustls` 的 Cargo.toml 硬开，
//! 我们这边关不掉）。rustls 0.23 在"两个 provider 同时可用"时无法自动选择，任何
//! `ServerConfig::builder()` / `ClientConfig::builder()` 都会 panic：
//! "Could not automatically determine the process-level CryptoProvider from Rustls crate features"。
//!
//! 以前这个安装散在 12 个调用点（两个二进制的启动路径、两个 tls 构造函数、测试 helper、
//! examples），每一处都写着"你必须先装"。而 `gateway/src/tls.rs` 里那条注释正好记录了
//! 这种冗余的代价：`cargo test` 下同进程总有别的测试先装（所以一直没暴露），
//! nextest 每条测试一个进程就崩。现在只有这一个入口，且幂等。
//!
//! 用法：**任何会构建 rustls 配置的代码路径**都调用 [`provider`]。本仓库的
//! `gateway::tls` / `agent::tls` 构造函数已经自己调用它，所以正常路径不需要显式调用；
//! 只有绕过这些构造函数、直接 `rustls::…Config::builder()` 的地方（测试 helper、examples）
//! 需要自己调一次。

use std::sync::OnceLock;

/// 「本进程已有一个 rustls `CryptoProvider`」的凭证。
///
/// 私有元组字段 ⇒ 只有本模块能构造它；没有 `Default`/`Clone`/`From`。拿得到它，
/// 就证明 [`provider`] 已经跑过。
#[derive(Debug)]
pub struct Installed(Origin);

/// 拿到凭证时实际发生了什么（只为日志与测试）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// 本次调用装上了 ring。
    InstalledRing,
    /// 已经有人装过了（别的调用点、同一个测试进程里的别的测试）。
    AlreadyInstalled,
}

impl Installed {
    pub fn origin(&self) -> Origin {
        self.0
    }
}

/// 确保本进程装有 rustls provider，并返回凭证。**幂等**，可在任何位置调用。
///
/// 刻意**不加** `#[must_use]`：它的价值在副作用，而"忘了调用"的后果是调用点自己
/// 构建 rustls 配置时**直接 panic**（nextest 每条测试一个进程，藏不住），
/// 不需要靠 lint 兜底；加了反而逼着十几个调用点写成 `let _ = …`，噪音大于收益。
///
/// rustls 0.23 的 `CryptoProvider` 没有 `name` 字段，所以"已被别人装过"时只能报"有"，
/// 报不出是哪一家——这对我们够用：任何 provider 都能满足 `Config::builder()`。
pub fn provider() -> &'static Installed {
    static INSTALLED: OnceLock<Installed> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        Installed(
            match rustls::crypto::ring::default_provider().install_default() {
                Ok(()) => Origin::InstalledRing,
                // 每进程最多成功一次；失败说明别人已经装好了，这正是我们想要的状态。
                Err(_existing) => Origin::AlreadyInstalled,
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 幂等：第二次调用拿到的是同一个凭证，且报 AlreadyInstalled。
    #[test]
    fn provider_is_idempotent() {
        let first = provider();
        let second = provider();
        assert!(std::ptr::eq(first, second), "应当返回同一个凭证");
        assert_eq!(first.origin(), second.origin());
        assert_eq!(
            first.origin(),
            Origin::InstalledRing,
            "本测试进程里应是首次安装"
        );
        // 装完之后 rustls 侧必须能取到默认 provider，否则 builder 仍会 panic。
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }
}
