//! rustls 进程级 CryptoProvider 的**唯一**安装点（provider 是 **aws-lc-rs**）。
//!
//! **为什么还要显式安装**（2026-09-27 起：workspace 里 ring 已彻底移除，`cargo tree -i ring`
//! 为空，provider 只剩 aws-lc-rs 一个）：
//!
//! 1. **reqwest 要求它**。`reqwest` 用的是 `rustls-tls-webpki-roots-no-provider`（它自己的
//!    `rustls-tls` 会拉 `__rustls-ring`，即把 ring 重新拉回树里，所以刻意不用）；这个变体在
//!    构建客户端时是 `rustls::crypto::CryptoProvider::get_default()` **否则 panic
//!    "No provider set"**（vendored `reqwest-0.12.28/src/async_impl/client.rs:763-770`：有 ring
//!    feature 时它会退回 `ring::default_provider()`，没有就直接 panic）。**它不会**走 rustls
//!    的"按 crate feature 自动选择"那条路。
//! 2. **不该依赖调用顺序**。库代码构造 rustls 配置时，若默认 provider 由"上一位调用者"安装，
//!    行为就取决于谁先跑（`cargo test` 同进程下一直没暴露，nextest 每条测试一个进程就崩）。
//!
//! 用法（2026-09-27 收窄）：**只有"即将构建 `reqwest` 客户端"的代码路径**需要调用 [`provider`]。
//! 构建 rustls 配置（`ServerConfig` / `ClientConfig` / `RootCertStore`）**不需要**调用——rustls
//! 在只有一个 provider feature 时会自己安装并选中（vendored `rustls-0.23.45/src/crypto/mod.rs:243`
//! 的 `get_default_or_install_from_crate_features`，由 `Config::builder()` 调用）。
//!
//! 当前需要它的地方只有：agent 的上游客户端（`agent::upstream_client`）、e2e 的 `test_client*`
//! 与那个自建 TLS 客户端、以及 `http/entry.rs` 里用 `reqwest::get` 的两个单测。原先那 12 个
//! "构造 rustls 配置前先装"的调用点已随 ring 的移除一并删除。

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
    /// 本次调用装上了 aws-lc-rs。
    InstalledAwsLcRs,
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
            match rustls::crypto::aws_lc_rs::default_provider().install_default() {
                Ok(()) => Origin::InstalledAwsLcRs,
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
            Origin::InstalledAwsLcRs,
            "本测试进程里应是首次安装"
        );
        // 装完之后 rustls 侧必须能取到默认 provider，否则 `Config::builder()` 仍会 panic。
        let installed = rustls::crypto::CryptoProvider::get_default().expect("已装上默认 provider");

        // 而且装上的必须是 **aws-lc-rs** 那一个（不是"随便谁装的"）：ring 已从依赖树移除，
        // 但哪天有人把它加回来、或改成先装 ring，这条会立刻红——不必等到某个 tls 测试
        // 在某个进程里偶然 panic。判据用密钥交换组的名字集合（同 crate 内构造，不受版本漂移影响）。
        let expected = rustls::crypto::aws_lc_rs::default_provider();
        let names = |p: &rustls::crypto::CryptoProvider| {
            p.kx_groups
                .iter()
                .map(|g| format!("{:?}", g.name()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(installed),
            names(&expected),
            "进程默认 provider 必须是 aws-lc-rs 的（ring 已移除；见本模块说明）"
        );
    }
}
