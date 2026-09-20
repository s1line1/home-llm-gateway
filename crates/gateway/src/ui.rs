//! `ui_dir` 的启动期判定策略：**这份目录能不能拿来托管 Dashboard**。
//!
//! 与 `http.rs` 的分工：这里回答"是不是一份能用的产物"（纯判定 + 日志），`http.rs`
//! 回答"怎么把它服务出去"（`ServeDir`、SPA fallback、占位页）。
//!
//! 单独成模块是为了**断开依赖环**：`AppState::new` 需要这个判定，而 `AppState` 定义在
//! `state.rs`；把它留在 `http.rs` 会让依赖变成 `state → http → state`。
//!
//! 为什么判定不能只看"有没有 index.html"：前端**源码**目录同样有 index.html——
//! Vite 的 `web/index.html` 里是 `<script type="module" src="/src/main.tsx">`，网关会把
//! TSX 当 `application/octet-stream` 发出去，浏览器执行不了 → 页面全白且**一条错误都没有**。

use std::path::{Path, PathBuf};

use tracing::{error, warn};

/// `ui_dir` 是否真的能拿来托管。
///
/// 原来的判断只问"目录里有 index.html 吗"，而前端**源码**目录同样有——Vite 的
/// `web/index.html` 里是 `<script type="module" src="/src/main.tsx">`，网关会把 TSX 当
/// `application/octet-stream` 发出去，浏览器执行不了 → 页面全白且**一条错误都没有**。
/// 所以这里问的是"这是一份能用的产物吗"。
#[derive(Debug, PartialEq, Eq)]
pub enum UiDirCheck {
    /// 可用：index.html 在，且它引用的本地资源都能在磁盘上找到。
    Usable,
    /// 目录里没有 index.html（还没构建）。
    NoIndex,
    /// index.html 是前端**源码**入口（引用 /src/*），浏览器必然白屏。
    SourceEntry,
    /// index.html 引用的产物文件不存在（构建过期或 ui_dir 指错）。附上是哪一个。
    MissingAsset(String),
}

/// 判定 `ui_dir` 是否是一份可托管的产物。放在 http.rs：只有这个模块知道
/// "一份前端产物长什么样、怎么被托管"，lib.rs 只负责在启动时按结果编排。
pub fn check_ui_dir(dir: &Path) -> UiDirCheck {
    let Ok(html) = std::fs::read_to_string(dir.join("index.html")) else {
        return UiDirCheck::NoIndex;
    };
    // Vite 的源码入口特征；换框架要跟着改（CRA 是 /static/js/…、Next export 是 /_next/…），
    // 真正框架无关的兜底是下面的产物存在性检查。
    if html.contains("src=\"/src/") || html.contains("src='/src/") {
        return UiDirCheck::SourceEntry;
    }
    for asset in local_asset_refs(&html) {
        if !dir.join(asset.trim_start_matches('/')).is_file() {
            return UiDirCheck::MissingAsset(asset);
        }
    }
    UiDirCheck::Usable
}

/// 抓 index.html 里 `src="/…"` / `href="/…"` 这类**本地静态资源**路径（去重、去掉 query/fragment）。
///
/// 只收"末段带扩展名"的引用，这条判据与 [`ui_fallback`] 的 `has_extension` 一致：
/// SPA 前端路由（`/keys`、`/metrics`）会 fallback 到 index.html，磁盘上本来就没有对应文件，
/// 误判成"缺失"会把一个**能用**的 UI 关掉——宁可漏报也不能误报。
/// 同样跳过 http(s)://、协议相对的 //cdn、data:：那些不归 ui_dir 管。
///
/// 手写扫描而非引 HTML parser：只为一次启动自检不值得加依赖（metrics.rs 同样是手写无依赖）。
fn local_asset_refs(html: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for attr in ["src=\"", "href=\"", "src='", "href='"] {
        let quote = attr.chars().last().expect("attr ends with a quote");
        let mut rest = html;
        while let Some(idx) = rest.find(attr) {
            rest = &rest[idx + attr.len()..];
            let Some(end) = rest.find(quote) else { break };
            let value = &rest[..end];
            rest = &rest[end + quote.len_utf8()..];
            if !value.starts_with('/') || value.starts_with("//") {
                continue;
            }
            let path = value.split(['?', '#']).next().unwrap_or(value);
            let looks_like_file = path.rsplit('/').next().is_some_and(|seg| seg.contains('.'));
            if !looks_like_file {
                continue;
            }
            if !out.iter().any(|p| p == path) {
                out.push(path.to_string());
            }
        }
    }
    out
}

/// `ui_dir` 的启动期判定：返回（可托管的目录, 不可用的原因）。
///
/// 必须确认它是**一份能用的产物**，而不只是"有 index.html"——Vite 的源码目录同样有
/// index.html，托管出去只会让浏览器白屏（见 [`check_ui_dir`]）。判定不通过就降级到
/// 占位页，并把具体原因写进 `AppState`，让页面自己说清楚。
///
/// **非致命**：这里任何问题都不阻止网关启动（`ui_dir` 只是给人看的诊断面）。
pub fn resolve_ui(configured: Option<&Path>) -> (Option<PathBuf>, Option<String>) {
    let Some(p) = configured else {
        return (None, None);
    };
    match check_ui_dir(p) {
        UiDirCheck::Usable => (Some(p.to_path_buf()), None),
        // 还没构建：占位页自带的通用文案（"构建前端后配置 ui_dir"）正好适用
        UiDirCheck::NoIndex => {
            warn!(path = %p.display(), "ui_dir 下没有 index.html；GET / 显示构建提示页");
            (None, None)
        }
        UiDirCheck::SourceEntry => {
            let msg = format!(
                "ui_dir 指向的是前端**源码**目录，不是构建产物（默认 web/dist）：{}",
                p.display()
            );
            error!(path = %p.display(), "{msg}；浏览器只会白屏，GET / 已改显示本提示页");
            (None, Some(msg))
        }
        UiDirCheck::MissingAsset(asset) => {
            let msg =
                format!("index.html 引用的产物不存在：{asset}（构建过期，或 ui_dir 指向了别处）");
            warn!(path = %p.display(), missing = %asset, "{msg}；GET / 显示构建提示页");
            (None, Some(msg))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- ui_dir 可用性判定 ----
    // 曾经的事故：ui_dir 配成前端**源码**目录，index.html 照样在，于是被当成"已构建"托管出去，
    // 浏览器拿到 application/octet-stream 的 TSX，页面全白且没有任何错误可查。

    #[test]
    fn check_ui_dir_reports_no_index() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(check_ui_dir(dir.path()), UiDirCheck::NoIndex);
    }

    #[test]
    fn check_ui_dir_detects_vite_source_entry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("index.html"),
            r#"<div id="root"></div><script type="module" src="/src/main.tsx"></script>"#,
        )
        .unwrap();
        assert_eq!(check_ui_dir(dir.path()), UiDirCheck::SourceEntry);
    }

    #[test]
    fn check_ui_dir_accepts_built_dist() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("assets")).unwrap();
        std::fs::write(dir.path().join("assets/index-abc.js"), "//built").unwrap();
        std::fs::write(dir.path().join("assets/index-abc.css"), "/*built*/").unwrap();
        std::fs::write(
            dir.path().join("index.html"),
            r#"<script type="module" crossorigin src="/assets/index-abc.js"></script>
    <link rel="stylesheet" crossorigin href="/assets/index-abc.css">"#,
        )
        .unwrap();
        assert_eq!(check_ui_dir(dir.path()), UiDirCheck::Usable);
    }

    #[test]
    fn check_ui_dir_flags_missing_asset() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("index.html"),
            r#"<script type="module" src="/assets/index-abc.js"></script>"#,
        )
        .unwrap();
        // 构建过期 / 目录指错：产物文件不在
        assert_eq!(
            check_ui_dir(dir.path()),
            UiDirCheck::MissingAsset("/assets/index-abc.js".into())
        );
    }

    #[test]
    fn check_ui_dir_ignores_non_asset_refs() {
        // 外部资源（http://、//cdn、data:）和 SPA 前端路由（无扩展名）都不是"缺失的产物"，
        // 误判会把一个能用的 UI 关掉。
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("assets")).unwrap();
        std::fs::write(dir.path().join("assets/ok.css"), "/*x*/").unwrap();
        std::fs::write(dir.path().join("favicon.ico"), "x").unwrap();
        std::fs::write(
            dir.path().join("index.html"),
            r#"<link rel="stylesheet" href="/assets/ok.css">
    <link rel="preconnect" href="https://fonts.example.com">
    <link rel="icon" href="//cdn.example.com/favicon.ico">
    <link rel="icon" href="/favicon.ico">
    <img src="data:image/png;base64,AAAA">
    <a href="/keys">keys</a>
    <a href="/metrics">metrics</a>"#,
        )
        .unwrap();
        assert_eq!(check_ui_dir(dir.path()), UiDirCheck::Usable);
    }
}
