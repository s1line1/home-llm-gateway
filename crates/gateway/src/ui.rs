//! `ui_dir` 的启动期判定策略：**这份目录能不能拿来托管 Dashboard**。
//!
//! 与 `http/` 的分工：这里回答"是不是一份能用的产物"（纯判定 + 日志）与"怎么把 index.html
//! 读出来"（[`IndexHtml`] 的缓存读），`http/ui.rs` 回答"怎么把它服务出去"
//! （`ServeDir`、SPA fallback、占位页）。
//!
//! 单独成模块是为了**断开依赖环**：`AppState::new` 需要这个判定，而 `AppState` 定义在
//! `state.rs`；把它留在 `http.rs` 会让依赖变成 `state → http → state`。
//!
//! 为什么判定不能只看"有没有 index.html"：前端**源码**目录同样有 index.html——
//! Vite 的 `web/index.html` 里是 `<script type="module" src="/src/main.tsx">`，网关会把
//! TSX 当 `application/octet-stream` 发出去，浏览器执行不了 → 页面全白且**一条错误都没有**。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use tracing::{error, warn};

/// `ui_dir` 里 `index.html` 的**缓存读**（服务期每个请求都要它）。
///
/// 放在本模块而不是 `http/` 的原因与判定一样：`AppState` 要持有它，而 `AppState` 定义在
/// `state.rs`；留在 `http/` 会重新造出 `state → http → state`。
///
/// 为什么需要缓存：`/metrics` 的浏览器分支与 SPA fallback 都要这份文件，而原来是**每次请求**
/// `std::fs::read_to_string` ——在 async 上下文里做阻塞 I/O，磁盘一慢就占住 tokio worker
/// （同一个 worker 上的其它请求一起被拖住）。
///
/// 缓存策略是**按 mtime 校验**而不是"启动时读一次"：重建前端后不需要重启网关就能生效，
/// 否则"我明明 rebuild 了，页面还是旧的"会变成一个很难查的坑。代价是每个请求一次
/// `tokio::fs::metadata`（走阻塞池，不挡 worker），命中时省掉整文件读取。
///
/// 读失败（文件被删/权限）**不缓存失败结果**，下次请求照旧重试——与原来"读不到就降级"
/// 的行为一致。
#[derive(Clone)]
pub(crate) struct IndexHtml {
    path: PathBuf,
    /// `None` = 还没成功读过。存 `Arc<str>` 让命中路径只做一次引用计数。
    cached: Arc<Mutex<Option<Cached>>>,
}

#[derive(Clone)]
struct Cached {
    /// 读这份内容时文件的 mtime；`None` = 该文件系统给不出 mtime。
    mtime: Option<SystemTime>,
    html: Arc<str>,
}

impl IndexHtml {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            cached: Arc::new(Mutex::new(None)),
        }
    }

    /// 取 index.html：mtime 未变则用缓存。读不到返回 `None`（调用方降级）。
    pub(crate) async fn load(&self) -> Option<Arc<str>> {
        let mtime = tokio::fs::metadata(&self.path)
            .await
            .ok()
            .and_then(|m| m.modified().ok());
        // 只有"缓存里有 mtime 且与磁盘一致"才算命中。mtime 不可知（None）时一律重读：
        // 宁可多读一次盘，也不要在这类文件系统上永久钉住旧内容。
        {
            let guard = self.cached.lock().expect("index cache mutex poisoned");
            if let Some(c) = guard.as_ref() {
                if mtime.is_some() && c.mtime == mtime {
                    return Some(c.html.clone());
                }
            }
        }
        // 先在锁外读：这里是唯一可能的 await，持锁跨 await 会把并发请求串起来
        let html: Arc<str> = tokio::fs::read_to_string(&self.path).await.ok()?.into();
        *self.cached.lock().expect("index cache mutex poisoned") = Some(Cached {
            mtime,
            html: html.clone(),
        });
        Some(html)
    }
}

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

    // ---- index.html 的缓存读 ----

    /// 用 `set_modified` 显式控制 mtime：只靠"写完再写"来触发变更会依赖文件系统时间戳
    /// 精度，测试会变得不确定。
    fn write_with_mtime(path: &Path, content: &str, mtime: SystemTime) {
        std::fs::write(path, content).unwrap();
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
    }

    #[tokio::test]
    async fn index_html_is_cached_until_mtime_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.html");
        let t0 = SystemTime::now();
        write_with_mtime(&path, "A", t0);
        let cache = IndexHtml::new(path.clone());

        assert_eq!(&*cache.load().await.unwrap(), "A");

        // 内容变了但 mtime 没变（模拟两次写落在同一时间戳）→ 仍是缓存内容：
        // 这正是"命中缓存、没有重读盘"的证据
        write_with_mtime(&path, "BBBB", t0);
        assert_eq!(
            &*cache.load().await.unwrap(),
            "A",
            "mtime 未变时必须命中缓存（不再读盘）"
        );

        // mtime 变了（重建前端）→ 重读，无需重启网关
        write_with_mtime(&path, "BBBB", t0 + std::time::Duration::from_secs(1));
        assert_eq!(
            &*cache.load().await.unwrap(),
            "BBBB",
            "mtime 变化后必须重新读盘（rebuild 后不重启也要生效）"
        );
    }

    #[tokio::test]
    async fn index_html_read_failure_is_not_cached() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.html");
        let cache = IndexHtml::new(path.clone());

        // 文件还不存在 → None（调用方降级为 Prometheus 文本）
        assert!(cache.load().await.is_none());

        // 失败不缓存：随后出现即可读到（与原来"读不到就降级"的行为一致）
        write_with_mtime(&path, "A", SystemTime::now());
        assert_eq!(&*cache.load().await.unwrap(), "A");
    }

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
