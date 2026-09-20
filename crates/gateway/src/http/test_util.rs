//! `http` 各子模块测试共用的辅助（只在 `cfg(test)` 下编译）。
//!
//! 单独成文件是因为测试随被测代码分散到了 `api.rs` / `ui.rs` / `middleware.rs`，
//! 而"造一个测试用 `AppState`"是它们共同的前提。

use std::path::PathBuf;
use std::time::Duration;

use axum::{
    http::{HeaderMap, HeaderValue},
    response::Response,
};

use crate::gateway::Options;
use crate::state::AppState;
use crate::{metrics::Metrics, registry::Registry, storage::KeyStore};

pub(super) fn test_state(ui: Option<PathBuf>) -> AppState {
    // 测试档位：只改这个文件真正关心的旋钮，其余取库默认（`Options::default()`）。
    let opts = Options {
        head_timeout: Duration::from_secs(5),
        ui_dir: ui,
        ..Options::default()
    };
    AppState::new(
        Registry::default(),
        KeyStore::new(None),
        Metrics::default(),
        &opts,
    )
}

pub(super) fn headers_with_accept(accept: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::ACCEPT,
        HeaderValue::from_str(accept).unwrap(),
    );
    h
}

pub(super) async fn body_str(resp: Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}
