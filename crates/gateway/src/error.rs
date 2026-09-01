//! 网关领域错误：库层用类型化错误（可 match/分类），anyhow 只留在二进制入口。

use std::io;

/// 网关统一错误。
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("config error: {0}")]
    Config(String),

    #[error("TLS/证书错误: {0}")]
    Tls(#[from] rustls::Error),

    #[error("IO 错误: {0}")]
    Io(#[from] io::Error),

    #[error("SQLite 错误: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("未知错误: {0}")]
    Other(String),
}

impl From<String> for GatewayError {
    fn from(s: String) -> Self {
        GatewayError::Other(s)
    }
}

impl From<&str> for GatewayError {
    fn from(s: &str) -> Self {
        GatewayError::Other(s.to_string())
    }
}

/// 便捷构造（用于 config 校验等带上下文的错误）。
pub fn config_err(msg: impl Into<String>) -> GatewayError {
    GatewayError::Config(msg.into())
}
