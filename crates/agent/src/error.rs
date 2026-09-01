//! agent 领域错误：库层用类型化错误，anyhow 只留在二进制入口。

use std::io;

/// agent 统一错误。
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("config error: {0}")]
    Config(String),

    #[error("TLS/证书错误: {0}")]
    Tls(#[from] rustls::Error),

    #[error("QUIC 连接错误: {0}")]
    Quic(#[from] quinn::ConnectError),

    #[error("IO 错误: {0}")]
    Io(#[from] io::Error),

    #[error("上游转发错误: {0}")]
    Forward(String),

    #[error("未知错误: {0}")]
    Other(String),
}

impl From<String> for AgentError {
    fn from(s: String) -> Self {
        AgentError::Other(s)
    }
}

/// 便捷构造（配置校验等带上下文的错误）。
pub fn config_err(msg: impl Into<String>) -> AgentError {
    AgentError::Config(msg.into())
}
