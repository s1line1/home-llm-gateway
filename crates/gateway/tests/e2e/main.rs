//! 端到端集成测试入口（tests/e2e/ 目录形式保持单测试二进制，`#[serial]` 全局生效）。
//!
//! 注意：这些测试必须**串行**运行（`#[serial]`）——每个测试都启动独立的
//! 多线程 runtime + QUIC 连接 + 时序敏感断言，默认并行会互相争抢 CPU。

mod admin;
mod agents;
mod chain;
mod common;
mod https;
mod metrics;
