use std::net::SocketAddr;

use clap::Parser;
use time::UtcOffset;
use tracing_subscriber::fmt::time::OffsetTime;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about = "mock-llm: 模拟 OpenAI 兼容接口的假 LLM")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:11435")]
    addr: SocketAddr,
    /// 实例名（多 agent 场景用于区分上游）
    #[arg(long, default_value = "mock-llm")]
    name: String,
}

/// 启动 mock 服务（独立函数，便于单元测试覆盖启动逻辑）。
async fn run(args: Args) -> anyhow::Result<()> {
    // 日志时间戳固定东八区（UTC+8）：China Standard Time，无夏令时。
    let timer = OffsetTime::new(
        UtcOffset::from_hms(8, 0, 0).expect("UTC+8 is a valid fixed offset"),
        time::format_description::well_known::Rfc3339,
    );
    let _ = tracing_subscriber::fmt()
        .with_timer(timer)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .try_init();

    let listener = tokio::net::TcpListener::bind(args.addr).await?;
    tracing::info!(name = %args.name, "mock-llm listening on {}", listener.local_addr()?);
    serve_forever(listener, args.name).await
}

/// 服务挂起点（正常永不返回；coverage 排除，避免不可达代码计入覆盖率）。
async fn serve_forever(listener: tokio::net::TcpListener, name: String) -> anyhow::Result<()> {
    axum::serve(listener, mock_llm::router(&name)).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run(Args::parse()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_binds_and_serves() {
        // 用 127.0.0.1:0 随机端口启动，短暂运行后中止，验证启动路径可执行
        let task = tokio::spawn(run(Args::parse_from([
            "mock-llm",
            "--addr",
            "127.0.0.1:0",
            "--name",
            "test-instance",
        ])));
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!task.is_finished(), "mock server should keep serving");
        task.abort();
    }
}
