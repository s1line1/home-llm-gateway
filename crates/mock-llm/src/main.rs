use std::net::SocketAddr;

use clap::Parser;
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let listener = tokio::net::TcpListener::bind(args.addr).await?;
    tracing::info!(name = %args.name, "mock-llm listening on {}", listener.local_addr()?);
    axum::serve(listener, mock_llm::router(&args.name)).await?;
    Ok(())
}
