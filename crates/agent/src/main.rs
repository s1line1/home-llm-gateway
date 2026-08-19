use std::{net::SocketAddr, path::PathBuf, time::Duration};

use agent::{Agent, AgentConfig};
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about = "home-agent: 常驻 LLM 所在机器，通过 QUIC 隧道接入云端网关")]
struct Args {
    /// 云端网关 QUIC 地址（IP:端口）
    #[arg(long)]
    cloud_addr: SocketAddr,
    /// 证书校验服务器名（须与网关证书 SAN 匹配）
    #[arg(long, default_value = "localhost")]
    server_name: String,
    /// 云端 CA 证书 PEM
    #[arg(long)]
    ca: PathBuf,
    /// agent 客户端证书 PEM
    #[arg(long)]
    cert: PathBuf,
    /// agent 客户端私钥 PEM
    #[arg(long)]
    key: PathBuf,
    /// agent 标识
    #[arg(long, default_value = "home-agent-1")]
    agent_id: String,
    /// 本地 LLM 的 OpenAI 兼容地址
    #[arg(long, default_value = "http://127.0.0.1:11434")]
    upstream: String,
    /// 心跳间隔秒数
    #[arg(long, default_value = "5")]
    heartbeat_secs: u64,
    /// 声明的模型列表（逗号分隔）
    #[arg(long, value_delimiter = ',', default_value = "*")]
    models: Vec<String>,
    /// 声明的最大并发请求数（网关据此做 admission control）
    #[arg(long, default_value_t = 4)]
    max_concurrency: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let cfg = AgentConfig {
        cloud_addr: args.cloud_addr,
        server_name: args.server_name,
        ca_cert: agent::tls::load_certs(&args.ca)?,
        client_cert: agent::tls::load_certs(&args.cert)?,
        client_key: agent::tls::load_key(&args.key)?,
        agent_id: args.agent_id,
        models: args.models,
        max_concurrency: args.max_concurrency,
        upstream_base: args.upstream,
        heartbeat_interval: Duration::from_secs(args.heartbeat_secs),
    };

    let _agent = Agent::start(cfg)?;
    std::future::pending::<()>().await;
    Ok(())
}
