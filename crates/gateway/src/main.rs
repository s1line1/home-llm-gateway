use std::{net::SocketAddr, path::PathBuf, time::Duration};

use clap::Parser;
use gateway::{Gateway, GatewayConfig, TlsPem};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about = "cloud-gateway: 家庭 LLM 远程访问网关（公网入口 + QUIC 隧道服务端）")]
struct Args {
    /// HTTP(S) 公网入口监听地址
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen_addr: SocketAddr,
    /// QUIC 隧道监听地址（UDP）
    #[arg(long, default_value = "0.0.0.0:4433")]
    quic_addr: SocketAddr,
    /// 服务端证书链 PEM（QUIC 隧道用）
    #[arg(long)]
    cert: PathBuf,
    /// 服务端私钥 PEM（QUIC 隧道用）
    #[arg(long)]
    key: PathBuf,
    /// 签发 agent 客户端证书的 CA PEM
    #[arg(long)]
    ca: PathBuf,
    /// 允许的 API Key（逗号分隔，静态）
    #[arg(long, value_delimiter = ',')]
    api_keys: Vec<String>,
    /// Admin token（提供后启用 /admin/keys 管理接口）
    #[arg(long)]
    admin_token: Option<String>,
    /// 动态 API Key 持久化文件
    #[arg(long, default_value = "keys.json")]
    keys_file: PathBuf,
    /// 单次转发空闲超时秒数（逐帧，SSE 长流不受影响）
    #[arg(long, default_value = "120")]
    timeout_secs: u64,
    /// agent 失联判定秒数
    #[arg(long, default_value = "15")]
    agent_stale_secs: u64,
    /// 每个 API Key 每分钟请求上限（0 = 不限流）
    #[arg(long, default_value_t = 0)]
    rate_limit_per_min: u32,
    /// 公网入口 HTTPS 证书 PEM（提供后启用 TLS，与 --tls-key 成对）
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// 公网入口 HTTPS 私钥 PEM（与 --tls-cert 成对）
    #[arg(long)]
    tls_key: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let tls = match (&args.tls_cert, &args.tls_key) {
        (Some(c), Some(k)) => Some(TlsPem {
            cert: std::fs::read(c)?,
            key: std::fs::read(k)?,
        }),
        (None, None) => None,
        _ => anyhow::bail!("--tls-cert and --tls-key must be provided together"),
    };

    let cfg = GatewayConfig {
        http_bind: args.listen_addr,
        quic_bind: args.quic_addr,
        ca_cert: gateway::tls::load_certs(&args.ca)?,
        server_cert: gateway::tls::load_certs(&args.cert)?,
        server_key: gateway::tls::load_key(&args.key)?,
        api_keys: args.api_keys,
        admin_token: args.admin_token,
        keys_file: Some(args.keys_file),
        request_timeout: Duration::from_secs(args.timeout_secs),
        agent_stale_after: Duration::from_secs(args.agent_stale_secs),
        rate_limit_per_min: args.rate_limit_per_min,
        tls,
    };

    let gw = Gateway::start(cfg).await?;
    tracing::info!(http = %gw.http_addr, quic = %gw.quic_addr, "gateway ready");
    let _gw = gw;

    std::future::pending::<()>().await;
    Ok(())
}
