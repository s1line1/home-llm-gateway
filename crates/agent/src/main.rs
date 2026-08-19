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

/// 把命令行参数映射为 agent 配置（独立函数，便于单元测试）。
fn agent_config_from_args(args: Args) -> anyhow::Result<AgentConfig> {
    Ok(AgentConfig {
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
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let cfg = agent_config_from_args(args)?;

    let _agent = Agent::start(cfg)?;
    std::future::pending::<()>().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use rcgen::{CertificateParams, DnType, IsCa, KeyPair, SanType};

    /// 在临时目录生成 (ca, client.crt, client.key) 并返回路径。
    fn gen_cert_files(dir: &std::path::Path) -> (PathBuf, PathBuf, PathBuf) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::default();
        ca.distinguished_name.push(DnType::CommonName, "test ca");
        ca.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca_cert = ca.self_signed(&ca_key).unwrap();

        let cli_key = KeyPair::generate().unwrap();
        let mut cli = CertificateParams::default();
        cli.distinguished_name.push(DnType::CommonName, "agent");
        cli.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
        let cli_cert = cli.signed_by(&cli_key, &ca_cert, &ca_key).unwrap();

        let write = |name: &str, content: &str| {
            let p = dir.join(name);
            std::fs::write(&p, content).unwrap();
            p
        };
        (
            write("ca.crt", &ca_cert.pem()),
            write("client.crt", &cli_cert.pem()),
            write("client.key", &cli_key.serialize_pem()),
        )
    }

    #[test]
    fn args_map_to_agent_config() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let args = Args::parse_from([
            "agent",
            "--cloud-addr", "1.2.3.4:4433",
            "--server-name", "llm.example.com",
            "--ca", ca.to_str().unwrap(),
            "--cert", cert.to_str().unwrap(),
            "--key", key.to_str().unwrap(),
            "--agent-id", "home-1",
            "--upstream", "http://127.0.0.1:11434",
            "--heartbeat-secs", "7",
            "--models", "qwen2.5,llama3",
            "--max-concurrency", "2",
        ]);
        let cfg = agent_config_from_args(args).unwrap();
        assert_eq!(cfg.cloud_addr.to_string(), "1.2.3.4:4433");
        assert_eq!(cfg.server_name, "llm.example.com");
        assert_eq!(cfg.agent_id, "home-1");
        assert_eq!(cfg.upstream_base, "http://127.0.0.1:11434");
        assert_eq!(cfg.heartbeat_interval, Duration::from_secs(7));
        assert_eq!(cfg.models, vec!["qwen2.5".to_string(), "llama3".to_string()]);
        assert_eq!(cfg.max_concurrency, 2);
    }

    #[test]
    fn defaults_applied() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let args = Args::parse_from([
            "agent",
            "--cloud-addr", "127.0.0.1:4433",
            "--ca", ca.to_str().unwrap(),
            "--cert", cert.to_str().unwrap(),
            "--key", key.to_str().unwrap(),
        ]);
        let cfg = agent_config_from_args(args).unwrap();
        assert_eq!(cfg.server_name, "localhost");
        assert_eq!(cfg.agent_id, "home-agent-1");
        assert_eq!(cfg.upstream_base, "http://127.0.0.1:11434");
        assert_eq!(cfg.heartbeat_interval, Duration::from_secs(5));
        assert_eq!(cfg.models, vec!["*".to_string()]);
        assert_eq!(cfg.max_concurrency, 4);
    }
}
