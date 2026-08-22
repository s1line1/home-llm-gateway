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
    /// 动态 API Key 持久化数据库文件（SQLite）
    #[arg(long, default_value = "keys.db")]
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

/// 把命令行参数映射为网关配置（独立函数，便于单元测试）。
fn config_from_args(args: Args) -> anyhow::Result<GatewayConfig> {
    let tls = match (&args.tls_cert, &args.tls_key) {
        (Some(c), Some(k)) => Some(TlsPem {
            cert: std::fs::read(c)?,
            key: std::fs::read(k)?,
        }),
        (None, None) => None,
        _ => anyhow::bail!("--tls-cert and --tls-key must be provided together"),
    };

    Ok(GatewayConfig {
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
    })
}

/// 启动网关主循环（独立函数，便于单元测试覆盖启动路径）。
async fn run(args: Args) -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .try_init();

    let cfg = config_from_args(args)?;

    let gw = Gateway::start(cfg).await?;
    tracing::info!(http = %gw.http_addr, quic = %gw.quic_addr, "gateway ready");
    let _gw = gw;

    std::future::pending::<()>().await;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run(Args::parse()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use rcgen::{CertificateParams, DnType, IsCa, KeyPair, SanType};

    /// 在临时目录生成 (ca, server.crt, server.key) 并返回路径。
    fn gen_cert_files(dir: &std::path::Path) -> (PathBuf, PathBuf, PathBuf) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::default();
        ca.distinguished_name.push(DnType::CommonName, "test ca");
        ca.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca_cert = ca.self_signed(&ca_key).unwrap();

        let srv_key = KeyPair::generate().unwrap();
        let mut srv = CertificateParams::default();
        srv.distinguished_name.push(DnType::CommonName, "gw");
        srv.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
        let srv_cert = srv.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();

        let write = |name: &str, content: &str| {
            let p = dir.join(name);
            std::fs::write(&p, content).unwrap();
            p
        };
        (
            write("ca.crt", &ca_cert.pem()),
            write("server.crt", &srv_cert.pem()),
            write("server.key", &srv_key.serialize_pem()),
        )
    }

    #[test]
    fn args_map_to_config() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let args = Args::parse_from([
            "gateway",
            "--listen-addr", "0.0.0.0:8443",
            "--quic-addr", "0.0.0.0:4433",
            "--cert", cert.to_str().unwrap(),
            "--key", key.to_str().unwrap(),
            "--ca", ca.to_str().unwrap(),
            "--api-keys", "k1,k2",
            "--admin-token", "admin",
            "--keys-file", dir.path().join("keys.json").to_str().unwrap(),
            "--timeout-secs", "30",
            "--agent-stale-secs", "20",
            "--rate-limit-per-min", "60",
        ]);
        let cfg = config_from_args(args).unwrap();
        assert_eq!(cfg.http_bind.to_string(), "0.0.0.0:8443");
        assert_eq!(cfg.quic_bind.to_string(), "0.0.0.0:4433");
        assert_eq!(cfg.api_keys, vec!["k1".to_string(), "k2".to_string()]);
        assert_eq!(cfg.admin_token.as_deref(), Some("admin"));
        assert_eq!(cfg.request_timeout, Duration::from_secs(30));
        assert_eq!(cfg.agent_stale_after, Duration::from_secs(20));
        assert_eq!(cfg.rate_limit_per_min, 60);
        assert_eq!(cfg.keys_file, Some(dir.path().join("keys.json")));
        assert!(cfg.tls.is_none());
    }

    #[test]
    fn tls_cert_without_key_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let args = Args::parse_from([
            "gateway",
            "--cert", cert.to_str().unwrap(),
            "--key", key.to_str().unwrap(),
            "--ca", ca.to_str().unwrap(),
            "--api-keys", "k",
            "--tls-cert", cert.to_str().unwrap(), // 只给证书不给私钥
        ]);
        assert!(config_from_args(args).is_err());
    }

    #[test]
    fn tls_pair_loaded_from_files() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let args = Args::parse_from([
            "gateway",
            "--cert", cert.to_str().unwrap(),
            "--key", key.to_str().unwrap(),
            "--ca", ca.to_str().unwrap(),
            "--api-keys", "k",
            "--tls-cert", cert.to_str().unwrap(),
            "--tls-key", key.to_str().unwrap(),
        ]);
        let cfg = config_from_args(args).unwrap();
        let tls = cfg.tls.expect("tls pair should be loaded");
        assert!(!tls.cert.is_empty() && !tls.key.is_empty());
    }

    #[tokio::test]
    async fn run_starts_gateway() {
        // 用随机端口 + 临时证书启动网关，主循环挂起在 pending
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let args = Args::parse_from([
            "gateway",
            "--listen-addr", "127.0.0.1:0",
            "--quic-addr", "127.0.0.1:0",
            "--cert", cert.to_str().unwrap(),
            "--key", key.to_str().unwrap(),
            "--ca", ca.to_str().unwrap(),
            "--api-keys", "test-key",
        ]);
        let task = tokio::spawn(run(args));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(!task.is_finished(), "gateway loop should stay running");
        task.abort();
    }
}
