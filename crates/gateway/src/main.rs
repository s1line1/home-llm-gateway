use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::Context;
use clap::Parser;
use gateway::{Gateway, GatewayConfig, TlsPem};
use serde::Deserialize;
use tracing_subscriber::EnvFilter;

/// 命令行仅保留：指定配置文件路径。
#[derive(Parser)]
#[command(version, about = "cloud-gateway: 家庭 LLM 远程访问网关（公网入口 + QUIC 隧道服务端）")]
struct Args {
    /// 配置文件路径（YAML），所有参数都在其中配置
    #[arg(long, default_value = "gateway-config.yml")]
    config: PathBuf,
}

/// YAML 配置文件结构。所有字段均有默认值；`cert`/`key`/`ca` 必须显式提供。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    /// HTTP(S) 公网入口监听地址
    #[serde(default = "default_listen_addr")]
    listen_addr: String,
    /// QUIC 隧道监听地址（UDP）
    #[serde(default = "default_quic_addr")]
    quic_addr: String,
    /// 服务端证书链 PEM（QUIC 隧道用）— 必填
    #[serde(default)]
    cert: PathBuf,
    /// 服务端私钥 PEM（QUIC 隧道用）— 必填
    #[serde(default)]
    key: PathBuf,
    /// 签发 agent 客户端证书的 CA PEM — 必填
    #[serde(default)]
    ca: PathBuf,
    /// Admin token（提供后启用 /admin/keys 管理接口）
    #[serde(default)]
    admin_token: Option<String>,
    /// 动态 API Key 持久化数据库文件（SQLite；null = 仅内存）
    #[serde(default = "default_keys_file")]
    keys_file: Option<PathBuf>,
    /// 单次转发空闲超时秒数（逐帧，SSE 长流不受影响）
    #[serde(default = "default_timeout_secs")]
    timeout_secs: u64,
    /// agent 失联判定秒数
    #[serde(default = "default_agent_stale_secs")]
    agent_stale_secs: u64,
    /// 每个 API Key 每分钟请求上限（0 = 不限流）
    #[serde(default)]
    rate_limit_per_min: u32,
    /// 公网入口 HTTPS 证书 PEM（提供后启用 TLS，与 tls_key 成对）
    #[serde(default)]
    tls_cert: Option<PathBuf>,
    /// 公网入口 HTTPS 私钥 PEM（与 tls_cert 成对）
    #[serde(default)]
    tls_key: Option<PathBuf>,
    /// React UI 静态目录（含 index.html；默认 web/dist，不存在时 `/` 显示构建提示页）
    #[serde(default = "default_ui_dir")]
    ui_dir: Option<PathBuf>,
}

fn default_listen_addr() -> String {
    "0.0.0.0:8080".into()
}
fn default_quic_addr() -> String {
    "0.0.0.0:4433".into()
}
fn default_keys_file() -> Option<PathBuf> {
    Some(PathBuf::from("keys.db"))
}
fn default_ui_dir() -> Option<PathBuf> {
    Some(PathBuf::from("web/dist"))
}
fn default_timeout_secs() -> u64 {
    120
}
fn default_agent_stale_secs() -> u64 {
    15
}

/// 把 YAML 配置映射为网关配置（独立函数，便于单元测试）。
fn config_from_file(cfg: ConfigFile) -> anyhow::Result<GatewayConfig> {
    if cfg.cert.as_os_str().is_empty() || cfg.key.as_os_str().is_empty() || cfg.ca.as_os_str().is_empty() {
        anyhow::bail!("config: cert/key/ca paths are required");
    }
    let tls = match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(c), Some(k)) => Some(TlsPem {
            cert: std::fs::read(c)
                .with_context(|| format!("config: cannot read tls_cert {}", c.display()))?,
            key: std::fs::read(k)
                .with_context(|| format!("config: cannot read tls_key {}", k.display()))?,
        }),
        (None, None) => None,
        _ => anyhow::bail!("config: tls_cert and tls_key must be provided together"),
    };

    Ok(GatewayConfig {
        http_bind: cfg
            .listen_addr
            .parse::<SocketAddr>()
            .with_context(|| format!("config: invalid listen_addr {:?}", cfg.listen_addr))?,
        quic_bind: cfg
            .quic_addr
            .parse::<SocketAddr>()
            .with_context(|| format!("config: invalid quic_addr {:?}", cfg.quic_addr))?,
        ca_cert: gateway::tls::load_certs(&cfg.ca)
            .with_context(|| format!("config: cannot load ca cert {}", cfg.ca.display()))?,
        server_cert: gateway::tls::load_certs(&cfg.cert)
            .with_context(|| format!("config: cannot load cert {}", cfg.cert.display()))?,
        server_key: gateway::tls::load_key(&cfg.key)
            .with_context(|| format!("config: cannot load key {}", cfg.key.display()))?,
        admin_token: cfg.admin_token,
        keys_file: cfg.keys_file,
        request_timeout: Duration::from_secs(cfg.timeout_secs),
        agent_stale_after: Duration::from_secs(cfg.agent_stale_secs),
        rate_limit_per_min: cfg.rate_limit_per_min,
        tls,
        ui_dir: cfg.ui_dir,
    })
}

/// 启动网关主循环（独立函数，便于单元测试覆盖启动路径）。
async fn run(args: Args) -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .try_init();

    let path = std::fs::read_to_string(&args.config)
        .with_context(|| format!("cannot read config file {}", args.config.display()))?;
    let file_cfg: ConfigFile = serde_yaml_ng::from_str(&path)
        .with_context(|| format!("invalid config file {}", args.config.display()))?;
    let cfg = config_from_file(file_cfg)?;

    let gw = Gateway::start(cfg).await?;
    tracing::info!(http = %gw.http_addr, quic = %gw.quic_addr, "Gateway ready");
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

    fn parse_yaml(yaml: &str) -> ConfigFile {
        serde_yaml_ng::from_str(yaml).unwrap()
    }

    #[test]
    fn yaml_maps_to_config() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let yaml = format!(
            r#"
listen_addr: "0.0.0.0:8443"
quic_addr: "0.0.0.0:4433"
cert: {}
key: {}
ca: {}
admin_token: admin
keys_file: {}
timeout_secs: 30
agent_stale_secs: 20
rate_limit_per_min: 60
"#,
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            ca.to_str().unwrap(),
            dir.path().join("keys.db").to_str().unwrap(),
        );
        let cfg = config_from_file(parse_yaml(&yaml)).unwrap();
        assert_eq!(cfg.http_bind.to_string(), "0.0.0.0:8443");
        assert_eq!(cfg.quic_bind.to_string(), "0.0.0.0:4433");
        assert_eq!(cfg.admin_token.as_deref(), Some("admin"));
        assert_eq!(cfg.keys_file, Some(dir.path().join("keys.db")));
        assert_eq!(cfg.request_timeout, Duration::from_secs(30));
        assert_eq!(cfg.agent_stale_after, Duration::from_secs(20));
        assert_eq!(cfg.rate_limit_per_min, 60);
        assert!(cfg.tls.is_none());
    }

    #[test]
    fn minimal_yaml_applies_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let yaml = format!(
            "cert: {}\nkey: {}\nca: {}\n",
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            ca.to_str().unwrap(),
        );
        let cfg = config_from_file(parse_yaml(&yaml)).unwrap();
        assert_eq!(cfg.http_bind.to_string(), "0.0.0.0:8080", "default listen_addr");
        assert_eq!(cfg.quic_bind.to_string(), "0.0.0.0:4433", "default quic_addr");
        assert_eq!(cfg.request_timeout, Duration::from_secs(120));
        assert_eq!(cfg.agent_stale_after, Duration::from_secs(15));
        assert_eq!(cfg.rate_limit_per_min, 0);
        assert!(cfg.admin_token.is_none());
        assert_eq!(cfg.keys_file, Some(PathBuf::from("keys.db")));
        assert!(cfg.tls.is_none());
    }

    #[test]
    fn missing_required_paths_rejected() {
        let result = config_from_file(parse_yaml("listen_addr: \"0.0.0.0:8443\"\n"));
        match result {
            Ok(_) => panic!("expected error for missing cert/key/ca"),
            Err(e) => assert!(e.to_string().contains("required"), "err: {e}"),
        }
    }

    #[test]
    fn tls_pair_loaded_from_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let yaml = format!(
            "cert: {}\nkey: {}\nca: {}\ntls_cert: {}\ntls_key: {}\n",
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            ca.to_str().unwrap(),
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
        );
        let cfg = config_from_file(parse_yaml(&yaml)).unwrap();
        let tls = cfg.tls.expect("tls pair should be loaded");
        assert!(!tls.cert.is_empty() && !tls.key.is_empty());
    }

    #[test]
    fn tls_cert_without_key_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let yaml = format!(
            "cert: {}\nkey: {}\nca: {}\ntls_cert: {}\n",
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            ca.to_str().unwrap(),
            cert.to_str().unwrap(),
        );
        assert!(config_from_file(parse_yaml(&yaml)).is_err());
    }

    #[test]
    fn invalid_yaml_rejected() {
        assert!(serde_yaml_ng::from_str::<ConfigFile>("listen_addr: [unclosed").is_err());
    }

    #[test]
    fn unknown_fields_rejected() {
        assert!(serde_yaml_ng::from_str::<ConfigFile>("nonsense_field: 1").is_err());
    }

    #[tokio::test]
    async fn run_starts_gateway() {
        // 写一份完整配置到临时目录，用随机端口启动网关
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let config_path = dir.path().join("config.yml");
        let yaml = format!(
            r#"
listen_addr: "127.0.0.1:0"
quic_addr: "127.0.0.1:0"
cert: {}
key: {}
ca: {}
keys_file: {}
"#,
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            ca.to_str().unwrap(),
            dir.path().join("keys.db").to_str().unwrap(),
        );
        std::fs::write(&config_path, &yaml).unwrap();
        let task = tokio::spawn(run(Args { config: config_path }));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(!task.is_finished(), "gateway loop should stay running");
        task.abort();
    }
}
