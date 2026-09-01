use std::{net::SocketAddr, path::PathBuf, time::Duration};

use agent::{Agent, AgentConfig};
use anyhow::Context;
use clap::Parser;
use serde::Deserialize;
use tracing_subscriber::EnvFilter;

/// 命令行仅保留：指定配置文件路径。
#[derive(Parser)]
#[command(version, about = "home-agent: 常驻 LLM 所在机器，通过 QUIC 隧道接入云端网关")]
struct Args {
    /// 配置文件路径（YAML），所有参数都在其中配置
    #[arg(long, default_value = "agent-config.yml")]
    config: PathBuf,
}

/// YAML 配置文件结构。`cloud_addr`/`ca`/`cert`/`key` 必填，其余有默认值。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    /// 云端网关 QUIC 地址（IP:端口）— 必填
    cloud_addr: String,
    /// 证书校验服务器名（须与网关证书 SAN 匹配）
    #[serde(default = "default_server_name")]
    server_name: String,
    /// 云端 CA 证书 PEM — 必填
    #[serde(default)]
    ca: PathBuf,
    /// agent 客户端证书 PEM — 必填
    #[serde(default)]
    cert: PathBuf,
    /// agent 客户端私钥 PEM — 必填
    #[serde(default)]
    key: PathBuf,
    /// agent 标识
    #[serde(default = "default_agent_id")]
    agent_id: String,
    /// 本地 LLM 的 OpenAI 兼容地址
    #[serde(default = "default_upstream")]
    upstream: String,
    /// 心跳间隔秒数
    #[serde(default = "default_heartbeat_secs")]
    heartbeat_secs: u64,
    /// 声明的模型列表（* = 全部）
    #[serde(default = "default_models")]
    models: Vec<String>,
    /// 声明的最大并发请求数（网关据此做 admission control）
    #[serde(default = "default_max_concurrency")]
    max_concurrency: u32,
    /// 每请求转发日志开关（received/responded/done；高并发时建议关闭）
    #[serde(default = "default_request_log")]
    request_log: bool,
}

fn default_server_name() -> String {
    "localhost".into()
}
fn default_agent_id() -> String {
    "home-agent-1".into()
}
fn default_upstream() -> String {
    "http://127.0.0.1:11434".into()
}
fn default_heartbeat_secs() -> u64 {
    5
}
fn default_models() -> Vec<String> {
    vec!["*".into()]
}
fn default_max_concurrency() -> u32 {
    4
}
fn default_request_log() -> bool {
    true
}

/// 把 YAML 配置映射为 agent 配置（独立函数，便于单元测试）。
fn config_from_file(cfg: ConfigFile) -> anyhow::Result<AgentConfig> {
    if cfg.ca.as_os_str().is_empty() || cfg.cert.as_os_str().is_empty() || cfg.key.as_os_str().is_empty() {
        anyhow::bail!("config: ca/cert/key paths are required");
    }
    Ok(AgentConfig {
        cloud_addr: cfg
            .cloud_addr
            .parse::<SocketAddr>()
            .with_context(|| format!("config: invalid cloud_addr {:?}", cfg.cloud_addr))?,
        server_name: cfg.server_name,
        ca_cert: agent::tls::load_certs(&cfg.ca)
            .with_context(|| format!("config: cannot load ca cert {}", cfg.ca.display()))?,
        client_cert: agent::tls::load_certs(&cfg.cert)
            .with_context(|| format!("config: cannot load cert {}", cfg.cert.display()))?,
        client_key: agent::tls::load_key(&cfg.key)
            .with_context(|| format!("config: cannot load key {}", cfg.key.display()))?,
        agent_id: cfg.agent_id,
        models: cfg.models,
        max_concurrency: cfg.max_concurrency,
        upstream_base: cfg.upstream,
        heartbeat_interval: Duration::from_secs(cfg.heartbeat_secs),
        request_log: cfg.request_log,
    })
}

/// 启动 agent 主循环（独立函数，便于单元测试覆盖启动路径）。
async fn run(args: Args) -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .try_init();

    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("cannot read config file {}", args.config.display()))?;
    let file_cfg: ConfigFile = serde_yaml_ng::from_str(&text)
        .with_context(|| format!("invalid config file {}", args.config.display()))?;
    let cfg = config_from_file(file_cfg)?;

    let _agent = Agent::start(cfg)?;
    wait_forever().await
}

/// 主循环挂起点（永不返回；coverage 排除，避免不可达代码计入覆盖率）。
async fn wait_forever() -> ! {
    std::future::pending::<()>().await;
    unreachable!("pending never resolves")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run(Args::parse()).await
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn parse_yaml(yaml: &str) -> ConfigFile {
        serde_yaml_ng::from_str(yaml).unwrap()
    }

    #[test]
    fn yaml_maps_to_agent_config() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let yaml = format!(
            r#"
cloud_addr: "1.2.3.4:4433"
server_name: "llm.example.com"
ca: {}
cert: {}
key: {}
agent_id: home-1
upstream: "http://127.0.0.1:8000"
heartbeat_secs: 7
models: [qwen2.5, llama3]
max_concurrency: 2
"#,
            ca.to_str().unwrap(),
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
        );
        let cfg = config_from_file(parse_yaml(&yaml)).unwrap();
        assert_eq!(cfg.cloud_addr.to_string(), "1.2.3.4:4433");
        assert_eq!(cfg.server_name, "llm.example.com");
        assert_eq!(cfg.agent_id, "home-1");
        assert_eq!(cfg.upstream_base, "http://127.0.0.1:8000");
        assert_eq!(cfg.heartbeat_interval, Duration::from_secs(7));
        assert_eq!(cfg.models, vec!["qwen2.5".to_string(), "llama3".to_string()]);
        assert_eq!(cfg.max_concurrency, 2);
        assert!(cfg.request_log, "explicit request_log: true should be honored");
    }

    #[test]
    fn minimal_yaml_applies_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let yaml = format!(
            "cloud_addr: \"127.0.0.1:4433\"\nca: {}\ncert: {}\nkey: {}\n",
            ca.to_str().unwrap(),
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
        );
        let cfg = config_from_file(parse_yaml(&yaml)).unwrap();
        assert_eq!(cfg.server_name, "localhost");
        assert_eq!(cfg.agent_id, "home-agent-1");
        assert_eq!(cfg.upstream_base, "http://127.0.0.1:11434");
        assert_eq!(cfg.heartbeat_interval, Duration::from_secs(5));
        assert_eq!(cfg.models, vec!["*".to_string()]);
        assert_eq!(cfg.max_concurrency, 4);
        assert!(cfg.request_log, "request_log should default to true");
    }

    #[test]
    fn missing_required_rejected() {
        // 缺 cert 路径 → 报错
        let dir = tempfile::tempdir().unwrap();
        let (ca, _, key) = gen_cert_files(dir.path());
        let yaml = format!(
            "cloud_addr: \"127.0.0.1:4433\"\nca: {}\nkey: {}\n",
            ca.to_str().unwrap(),
            key.to_str().unwrap(),
        );
        let result = config_from_file(parse_yaml(&yaml));
        match result {
            Ok(_) => panic!("expected error for missing cert"),
            Err(e) => assert!(e.to_string().contains("required"), "err: {e}"),
        }
    }

    #[test]
    fn invalid_yaml_rejected() {
        assert!(serde_yaml_ng::from_str::<ConfigFile>("cloud_addr: [unclosed").is_err());
    }

    #[test]
    fn unknown_fields_rejected() {
        assert!(serde_yaml_ng::from_str::<ConfigFile>("nonsense_field: 1").is_err());
    }

    #[tokio::test]
    async fn run_starts_agent_loop() {
        // 写一份完整配置到临时目录；云端地址不可达 → 后台重试，主循环挂起在 pending
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let config_path = dir.path().join("config.yml");
        let yaml = format!(
            r#"
cloud_addr: "127.0.0.1:1"
ca: {}
cert: {}
key: {}
heartbeat_secs: 1
"#,
            ca.to_str().unwrap(),
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
        );
        std::fs::write(&config_path, &yaml).unwrap();
        let task = tokio::spawn(run(Args { config: config_path }));
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!task.is_finished(), "agent loop should stay running");
        task.abort();
    }
}
