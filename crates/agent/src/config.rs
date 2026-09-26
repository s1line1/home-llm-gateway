//! agent 配置：YAML 解析 → AgentConfig 映射（从 main.rs 独立出来，便于测试与复用）。

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use crate::AgentConfig;
use anyhow::Context;
use serde::Deserialize;

/// YAML 配置文件结构。`cloud_addr`/`ca`/`cert`/`key` 必填，其余有默认值。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
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
    /// 声明的模型列表（edge 能力声明，网关据此做模型路由；`*` = 全匹配，
    /// 不贡献 /v1/models 聚合条目）。示例：`[qwen2.5, llama3]`
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
    "edge-1".into()
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

/// 从 YAML 文件加载并映射为 agent 配置。
pub fn from_path(path: &PathBuf) -> anyhow::Result<AgentConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read config file {}", path.display()))?;
    let file_cfg: ConfigFile = serde_yaml_ng::from_str(&text)
        .with_context(|| format!("invalid config file {}", path.display()))?;
    from_file(file_cfg)
}

/// 把 YAML 配置映射为 agent 配置（独立函数，便于单元测试）。
pub fn from_file(cfg: ConfigFile) -> anyhow::Result<AgentConfig> {
    if cfg.ca.as_os_str().is_empty()
        || cfg.cert.as_os_str().is_empty()
        || cfg.key.as_os_str().is_empty()
    {
        anyhow::bail!("config: ca/cert/key paths are required");
    }
    // 零值校验（记录 P2-8 的 agent 侧）：`heartbeat_secs: 0` 会让心跳循环 `sleep(0)` +
    // `timeout(0, ..)` 每次都立刻失败，两次失败即强制重连 ⇒ 拨号风暴 + 网关侧反复摘除/注册。
    // 配置文件里那个 `0` 看起来同样毫无异常，所以在这里就拒掉。
    if cfg.heartbeat_secs == 0 {
        anyhow::bail!(
            "config: heartbeat_secs must be at least 1 second, but is 0: a zero heartbeat makes \
             every wait time out immediately, forcing a reconnect on every cycle"
        );
    }
    Ok(AgentConfig {
        cloud_addr: cfg
            .cloud_addr
            .parse::<SocketAddr>()
            .with_context(|| format!("config: invalid cloud_addr {:?}", cfg.cloud_addr))?,
        server_name: cfg.server_name,
        ca_cert: proto::pem::load_certs(&cfg.ca)
            .with_context(|| format!("config: cannot load ca cert {}", cfg.ca.display()))?,
        client_cert: proto::pem::load_certs(&cfg.cert)
            .with_context(|| format!("config: cannot load cert {}", cfg.cert.display()))?,
        client_key: proto::pem::load_key(&cfg.key)
            .with_context(|| format!("config: cannot load key {}", cfg.key.display()))?,
        agent_id: cfg.agent_id,
        models: cfg.models,
        max_concurrency: cfg.max_concurrency,
        upstream_base: normalize_upstream(&cfg.upstream)?,
        heartbeat_interval: Duration::from_secs(cfg.heartbeat_secs),
        request_log: cfg.request_log,
    })
}

/// 校验并规范化 `upstream`（复扫 E3）：必须是**不带路径的 http(s) origin**。
///
/// 为什么必须在启动时做：`stream.rs` 用 `format!("{upstream}{path}{query}")` 拼目标 URL，
/// 所以 `upstream` 的写法直接决定每个请求长什么样。两类写法今天都会让**每一个**请求失败，
/// 却要等到第一个请求才以 502 暴露：
///   - 缺 scheme（`127.0.0.1:11434`）——YAML 里看起来毫无异常，reqwest 把解析错误推迟到 send；
///   - 尾斜杠（`http://host:11434/`）——拼出 `//v1/...`，而项目自己的
///     `proto::path::safe_upstream_path` 把空段判为不可转发，等于 agent 亲手拼出一个自己会
///     拒绝的 URL（上游对 `//v1/...` 常 404/301，而 agent 不跟随重定向）。
///
/// 尾斜杠是等价的 origin 写法（`http://h:1/` ≡ `http://h:1`），所以**规范化掉**而不是拒掉；
/// 其余会静默改变语义的一律报错。返回的值可以直接与以 `/` 开头的路径拼接。
fn normalize_upstream(raw: &str) -> anyhow::Result<String> {
    let url = reqwest::Url::parse(raw).with_context(|| {
        format!("config: upstream {raw:?} is not an absolute URL (missing scheme?)")
    })?;
    if url.scheme() != "http" && url.scheme() != "https" {
        anyhow::bail!(
            "config: upstream {raw:?} must be http or https, but is {:?}",
            url.scheme()
        );
    }
    if url.host_str().is_none() {
        anyhow::bail!("config: upstream {raw:?} has no host");
    }
    if url.query().is_some() || url.fragment().is_some() {
        anyhow::bail!("config: upstream {raw:?} must not carry a query or a fragment");
    }
    // `Url::parse` 会把"没有路径"归一成 `"/"`，所以只认 `/` 为"没有路径"。
    if url.path() != "/" {
        anyhow::bail!(
            "config: upstream {raw:?} must be a bare origin like http://127.0.0.1:11434; \
             the request path is appended to it, so a path here would be prepended to every request"
        );
    }
    Ok(raw.trim_end_matches('/').to_string())
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

    /// 规格（P2-8 agent 侧）：`heartbeat_secs: 0` 必须在加载时就拒掉。
    ///
    /// 零心跳 = 每个等待都立刻超时 → 两次失败即强制重连：网关侧会看到永不停歇的
    /// "注册 → 摘除 → 再注册"，而 agent 日志里只有心跳失败。配置文件里那个 `0` 看起来毫无异常。
    #[test]
    fn zero_heartbeat_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let yaml = format!(
            r#"
cloud_addr: "127.0.0.1:4433"
ca: "{}"
cert: "{}"
key: "{}"
heartbeat_secs: {{}}
"#,
            ca.display(),
            cert.display(),
            key.display()
        );
        let err = match from_file(parse_yaml(&yaml.replace("{}", "0"))) {
            Ok(_) => panic!("零心跳必须被拒"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("heartbeat_secs"), "报错要点名 YAML 键：{err}");

        // 正常值照样通过（别把合法配置一起拒了）
        assert!(
            from_file(parse_yaml(&yaml.replace("{}", "5"))).is_ok(),
            "非零心跳必须正常加载"
        );
    }

    /// 规格（2026-09-25 复扫 E3）：`upstream` 必须在**启动时**校验，而不是等到每个请求 502。
    ///
    /// 尾斜杠是这条的起点：`stream.rs` 用 `format!("{upstream}{path}{query}")` 拼 URL，于是
    /// `http://host:11434/` 与 `/v1/...` 拼成 `//v1/...`——而项目自己的守卫
    /// （`proto::path::safe_upstream_path`）把空段判为不可转发，等于 **agent 亲手拼出一个自己
    /// 会拒绝的 URL**；上游对 `//v1/...` 常 404/301，而 agent 明确不跟随重定向（P2-4），
    /// 所以那台机器每个请求都失败。
    ///
    /// 缺 scheme 的写法更隐蔽：YAML 里 `127.0.0.1:11434` 看起来毫无异常，而 reqwest 把 URL 解析
    /// 错误推迟到 send ⇒ 直到第一个请求才以 502 暴露。
    #[test]
    fn upstream_is_validated_at_load_time() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let load = |upstream: &str| {
            let yaml = format!(
                "cloud_addr: \"127.0.0.1:4433\"\nca: {}\ncert: {}\nkey: {}\nupstream: \"{}\"\n",
                ca.display(),
                cert.display(),
                key.display(),
                upstream
            );
            from_file(parse_yaml(&yaml))
        };

        // 尾斜杠是**等价的 origin 写法**，规范化掉即可——不能因此把一份合法配置判死。
        for ok in ["http://127.0.0.1:11434", "http://127.0.0.1:11434/"] {
            let cfg = load(ok).unwrap_or_else(|e| panic!("{ok} 应当可用：{e}"));
            assert_eq!(
                cfg.upstream_base, "http://127.0.0.1:11434",
                "{ok} 应被规范化"
            );
        }

        // 下面每一条都会让**每个请求**失败或静默改变语义 ⇒ 启动时就该报错。
        for (bad, why) in [
            ("127.0.0.1:11434", "缺 scheme"),
            ("localhost:11434", "缺 scheme"),
            ("ftp://127.0.0.1:11434", "非 http(s)"),
            (
                "http://127.0.0.1:11434/api",
                "带了路径（会被前置到每个请求上）",
            ),
            ("http://127.0.0.1:11434?a=b", "带了 query"),
            ("http://127.0.0.1:11434#frag", "带了 fragment"),
        ] {
            let err = match load(bad) {
                Ok(c) => panic!("{bad}（{why}）必须被拒，却加载成了 {:?}", c.upstream_base),
                Err(e) => e.to_string(),
            };
            assert!(
                err.contains("upstream"),
                "报错要点名 YAML 键 upstream（{bad}）：{err}"
            );
        }
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
        let cfg = from_file(parse_yaml(&yaml)).unwrap();
        assert_eq!(cfg.cloud_addr.to_string(), "1.2.3.4:4433");
        assert_eq!(cfg.server_name, "llm.example.com");
        assert_eq!(cfg.agent_id, "home-1");
        assert_eq!(cfg.upstream_base, "http://127.0.0.1:8000");
        assert_eq!(cfg.heartbeat_interval, Duration::from_secs(7));
        assert_eq!(
            cfg.models,
            vec!["qwen2.5".to_string(), "llama3".to_string()]
        );
        assert_eq!(cfg.max_concurrency, 2);
        assert!(
            cfg.request_log,
            "explicit request_log: true should be honored"
        );
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
        let cfg = from_file(parse_yaml(&yaml)).unwrap();
        assert_eq!(cfg.server_name, "localhost");
        assert_eq!(cfg.agent_id, "edge-1");
        assert_eq!(cfg.upstream_base, "http://127.0.0.1:11434");
        assert_eq!(cfg.heartbeat_interval, Duration::from_secs(5));
        assert_eq!(cfg.models, vec!["*".to_string()]);
        assert_eq!(cfg.max_concurrency, 4);
        assert!(cfg.request_log, "request_log should default to true");
    }

    #[test]
    fn missing_required_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, _, key) = gen_cert_files(dir.path());
        let yaml = format!(
            "cloud_addr: \"127.0.0.1:4433\"\nca: {}\nkey: {}\n",
            ca.to_str().unwrap(),
            key.to_str().unwrap(),
        );
        let result = from_file(parse_yaml(&yaml));
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

    #[test]
    fn from_path_reads_and_maps() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let config_path = dir.path().join("agent-config.yml");
        let yaml = format!(
            "cloud_addr: \"127.0.0.1:4433\"\nca: {}\ncert: {}\nkey: {}\n",
            ca.to_str().unwrap(),
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
        );
        std::fs::write(&config_path, &yaml).unwrap();
        let cfg = from_path(&config_path).unwrap();
        assert_eq!(cfg.cloud_addr.to_string(), "127.0.0.1:4433");
    }

    #[test]
    fn from_path_missing_file_errors() {
        assert!(from_path(&PathBuf::from("/nonexistent/agent-config.yml")).is_err());
    }
}
