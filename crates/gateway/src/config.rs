//! 网关配置：YAML 解析 → GatewayConfig 映射（从 main.rs 独立出来，便于测试与复用）。

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::Context;
use serde::Deserialize;

use crate::{storage::KeyStore, GatewayConfig, Options, TlsPem, TunnelTls};

/// YAML 配置文件结构。所有字段均有默认值；`cert`/`key`/`ca` 必须显式提供。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
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
    /// 已验证身份缓存的容量（条）。0 = 关闭缓存（每个请求都完整跑 argon2）。
    ///
    /// argon2 每次校验同时占 19MiB 工作内存，所以"每请求一次"的代价是
    /// `并发数 × 19MiB`（实测 32 并发 → 654MB，并因此 OOM）。缓存 + 单飞把它降到
    /// "每(凭据版本)一次"：每请求只做 O(1) 的 enabled/版本核对，而吊销仍然即时。
    #[serde(default = "default_verified_cache_max")]
    verified_cache_max: usize,
    /// agent 失联判定秒数
    #[serde(default = "default_agent_stale_secs")]
    agent_stale_secs: u64,
    /// 隧道「控制操作」超时秒数：打开流 + 发送请求头（+ 取消帧）。
    ///
    /// 健康隧道这些操作是**毫秒级**（本机实测全部固定开销 ≈56ms），2s 已极宽松。
    /// 为什么要设：隧道坏掉时这些 await 可能**长时间不返回**，请求就一直挂在那里占着
    /// 连接、并发槽位和缓冲区；超时即判定连接已死 → 摘掉注册表条目，请求快速失败
    /// （502），后续请求也不会再选中这条死连接。
    #[serde(default = "default_tunnel_op_secs")]
    tunnel_op_secs: u64,
    /// 等待上游**响应头**（首字节）的秒数 —— 与 `timeout_secs` 的区别很重要：
    /// 上游"思考"多久是合法的（本地大模型 1–3s 很常见），所以不能拿隧道控制超时（2s）
    /// 去卡它；但它也绝不该像 `timeout_secs` 那样等 120s —— agent 卡死（注册着但什么都
    /// 不回）时每个请求都会把连接、并发槽位和缓冲区占满那么久（实测 40 并发钉住约
    /// 620MB，客户端早已断开却无人发现）。**这里是实测确认的主要挂起点**。
    #[serde(default = "default_head_timeout_secs")]
    head_timeout_secs: u64,
    /// 摘除一条连接后等它在途请求收尾的**宽限秒数**，超过就强制关闭。
    ///
    /// 只在"摘除"这条路径上生效（连续 3 次同因隧道失败），不影响正常请求。
    /// 取值要与 `head_timeout_secs` 同量级才有意义：在途请求里既有"已送达上游、模型正在
    /// 生成"的，也有"还在等响应头"的（槽位覆盖整段响应头等待）——**比 `head_timeout_secs`
    /// 小，就会把本来还在合法等待响应头的请求一起掐断**（配小了启动时会打一条 WARN）。
    /// 也不能太大，否则 agent 迟迟察觉不到自己被摘除，变回"自认为在线的僵尸"。
    /// `0` = 不等、立刻关。默认与 `head_timeout_secs` 相同（15s，2026-09 由 5s 上调）。
    #[serde(default = "default_evict_close_grace_secs")]
    evict_close_grace_secs: u64,
    /// 「响应头静默」判据里**对端还在说话时**的静默容忍上限（秒）。
    ///
    /// 只在"响应头超时"这条路径上生效：窗口（`4 × head_timeout_secs`）内没有成功响应头时，
    /// 若对端的心跳还新鲜且静默没超过本值，就仍然按"慢"处理、不摘除（见
    /// `Options::head_silent_grace` 与评估 §5 H2）。
    /// 默认 120（= `timeout_secs`，一条请求的寿命）；**不能小于 `4 × head_timeout_secs`**，
    /// 否则这一层不会生效。`0` = 关掉这一层（回到"窗口一过就判死"）。
    #[serde(default = "default_head_silent_grace_secs")]
    head_silent_grace_secs: u64,
    /// 每个 API Key 每分钟请求上限（0 = 不限流）
    #[serde(default)]
    rate_limit_per_min: u32,
    /// HTTP 全局在途请求上限（0 = 不限；防多 key 总和压垮单实例）。
    ///
    /// 计数口径：所有路径的在途 HTTP 请求（只有 `/metrics` 豁免），SSE 长流从开始占到
    /// 最后一块 body 送完；超限返回 429 + Retry-After。
    ///
    /// **该值应按网关内存倒推**：每个在途流式请求约吃 **19 MiB，但只在缓存关闭时成立**
    /// （缓存打开时命中即不再跑 argon2；见 README《并发上限与内存》与
    /// `gateway_config.example.yml` 的同一处限定）—— 旧版本这里写"15–20MB ⇒ ≈ MemoryMax/20MB"
    /// 且**没有**这个限定，会让运维把闸门设小约 75 倍（P3-11）。
    /// 给得过大的话，先撞的是 cgroup 的 `MemoryMax`——网关被 OOM 杀掉、连接被中断，
    /// 而不是在这里优雅地返回 429，那道闸就形同虚设。
    #[serde(default)]
    max_concurrent_requests: u32,
    /// 每条 agent 连接上允许**同时在途**的隧道流数（QUIC 双向流额度）。
    ///
    /// 为什么需要它：s2n-quic 的 `initial_max_streams_bidi` 默认只有 **100**
    /// （`InitialMaxStreamsBidi::RECOMMENDED`），而实际可用额度取
    /// `min(本地额度, 对端额度)`。agent 侧已经显式给了 1000
    /// （`agent::connect_once` 的 `with_max_open_remote_bidirectional_streams(1000)`），
    /// **但网关自己的本地额度从没设过 = 100**，于是每条 agent 连接最多只能有
    /// 100 条在途请求——对端 agent 却按 `max_concurrency`（部署里是 256）对外声明
    /// 容量。超过 100 条时 `open_bidirectional_stream()` 会**排队等额度回收**，
    /// 上游一慢就等过 `tunnel_op_secs`，被误判成"隧道已死"→ 摘除整条连接 →
    /// agent 重连 → 注册表瞬间空 → 全量 503（实测一次 30s 压测 +6835 次
    /// `reason="registry-empty"`、`tunnel open timed out` 累计 9345 次）。
    ///
    /// 取值必须 **≥ 任何 agent 声明的 max_concurrency**；注册时若发现 agent 声明超了，
    /// 网关会打 WARN（否则同样的排队超时会以更难查的形式复现）。0 = 用默认值。
    #[serde(default = "default_max_open_tunnel_streams")]
    max_open_tunnel_streams: u32,
    /// 客户端"完全停滞"多久就放弃（秒）：请求体读不动、或响应体客户端不消费。
    ///
    /// 为什么必须有：准入票据（`max_concurrent_requests` 那道闸）的释放挂在 Drop 上，
    /// 但**释放的前提是那个任务/连接能结束**。以前有三处客户端侧等待**没有超时**，
    /// 任一处都能让在途请求永久占住槽位：读请求体、写响应体通道、hyper 往 socket 写响应。
    ///
    /// 实测（2026-09-18 云端）这类泄漏沉淀过 8 个僵尸槽位：`hlmg_active_requests` 恒定 8
    /// 不再下降，而 `hlmg_request_count − Σ状态码 = 8` 精确对上——即"被准入但永不结束"。
    /// 槽位只增不减，配置闸门时会被慢慢吃光（生产口径约 32，8 个就是 25%），只能重启恢复。
    ///
    /// 语义是**停滞**而不是**总时长**：只要该方向还有字节在流动就不断续期，所以慢而持续的
    /// 大 body 上传、弱网下逐块到达的 SSE 都不会被误杀；真正停住（一个字节都没有）才放弃。
    /// 默认 60s 与隧道侧逐帧空闲超时（`timeout_secs`，120s）同量级且更短，避免"上游还在
    /// 产出、客户端已僵住"时白烧 token。
    #[serde(default = "default_client_stall_secs")]
    client_stall_secs: u64,
    /// 公网入口并发连接数上限（0 = 不限）。见 `Options::max_entry_connections`：
    /// 满额时**暂停 accept**（新连接留在内核 backlog 排队），所以它是资源上限而不是限流闸。
    #[serde(default = "default_max_entry_connections")]
    max_entry_connections: usize,
    /// 关闭时强制用量落库的等待上限（秒）。见 `Options::shutdown_flush_timeout`。
    #[serde(default = "default_shutdown_flush_secs")]
    shutdown_flush_secs: u64,
    /// 关闭时等待在途请求收尾的上限（秒）。见 `Options::shutdown_grace`。
    #[serde(default = "default_shutdown_grace_secs")]
    shutdown_grace_secs: u64,
    /// 公网入口 HTTPS 证书 PEM（提供后启用 TLS，与 tls_key 成对）
    #[serde(default)]
    tls_cert: Option<PathBuf>,
    /// 公网入口 HTTPS 私钥 PEM（与 tls_cert 成对）
    #[serde(default)]
    tls_key: Option<PathBuf>,
    /// React UI 静态目录（含 index.html）。
    ///
    /// **不写这一项 = 用 [`default_ui_dir`] 的镜像内路径**（`/usr/local/share/home-llm-gateway/web`），
    /// 那是 `Dockerfile` 把前端产物 COPY 进去的位置 ⇒ 容器部署开箱即用，配置里不需要这一行。
    /// 原生（systemd）部署要显式写自己的目录（例如 `web/dist`，相对 `WorkingDirectory`）。
    /// 目录里没有可用产物时是**非致命降级**：`/` 显示构建提示页，进程照常启动。
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
/// 部署默认的 UI 目录：**镜像内那个绝对路径**（`Dockerfile` 的
/// `COPY --from=web-builder … /usr/local/share/home-llm-gateway/web`）。
///
/// 为什么是绝对路径而不是曾经的 `web/dist`：容器里 `ui_dir` 通常不写（镜像是自包含的），
/// 而相对路径按**进程 CWD** 解析 —— 镜像的 CWD 是 `/etc/home-llm-gateway`，正是配置/证书/
/// `keys.db` 的**挂载点**，镜像里放那儿的东西会被宿主目录遮住 ⇒ 曾经的默认值在容器里必然
/// 降级成"UI 未构建"。换成绝对路径后：**有配置用配置，没配置就用镜像内这份**。
/// （原生部署因此要显式写自己的目录，`gateway_config.example.yml` 里给的就是那种写法。）
fn default_ui_dir() -> Option<PathBuf> {
    Some(PathBuf::from("/usr/local/share/home-llm-gateway/web"))
}
fn default_timeout_secs() -> u64 {
    Options::DEFAULT_REQUEST_TIMEOUT.as_secs()
}
fn default_agent_stale_secs() -> u64 {
    Options::DEFAULT_AGENT_STALE_AFTER.as_secs()
}
fn default_verified_cache_max() -> usize {
    KeyStore::default_verified_max()
}
/// 隧道控制操作超时默认值（秒）。
///
/// 高并发下开流/写帧要排队过连接级流管理器，超时值直接决定"多少请求被误判"。
///
/// 实测（2026-09-17，云端 2 vCPU，768 并发）：
///   2s → 单次超时即摘除，注册表变空、503 占 92.6%（僵尸态，已由 registry::evict 修掉）
///   5s + 连续 3 次才摘除 → 4 个 agent 时零 503，但仍有 5–7% 请求是 502（隧道操作超 5s）
/// 故再放宽到 10s：坏连接仍有"连续 3 次超时"兜底（最坏 30s 判死），
/// 而健康但繁忙的连接不再因 5s 这个人为门槛被计一次失败。
fn default_tunnel_op_secs() -> u64 {
    Options::DEFAULT_TUNNEL_OP_TIMEOUT.as_secs()
}
fn default_head_timeout_secs() -> u64 {
    Options::DEFAULT_HEAD_TIMEOUT.as_secs()
}
/// 摘除宽限默认值（秒）。见 `Options::evict_close_grace`。
fn default_evict_close_grace_secs() -> u64 {
    Options::DEFAULT_EVICT_CLOSE_GRACE.as_secs()
}
/// 「对端还活着」时的静默容忍上限默认值（秒）。见 `Options::head_silent_grace`。
fn default_head_silent_grace_secs() -> u64 {
    Options::DEFAULT_HEAD_SILENT_GRACE.as_secs()
}
/// 客户端停滞阈值默认值（秒）。见字段注释：语义是"该方向不再有字节流动"，
/// 所以对慢而持续的传输无影响；60s 足以覆盖人类可感知的正常停顿。
fn default_client_stall_secs() -> u64 {
    Options::DEFAULT_CLIENT_STALL.as_secs()
}
/// 公网入口并发连接数默认上限。见 `Options::max_entry_connections`：
/// 1024 是"README 实测 768 并发客户端、fd 峰值 785"之上留了余量的水位。
fn default_max_entry_connections() -> usize {
    Options::DEFAULT_MAX_ENTRY_CONNECTIONS
}
/// 关闭落库等待上限默认值（秒）。见 `Options::shutdown_flush_timeout`。
fn default_shutdown_flush_secs() -> u64 {
    Options::DEFAULT_SHUTDOWN_FLUSH_TIMEOUT.as_secs()
}
/// 关闭排空等待上限默认值（秒）。见 `Options::shutdown_grace`。
fn default_shutdown_grace_secs() -> u64 {
    Options::DEFAULT_SHUTDOWN_GRACE.as_secs()
}
/// 每连接隧道流额度默认值。
///
/// 1024 的依据：agent 的 `max_concurrency` 默认只有 4（见 `agent::default_max_concurrency`），
/// 实测部署里手填的是 256；1024 对"单连接 256 并发"留了 4 倍余量，又远小于
/// 一个连接能承受的流数上限（s2n-quic 的 VarInt 上限是 2^60，真正的约束是内存）。
/// 想让网关收紧每 agent 在途量时，**调 `max_concurrent_requests` 或 agent 的
/// `max_concurrency`**，而不是靠把这里调小去当限流闸——调小只会让开流排队超时，
/// 表现为"隧道随机超时"（见字段注释）。
fn default_max_open_tunnel_streams() -> u32 {
    Options::DEFAULT_MAX_OPEN_TUNNEL_STREAMS
}

/// 从 YAML 文件加载并映射为网关配置。
pub fn from_path(path: &PathBuf) -> anyhow::Result<GatewayConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read config file {}", path.display()))?;
    let file_cfg: ConfigFile = serde_yaml_ng::from_str(&text)
        .with_context(|| format!("invalid config file {}", path.display()))?;
    from_file(file_cfg)
}

/// 把 YAML 配置映射为网关配置（独立函数，便于单元测试）。
///
/// 这里是**唯一**的 YAML 字段名 → 类型化旋钮映射点：`Options` 的每个字段都显式写出来，
/// 这是映射的职责；测试与库调用方则用 `..Options::default()` 只写自己要改的那些。
pub fn from_file(cfg: ConfigFile) -> anyhow::Result<GatewayConfig> {
    if cfg.cert.as_os_str().is_empty()
        || cfg.key.as_os_str().is_empty()
        || cfg.ca.as_os_str().is_empty()
    {
        anyhow::bail!("config: cert/key/ca paths are required");
    }
    let tunnel = TunnelTls::from_pem_files(&cfg.ca, &cfg.cert, &cfg.key)
        .context("config: cannot load the tunnel cert/key/ca")?;
    let https = match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(c), Some(k)) => Some(
            TlsPem::from_pem_files(c, k)
                .with_context(|| format!("config: cannot read {}", c.display()))?,
        ),
        (None, None) => None,
        _ => anyhow::bail!("config: tls_cert and tls_key must be provided together"),
    };

    Ok(GatewayConfig {
        tunnel,
        opts: Options {
            http_bind: cfg
                .listen_addr
                .parse::<SocketAddr>()
                .with_context(|| format!("config: invalid listen_addr {:?}", cfg.listen_addr))?,
            quic_bind: cfg
                .quic_addr
                .parse::<SocketAddr>()
                .with_context(|| format!("config: invalid quic_addr {:?}", cfg.quic_addr))?,
            https,
            admin_token: cfg.admin_token,
            keys_file: cfg.keys_file,
            ui_dir: cfg.ui_dir,
            verified_cache_max: cfg.verified_cache_max,
            request_timeout: Duration::from_secs(cfg.timeout_secs),
            tunnel_op_timeout: Duration::from_secs(cfg.tunnel_op_secs),
            head_timeout: Duration::from_secs(cfg.head_timeout_secs),
            evict_close_grace: Duration::from_secs(cfg.evict_close_grace_secs),
            head_silent_grace: Duration::from_secs(cfg.head_silent_grace_secs),
            agent_stale_after: Duration::from_secs(cfg.agent_stale_secs),
            client_stall: Duration::from_secs(cfg.client_stall_secs),
            max_entry_connections: cfg.max_entry_connections,
            shutdown_flush_timeout: Duration::from_secs(cfg.shutdown_flush_secs),
            shutdown_grace: Duration::from_secs(cfg.shutdown_grace_secs),
            rate_limit_per_min: cfg.rate_limit_per_min,
            max_concurrent_requests: cfg.max_concurrent_requests,
            // 原样带过去：`0 → 默认值`的归一只有一处，在 `Options::stream_ceiling()`。
            max_open_tunnel_streams: cfg.max_open_tunnel_streams,
        },
    })
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
        let cfg = from_file(parse_yaml(&yaml)).unwrap();
        assert_eq!(cfg.opts.http_bind.to_string(), "0.0.0.0:8443");
        assert_eq!(cfg.opts.quic_bind.to_string(), "0.0.0.0:4433");
        assert_eq!(cfg.opts.admin_token.as_deref(), Some("admin"));
        assert_eq!(cfg.opts.keys_file, Some(dir.path().join("keys.db")));
        assert_eq!(cfg.opts.request_timeout, Duration::from_secs(30));
        assert_eq!(cfg.opts.agent_stale_after, Duration::from_secs(20));
        assert_eq!(cfg.opts.rate_limit_per_min, 60);
        assert!(cfg.opts.https.is_none());
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
        let cfg = from_file(parse_yaml(&yaml)).unwrap();
        assert_eq!(
            cfg.opts.http_bind.to_string(),
            "0.0.0.0:8080",
            "default listen_addr"
        );
        assert_eq!(
            cfg.opts.quic_bind.to_string(),
            "0.0.0.0:4433",
            "default quic_addr"
        );
        assert_eq!(cfg.opts.request_timeout, Duration::from_secs(120));
        assert_eq!(cfg.opts.agent_stale_after, Duration::from_secs(15));
        assert_eq!(cfg.opts.rate_limit_per_min, 0);
        assert!(cfg.opts.admin_token.is_none());
        assert_eq!(cfg.opts.keys_file, Some(PathBuf::from("keys.db")));
        assert!(cfg.opts.https.is_none());
    }

    #[test]
    fn missing_required_paths_rejected() {
        let result = from_file(parse_yaml("listen_addr: \"0.0.0.0:8443\"\n"));
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
        let cfg = from_file(parse_yaml(&yaml)).unwrap();
        let tls = cfg.opts.https.expect("tls pair should be loaded");
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
        assert!(from_file(parse_yaml(&yaml)).is_err());
    }

    #[test]
    fn invalid_yaml_rejected() {
        assert!(serde_yaml_ng::from_str::<ConfigFile>("listen_addr: [unclosed").is_err());
    }

    #[test]
    fn unknown_fields_rejected() {
        assert!(serde_yaml_ng::from_str::<ConfigFile>("nonsense_field: 1").is_err());
    }

    /// `gateway_config.example.yml` 必须始终能解析，并且**覆盖到新增的字段**。
    ///
    /// 为什么值得一条测试：`ConfigFile` 开了 `deny_unknown_fields`，示例文件写错字段名
    /// 会直接导致「照抄示例 → 网关起不来」；反过来新增字段若忘了写进示例，用户也看不到
    /// 这个开关的存在（`tunnel_op_secs` / `head_timeout_secs` 就是这类旋钮）。
    #[test]
    fn example_config_parses_and_documents_knobs() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../gateway_config.example.yml");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("读不到 {}: {e}", path.display()));
        let cfg: ConfigFile = serde_yaml_ng::from_str(&text)
            .unwrap_or_else(|e| panic!("{} 解析失败（字段名写错？）: {e}", path.display()));
        // 每个超时开关都必须出现在示例里，否则用户无从知道
        for key in [
            "timeout_secs",
            "tunnel_op_secs",
            "head_timeout_secs",
            "evict_close_grace_secs",
            "head_silent_grace_secs",
            "max_open_tunnel_streams",
            "max_entry_connections",
            "client_stall_secs",
            "shutdown_flush_secs",
            "shutdown_grace_secs",
        ] {
            assert!(
                text.contains(key),
                "gateway_config.example.yml 缺少配置项说明：{key}"
            );
        }
        assert_eq!(cfg.tunnel_op_secs, default_tunnel_op_secs());
        assert_eq!(cfg.head_timeout_secs, default_head_timeout_secs());
        assert_eq!(cfg.evict_close_grace_secs, default_evict_close_grace_secs());
        assert_eq!(cfg.head_silent_grace_secs, default_head_silent_grace_secs());
        assert_eq!(
            cfg.max_open_tunnel_streams,
            default_max_open_tunnel_streams()
        );
        assert_eq!(cfg.client_stall_secs, default_client_stall_secs());
        assert_eq!(cfg.max_entry_connections, default_max_entry_connections());
        assert_eq!(cfg.shutdown_flush_secs, default_shutdown_flush_secs());
        assert_eq!(cfg.shutdown_grace_secs, default_shutdown_grace_secs());
    }

    /// 规格：**流额度不能是 0**。
    ///
    /// 0 在 s2n-quic 里意味着"一条双向流都不许开"，而不是"不限"——直接照抄进
    /// `with_max_open_local_bidirectional_streams` 会让网关连注册流都开不出来，
    /// 表现是"agent 永远注册不上"，与配置字面意思（0 = 不限/默认）完全相反。
    #[test]
    fn zero_max_open_tunnel_streams_falls_back_to_the_default() {
        assert!(default_max_open_tunnel_streams() >= 256);
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        // YAML 里显式写 0 必须能解析，且不能原样传给 s2n-quic ——
        // 在 s2n-quic 里 0 的意思是"一条双向流都不许开"（不是"不限"），
        // 照抄进去会让网关连 agent 的注册流都开不出来，表现是"agent 永远注册不上"。
        let yaml = format!(
            "cert: {}\nkey: {}\nca: {}\nmax_open_tunnel_streams: 0\n",
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            ca.to_str().unwrap(),
        );
        assert_eq!(parse_yaml(&yaml).max_open_tunnel_streams, 0);
        assert_eq!(
            from_file(parse_yaml(&yaml)).unwrap().opts.stream_ceiling(),
            default_max_open_tunnel_streams()
        );

        // 显式给非 0 值时按原值生效（运维要能收紧/放宽额度）
        let yaml = format!(
            "cert: {}\nkey: {}\nca: {}\nmax_open_tunnel_streams: 300\n",
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            ca.to_str().unwrap(),
        );
        assert_eq!(
            from_file(parse_yaml(&yaml)).unwrap().opts.stream_ceiling(),
            300
        );

        // 省略时用默认值
        let yaml = format!(
            "cert: {}\nkey: {}\nca: {}\n",
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            ca.to_str().unwrap(),
        );
        assert_eq!(
            from_file(parse_yaml(&yaml)).unwrap().opts.stream_ceiling(),
            default_max_open_tunnel_streams()
        );
    }

    #[test]
    fn from_path_reads_and_maps() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let config_path = dir.path().join("config.yml");
        let yaml = format!(
            "listen_addr: \"127.0.0.1:8080\"\nquic_addr: \"127.0.0.1:4433\"\ncert: {}\nkey: {}\nca: {}\n",
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            ca.to_str().unwrap(),
        );
        std::fs::write(&config_path, &yaml).unwrap();
        let cfg = from_path(&config_path).unwrap();
        assert_eq!(cfg.opts.http_bind.to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn from_path_missing_file_errors() {
        assert!(from_path(&PathBuf::from("/nonexistent/config.yml")).is_err());
    }

    /// 规格：**数值旋钮的默认值只能有一个说法**。
    ///
    /// 默认值现在有两处落点：`Options::default()`（库 / 测试调用方）与这里的 serde
    /// `default_*`（部署，YAML 省略该字段时）。端口与落盘位置**刻意不同**——库默认密闭
    /// （临时端口、不碰任何文件），部署默认是 `0.0.0.0:8080` / `keys.db`——但所有
    /// `Duration` / 数量旋钮必须一致：否则同一条 `timeout_secs` 的默认值会有两个说法，
    /// "文档写的是哪一个"就变成靠记忆。这条测试把两者钉在一起。
    #[test]
    fn yaml_defaults_and_options_default_agree_on_the_tuning_knobs() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, cert, key) = gen_cert_files(dir.path());
        let yaml = format!(
            "cert: {}\nkey: {}\nca: {}\n",
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            ca.to_str().unwrap(),
        );
        let opts = from_file(parse_yaml(&yaml)).unwrap().opts;
        let d = Options::default();

        assert_eq!(opts.request_timeout, d.request_timeout, "timeout_secs");
        assert_eq!(
            opts.tunnel_op_timeout, d.tunnel_op_timeout,
            "tunnel_op_secs"
        );
        assert_eq!(opts.head_timeout, d.head_timeout, "head_timeout_secs");
        assert_eq!(
            opts.evict_close_grace, d.evict_close_grace,
            "evict_close_grace_secs"
        );
        assert_eq!(
            opts.head_silent_grace, d.head_silent_grace,
            "head_silent_grace_secs"
        );
        assert_eq!(
            opts.agent_stale_after, d.agent_stale_after,
            "agent_stale_secs"
        );
        assert_eq!(opts.client_stall, d.client_stall, "client_stall_secs");
        assert_eq!(
            opts.shutdown_flush_timeout, d.shutdown_flush_timeout,
            "shutdown_flush_secs"
        );
        assert_eq!(opts.shutdown_grace, d.shutdown_grace, "shutdown_grace_secs");
        assert_eq!(opts.verified_cache_max, d.verified_cache_max);
        assert_eq!(opts.rate_limit_per_min, d.rate_limit_per_min);
        assert_eq!(opts.max_concurrent_requests, d.max_concurrent_requests);
        assert_eq!(
            opts.max_open_tunnel_streams, d.max_open_tunnel_streams,
            "max_open_tunnel_streams"
        );
        assert_eq!(opts.stream_ceiling(), d.stream_ceiling());

        // 刻意不同：库默认密闭（内核分配端口、不读不写任何文件），部署默认面向公网
        assert_ne!(opts.http_bind, d.http_bind, "库默认不绑公网端口");
        assert_ne!(opts.keys_file, d.keys_file, "库默认不碰 keys.db");
        // 部署的 UI 默认必须**钉死成镜像内那个绝对路径**：容器里配置通常不写 `ui_dir`
        // （镜像是自包含的），所以这个默认值就是容器唯一的 UI 入口 —— 写成相对路径
        // （曾经的 `web/dist`）会落在挂载点 `/etc/home-llm-gateway` 里、被宿主目录遮住。
        assert_eq!(
            opts.ui_dir,
            Some(std::path::PathBuf::from(
                "/usr/local/share/home-llm-gateway/web"
            )),
            "部署默认 UI 目录 = 镜像内路径（Dockerfile 的 COPY 目标）"
        );
        assert!(d.ui_dir.is_none(), "库默认不读 UI 目录");
    }
}
