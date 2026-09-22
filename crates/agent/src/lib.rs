//! edge-agent：常驻 LLM 所在机器（edge 节点），主动拨 QUIC 长连接上云，把云端请求转发给本地 LLM。

pub mod tls;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use proto::{
    io::{write_frame, FrameReader},
    Frame,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use s2n_quic::{client::Connect, provider::limits::Limits};
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info, warn};

use crate::stream::handle_stream;

pub mod config;
pub mod error;
pub mod stream;

pub struct AgentConfig {
    /// 云端网关 QUIC 地址。
    pub cloud_addr: SocketAddr,
    /// 证书校验用的服务器名（须与网关证书 SAN 匹配）。
    pub server_name: String,
    pub ca_cert: Vec<CertificateDer<'static>>,
    pub client_cert: Vec<CertificateDer<'static>>,
    pub client_key: PrivateKeyDer<'static>,
    pub agent_id: String,
    pub models: Vec<String>,
    pub max_concurrency: u32,
    /// 本地 LLM 的 OpenAI 兼容地址，如 http://127.0.0.1:11434
    pub upstream_base: String,
    pub heartbeat_interval: Duration,
    /// 是否打印每请求的转发日志（received/responded/done/cancelled）。
    /// 高并发/压测时建议关闭，避免日志刷屏；连接/注册等低频日志不受此开关影响。
    pub request_log: bool,
}

pub struct Agent {
    task: tokio::task::JoinHandle<()>,
}

impl Agent {
    pub fn start(cfg: AgentConfig) -> anyhow::Result<Self> {
        // provider 由 `tls::rustls_client_tls` 自己确保（幂等），这里不再需要显式安装。
        let client_config = tls::rustls_client_tls(
            &cfg.ca_cert,
            cfg.client_cert.clone(),
            cfg.client_key.clone_key(),
        )?;
        // 外层包一层守护：run 正常**永不返回**，一旦返回（panic / 被取消），进程就只是
        // "看起来还在运行"——main 停在 shutdown_signal()，既不重连也不退出，日志里也
        // 什么都没有。所以这里喊出来并让进程退出，交给外部守护重新拉起
        // （deploy/agent.service 是 Restart=always / RestartSec=3）。静默的僵尸进程
        // 比一次崩溃难查得多。
        let task = tokio::spawn(async move {
            let mut inner = AbortOnDrop(tokio::spawn(run(cfg, client_config)));
            match (&mut inner.0).await {
                Ok(()) => error!("agent run loop exited; exiting so the supervisor restarts us"),
                Err(e) if e.is_panic() => {
                    error!("agent run loop panicked: {e}; exiting so the supervisor restarts us")
                }
                Err(e) => warn!("agent run loop cancelled: {e}"),
            }
            std::process::exit(1);
        });
        Ok(Self { task })
    }

    pub async fn shutdown(self) {
        self.task.abort();
    }
}

/// 内层 run 任务的 Drop 兜底：外层被 abort（`Agent::shutdown`）时连带把它也 abort。
/// 没有这层，`shutdown()` 只会停掉包装任务，真正的连接循环会变成孤儿继续跑。
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// 重连退避基准（第一次重连等这么久）。
const BACKOFF_BASE: Duration = Duration::from_millis(500);
/// 标称上限。DESIGN §6.1 原设计是"抖动 + 上限 60s"，这里刻意取 30s：网关滚动重启后
/// agent 回归更快；握手风暴的余地由 `connect_once` 里的 30s 握手限时给（那段注释解释了
/// 为什么不能更短）。
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// 会话活过这么久才算"健康"，断开时才把退避重置回基准。
///
/// 阈值存在的唯一理由是记录 P2-1 那个根因：`connect_once` 返回 `Ok(())` 有**两种**语义——
/// "健康跑了很久后断开" 与 "刚注册就被踢"（如同名 `agent_id` 互踢、网关注册后立刻关连接）。
/// 旧代码把两者都当成前者、退避一律重置回 500ms，于是每 ~500ms 互踢一次、永不收敛
/// （实测：3 秒内 5 次连接、6 个 `/v1/slow` 全 502，而两侧进程与 `/admin/agents` 都正常）。
/// 现在**只看会话活了多久**，与 Ok/Err 无关。
const BACKOFF_RESET_AFTER: Duration = Duration::from_secs(60);
/// 抖动幅度（百分比）：多台 agent 同时断线（网关重启）时不要把重连挤在同一毫秒。
const BACKOFF_JITTER_PERCENT: u64 = 20;

/// 下一轮的标称退避：会话活得够久才重置，否则翻倍（封顶 [`BACKOFF_MAX`]）。
fn next_backoff(current: Duration, session_alive: Duration) -> Duration {
    if session_alive >= BACKOFF_RESET_AFTER {
        BACKOFF_BASE
    } else {
        std::cmp::min(current.saturating_mul(2), BACKOFF_MAX)
    }
}

/// 给标称退避加 ±[`BACKOFF_JITTER_PERCENT`]% 抖动，并**仍然封顶** [`BACKOFF_MAX`]
/// （顶上因此是单边缩小：一撮 agent 落在 `[24s, 30s]` 而不是同一个 30s）。
///
/// `entropy` 由调用方给：生产用时钟纳秒，测试直接喂值——策略是纯函数，才钉得住。
fn jittered(backoff: Duration, entropy: u64) -> Duration {
    let span = BACKOFF_JITTER_PERCENT * 2;
    let percent = 100 - BACKOFF_JITTER_PERCENT + (entropy % (span + 1));
    let micros = backoff.as_micros() * u128::from(percent) / 100;
    std::cmp::min(Duration::from_micros(micros as u64), BACKOFF_MAX)
}

/// 抖动的熵：不引入 `rand` 依赖（只为一个 ±20% 的抖动不值当），用时钟纳秒 + 秒数混合。
fn jitter_entropy() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()) ^ d.as_secs())
        .unwrap_or(0)
}

async fn run(cfg: AgentConfig, client_config: rustls::ClientConfig) {
    let mut backoff = BACKOFF_BASE;
    loop {
        let started = std::time::Instant::now();
        let outcome = connect_once(&cfg, client_config.clone()).await;
        let session_alive = started.elapsed();
        // 先算出真正要等多久再打日志：日志里的值必须就是实际睡的值（排查时据此对齐
        // 两侧时间线），而且抖动过的值才看得出"多台机器错开了"。
        let wait = jittered(backoff, jitter_entropy());
        match outcome {
            Ok(()) => info!(
                session_alive_secs = session_alive.as_secs(),
                wait_ms = wait.as_millis(),
                "disconnected from cloud, reconnecting"
            ),
            Err(e) => warn!(
                session_alive_secs = session_alive.as_secs(),
                wait_ms = wait.as_millis(),
                "agent error: {e}; retrying"
            ),
        }
        tokio::time::sleep(wait).await;
        backoff = next_backoff(backoff, session_alive);
    }
}

async fn connect_once(
    cfg: &AgentConfig,
    client_config: rustls::ClientConfig,
) -> anyhow::Result<()> {
    // let limits = Limits::new().with_max_idle_timeout(Duration::from_secs(20))?; // 对齐 quinn 时代的 20s
    let limits = Limits::new()
        .with_max_idle_timeout(Duration::from_secs(20))?
        .with_max_open_remote_bidirectional_streams(1000)?
        // s2n-quic 默认握手限时 10s（`MAX_HANDSHAKE_DURATION_DEFAULT`）。实测在网关
        // 高并发（数百条流在途）时新连接握不上手，日志是
        // `MaxHandshakeDurationExceeded { max_handshake_duration: 10s }`，
        // 于是"心跳超时→断开→重连→握手又超时"形成风暴。放到 30s 给拥塞留余地；
        // 真正的重连退避由 `run()` 的指数退避负责（上限 30s）。
        .with_max_handshake_duration(Duration::from_secs(30))?;

    // 不设 with_max_idle_timeout 时默认 30s（MaxIdleTimeout::RECOMMENDED）
    let client = s2n_quic::Client::builder()
        .with_tls(s2n_quic::provider::tls::rustls::Client::from(Arc::new(
            client_config,
        )))?
        .with_io("0.0.0.0:0")?
        .with_limits(limits)?
        .start()?;
    let mut conn = client
        .connect(Connect::new(cfg.cloud_addr).with_server_name(cfg.server_name.clone()))
        .await?;

    // 保活：s2n-quic 的周期 = min(本端 max_idle_timeout × 3/4, max_keep_alive_period)
    // —— 这里是 min(20s × 3/4, 30s) = 15s。它小于协商出的空闲超时
    //    （min(本端 20s, 网关 30s) = 20s），网关才不会把连接判空闲关掉。
    //    公式见 s2n-quic-transport 的 `KeepAlive::new`（用的是本端 limits，不是协商值）；
    //    `max_keep_alive_period` 默认 30s。
    conn.keep_alive(true)?;

    // ① 先拆：Handle 用来"开流"（Register/Heartbeat），acceptor 用来"收流"（代理请求）
    let (handle, mut acceptor) = conn.split();

    info!("connected to cloud gateway at {}", cfg.cloud_addr);

    // ② Register 用 handle 开一条流发注册帧
    register(handle.clone(), cfg).await?;

    info!(agent_id = %cfg.agent_id, models = ?cfg.models,max_concurrenty = cfg.max_concurrency,"registered with cloud gateway");

    // ③ 心跳任务拿到 handle 的 clone（各任务一份，互不冲突）
    let mut hb = tokio::spawn(heartbeat_loop(
        handle.clone(),
        cfg.agent_id.clone(),
        cfg.heartbeat_interval,
    ));

    let http = reqwest::Client::new();
    // ④ accept 循环用 acceptor（单消费者，独占）
    //
    // 和心跳**并跑**，而不是各跑各的：心跳是网关判定"这个 agent 还活着"的唯一依据
    // （网关侧 stale 判定默认 15s，agent 侧心跳默认 5s 一次）。心跳任务一旦结束，
    // 哪怕 QUIC 连接本身还开着，这条连接在网关眼里也已经死了 —— 表现是"agent 自认为
    // 连着、网关把所有请求判 503、两侧都没有日志、只能人工重启"的静默态。
    // 所以必须观察它：它一结束就结束这条连接，交回 run() 的重连循环。
    loop {
        tokio::select! {
            r = &mut hb => {
                match r {
                    Ok(Ok(())) => warn!("heartbeat loop exited; forcing reconnect"),
                    Ok(Err(e)) => warn!("heartbeat loop failed: {e}; forcing reconnect"),
                    Err(e) if e.is_panic() => error!("heartbeat loop panicked: {e}; forcing reconnect"),
                    Err(e) => warn!("heartbeat task cancelled: {e}; forcing reconnect"),
                }
                break;
            }
            accepted = acceptor.accept_bidirectional_stream() => match accepted {
                Ok(Some(stream)) => {
                    tokio::spawn(handle_stream(
                        stream,
                        http.clone(),
                        cfg.upstream_base.clone(),
                        cfg.request_log,
                    ));
                }
                Ok(None) => break, // 连接正常关闭
                Err(e) => {
                    warn!("accept stream failed: {e}");
                    break;
                }
            },
        }
    }

    hb.abort();
    Ok(())
}

async fn register(mut conn: s2n_quic::connection::Handle, cfg: &AgentConfig) -> anyhow::Result<()> {
    // open a new stream and split the receiving and sending sides
    let stream = conn.open_bidirectional_stream().await?;
    let client_id = stream.id();
    // 曾经是 println!：没有时间戳、没有级别，混在日志里像噪声，措辞也不对
    // （注册的是 agent，不是 server）。
    debug!(client_id, "registering with cloud gateway");

    let (recv, mut send) = stream.split();

    write_frame(
        &mut send,
        &Frame::Register {
            agent_id: cfg.agent_id.clone(),
            models: cfg.models.clone(),
            max_concurrency: cfg.max_concurrency,
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
    )
    .await?;
    send.finish()?;
    // // 网关不发 ack；读到 EOF 即可
    let mut reader = FrameReader::new(recv);
    tokio::time::timeout(Duration::from_secs(10), reader.next())
        .await
        .map_err(|_| anyhow::anyhow!("register timed out waiting for gateway EOF"))? // 超时
        .map_err(|e| anyhow::anyhow!("register read failed: {e}"))?; // io::Error

    Ok(())
}

async fn heartbeat_loop(
    mut conn: s2n_quic::connection::Handle,
    agent_id: String,
    interval: Duration,
) -> anyhow::Result<()> {
    // 单次心跳的等待上限：**与心跳间隔解耦**。原来是硬编码 5s，恰好等于默认的
    // 5s 心跳间隔、零余量；而满负载时 `open_bidirectional_stream()` 要抢连接级流
    // 管理器，稍一排队就超时——一次超时就把整条连接拆掉，代价是此后十几秒内网关
    // 没有任何健康 agent（所有请求 503）。取 3× 间隔（默认 15s）留出排队余量。
    let wait = interval.saturating_mul(3);
    // 允许连续失败次数：一次超时不代表连接坏了，但也不能无限忍——否则网关早已按
    // stale 判死（默认 15s），agent 还抱着连接不动。
    //
    // 取 2 的算式（默认 interval=5s、wait=15s）：容忍窗口 ≈
    // `2 × interval + wait` = 10 + 15 = 25s，略大于网关的 stale 窗口 15s，
    // 即"还在容忍"期间网关最多已经判了 10s 的 stale —— 再长就等于装死。
    const MAX_CONSECUTIVE_FAILURES: u32 = 2;
    let mut failures = 0u32;
    loop {
        tokio::time::sleep(interval).await;
        match heartbeat_once(&mut conn, &agent_id, wait).await {
            Ok(()) => failures = 0,
            Err(e) => {
                failures += 1;
                warn!(
                    failures,
                    max = MAX_CONSECUTIVE_FAILURES,
                    "heartbeat failed: {e}; will keep the connection until failures accumulate"
                );
                if failures >= MAX_CONSECUTIVE_FAILURES {
                    return Err(anyhow::anyhow!(
                        "heartbeat failed {failures} times in a row: {e}"
                    ));
                }
            }
        }
    }
}

/// 发一次心跳并等网关回包；整体（开流 + 写帧 + 收帧）受 `wait` 约束。
async fn heartbeat_once(
    conn: &mut s2n_quic::connection::Handle,
    agent_id: &str,
    wait: Duration,
) -> anyhow::Result<()> {
    let exchange = async {
        // 心跳走一条独立短流（开→写→半关→读完），不与业务流共用编码状态
        let stream = conn.open_bidirectional_stream().await?;
        let (recv, mut send) = stream.split();
        write_frame(
            &mut send,
            &Frame::Heartbeat {
                agent_id: agent_id.to_string(),
                inflight: 0,
            },
        )
        .await?;
        send.shutdown().await?;
        let mut reader = FrameReader::new(recv);
        while reader.next().await?.is_some() {}
        Ok::<(), anyhow::Error>(())
    };
    tokio::time::timeout(wait, exchange)
        .await
        .map_err(|_| anyhow::anyhow!("heartbeat timed out after {wait:?}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::ALPN;

    /// 规格（记录 P2-1）：**"连上就被踢"不许把退避重置回 500ms**。
    ///
    /// 这是同名 `agent_id` 互踢"每 ~500ms 一次、永不收敛"的根因：`connect_once` 返回
    /// `Ok(())` 有两种语义，旧代码把"刚注册就被踢"也当成"健康跑了很久后断开"。
    /// 判据：会话只活了毫秒级时，退避必须**继续增长/保持在上限**，绝不能回到基准。
    #[test]
    fn a_short_lived_session_does_not_reset_the_backoff() {
        let short = Duration::from_millis(5);
        assert_eq!(
            next_backoff(BACKOFF_BASE, short),
            BACKOFF_BASE * 2,
            "短命会话必须继续退避"
        );
        assert_eq!(
            next_backoff(Duration::from_secs(2), short),
            Duration::from_secs(4)
        );
        assert_eq!(
            next_backoff(BACKOFF_MAX, short),
            BACKOFF_MAX,
            "已经到顶就保持在顶，而不是被打回基准（这正是互踢风暴的形状）"
        );
    }

    /// 规格：会话活得够久 = 真的健康过，断开时才把退避重置回基准。
    #[test]
    fn a_long_lived_session_resets_the_backoff() {
        assert_eq!(next_backoff(BACKOFF_MAX, BACKOFF_RESET_AFTER), BACKOFF_BASE);
        assert_eq!(
            next_backoff(Duration::from_secs(4), BACKOFF_RESET_AFTER * 10),
            BACKOFF_BASE
        );
        // 边界：差一毫秒不算健康
        assert_eq!(
            next_backoff(BACKOFF_MAX, BACKOFF_RESET_AFTER - Duration::from_millis(1)),
            BACKOFF_MAX
        );
    }

    /// 规格：连续失败/短命会话下退避**单调增长到上限并停在那儿**（旧代码在每条
    /// `Ok(())` 上都重置，所以永远停在 500ms）。
    #[test]
    fn the_backoff_grows_to_the_cap_and_stays_there() {
        let mut backoff = BACKOFF_BASE;
        let mut seen = vec![backoff];
        for _ in 0..12 {
            backoff = next_backoff(backoff, Duration::from_millis(1));
            seen.push(backoff);
        }
        assert_eq!(
            seen,
            vec![
                Duration::from_millis(500),
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(16),
                Duration::from_secs(30),
                Duration::from_secs(30),
                Duration::from_secs(30),
                Duration::from_secs(30),
                Duration::from_secs(30),
                Duration::from_secs(30),
                Duration::from_secs(30),
            ],
            "退避序列必须是 500ms 起翻倍、封顶 30s"
        );
    }

    /// 规格：抖动必须在 ±20% 之内、**两端都能取到**（否则就是"加了抖动"的自述），
    /// 且封顶之后不许超过上限。
    #[test]
    fn jitter_stays_within_bounds_reaches_both_ends_and_respects_the_cap() {
        let base = Duration::from_secs(1);
        let values: Vec<Duration> = (0..=40).map(|e| jittered(base, e)).collect();
        for v in &values {
            assert!(
                *v >= Duration::from_millis(800) && *v <= Duration::from_millis(1200),
                "抖动越界：{v:?}（基准 {base:?}）"
            );
        }
        assert!(
            values.iter().any(|v| *v < base),
            "必须能取到向下的一侧：{values:?}"
        );
        assert!(
            values.iter().any(|v| *v > base),
            "必须能取到向上的一侧：{values:?}"
        );
        // 熵只影响结果、不该把结果挤成常量（"抖了但都一样"等于没抖）
        let distinct: std::collections::BTreeSet<u128> =
            values.iter().map(|v| v.as_micros()).collect();
        assert!(distinct.len() >= 5, "抖动值太集中：{distinct:?}");

        // 顶上单边缩小：仍然封顶，不会超过标称上限
        for e in 0..=40 {
            let capped = jittered(BACKOFF_MAX, e);
            assert!(
                capped <= BACKOFF_MAX,
                "抖动后不得超过标称上限（e={e}）：{capped:?}"
            );
            assert!(
                capped >= BACKOFF_MAX * 4 / 5,
                "顶上也不该掉太多：{capped:?}"
            );
        }
    }

    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, SanType,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use s2n_quic::connection::{Handle, StreamAcceptor};
    use std::sync::Arc;

    /// 生成 (CA, 服务端证书, 服务端私钥, 客户端证书, 客户端私钥) 的 DER。
    fn gen_pki() -> (
        CertificateDer<'static>,
        CertificateDer<'static>,
        PrivateKeyDer<'static>,
        CertificateDer<'static>,
        PrivateKeyDer<'static>,
    ) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "test ca");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let srv_key = KeyPair::generate().unwrap();
        let mut srv = CertificateParams::default();
        srv.distinguished_name.push(DnType::CommonName, "gw");
        srv.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
        srv.is_ca = IsCa::NoCa;
        srv.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        srv.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let srv_cert = srv.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();

        let cli_key = KeyPair::generate().unwrap();
        let mut cli = CertificateParams::default();
        cli.distinguished_name.push(DnType::CommonName, "agent");
        cli.is_ca = IsCa::NoCa;
        cli.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        cli.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let cli_cert = cli.signed_by(&cli_key, &ca_cert, &ca_key).unwrap();

        (
            ca_cert.der().clone(),
            srv_cert.der().clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(srv_key.serialize_der())),
            cli_cert.der().clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cli_key.serialize_der())),
        )
    }

    /// 建立一个本地的 s2n-quic 连接对（无 mTLS），返回客户端 [`Handle`]。
    /// 服务端只保活连接、不读流。
    async fn test_connection() -> Handle {
        // 本测试直接构建 rustls 配置（绕过 tls 构造函数）→ 自己确保 provider 已装。
        proto::crypto::provider();

        // 服务端：自签证书 + 无客户端认证
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

        let mut stls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        stls.alpn_protocols = vec![ALPN.to_vec()];

        let mut server = s2n_quic::Server::builder()
            .with_tls(s2n_quic::provider::tls::rustls::Server::from(Arc::new(
                stls,
            )))
            .unwrap()
            .with_io("127.0.0.1:0")
            .unwrap()
            .start()
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        // 服务端 accept 一条连接并保活：别返回，返回会 drop 句柄导致连接关闭
        tokio::spawn(async move {
            let conn = server.accept().await.expect("client should connect");
            let (_handle, _acceptor) = conn.split();
            std::future::pending::<()>().await;
        });

        // 客户端：信任自签证书，无客户端证书
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let mut ctls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        ctls.alpn_protocols = vec![ALPN.to_vec()];

        let client = s2n_quic::Client::builder()
            .with_tls(s2n_quic::provider::tls::rustls::Client::from(Arc::new(
                ctls,
            )))
            .unwrap()
            .with_io("0.0.0.0:0")
            .unwrap()
            .start()
            .unwrap();
        let conn = client
            .connect(s2n_quic::client::Connect::new(server_addr).with_server_name("localhost"))
            .await
            .unwrap();
        let (handle, _acceptor) = conn.split();
        handle
    }

    /// 用 CA 签发的服务端证书建 mTLS s2n-quic server，把每条接入连接的 [`Handle`] 发给测试。
    async fn test_server(
        ca: &CertificateDer<'static>,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> (SocketAddr, tokio::sync::mpsc::Receiver<Handle>) {
        // 本测试直接构建 rustls 配置（绕过 tls 构造函数）→ 自己确保 provider 已装。
        proto::crypto::provider();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let mut stls = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert], key)
            .unwrap();
        stls.alpn_protocols = vec![ALPN.to_vec()];

        let mut server = s2n_quic::Server::builder()
            .with_tls(s2n_quic::provider::tls::rustls::Server::from(Arc::new(
                stls,
            )))
            .unwrap()
            .with_io("127.0.0.1:0")
            .unwrap()
            .start()
            .unwrap();
        let addr = server.local_addr().unwrap();

        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            while let Some(conn) = server.accept().await {
                let tx = tx.clone();
                let (handle, _acceptor) = conn.split();
                let _ = tx.send(handle).await;
            }
        });
        (addr, rx)
    }

    /// 假网关：接受连接后**只服务注册流**（读一帧 → finish，让 agent 的 register 拿到 EOF），
    /// 此后的流（心跳）一律 `reset` 掉 —— 心跳读立刻报错，于是心跳任务结束。
    ///
    /// 每条接入连接都会往 channel 发一个信号：测试用它数"重连了几次"。用 reset 而不是
    /// 干脆不读，是为了避开 `heartbeat_loop` 里那个 5s 的 ack 超时，测试才跑得快。
    async fn test_server_that_only_serves_register(
        ca: &CertificateDer<'static>,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> (SocketAddr, tokio::sync::mpsc::Receiver<()>) {
        // 本测试直接构建 rustls 配置（绕过 tls 构造函数）→ 自己确保 provider 已装。
        proto::crypto::provider();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let mut stls = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert], key)
            .unwrap();
        stls.alpn_protocols = vec![ALPN.to_vec()];

        let mut server = s2n_quic::Server::builder()
            .with_tls(s2n_quic::provider::tls::rustls::Server::from(Arc::new(
                stls,
            )))
            .unwrap()
            .with_io("127.0.0.1:0")
            .unwrap()
            .start()
            .unwrap();
        let addr = server.local_addr().unwrap();

        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            while let Some(conn) = server.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let (_handle, mut acceptor) = conn.split();
                    if let Ok(Some(stream)) = acceptor.accept_bidirectional_stream().await {
                        let (mut recv, mut send) = stream.split();
                        let _ = proto::io::read_frame(&mut recv).await; // 注册帧
                        let _ = send.finish(); // 让 agent 侧读到 EOF，注册成功
                    }
                    let _ = tx.send(()).await; // "这条连接已经注册完成"
                                               // 之后的心跳流：reset 掉，让 agent 的心跳任务立刻失败
                    while let Ok(Some(stream)) = acceptor.accept_bidirectional_stream().await {
                        let (_recv, mut send) = stream.split();
                        let _ = send.reset(0u32.into());
                    }
                });
            }
        });
        (addr, rx)
    }

    /// 假网关：服务注册流，之后**消费心跳流但不回包**（读到帧后按 `reply_delay` 决定何时 finish）。
    ///
    /// 用途是复现"心跳等待超时"：`reply_delay` > 心跳等待上限时，这次心跳必然超时，
    /// 但**连接本身是健康的**（没有 reset、没有断开）——这正是要区分的那条路径。
    async fn test_server_that_delays_heartbeat_reply(
        ca: &CertificateDer<'static>,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
        first_reply_delay: Duration,
    ) -> SocketAddr {
        // 本测试直接构建 rustls 配置（绕过 tls 构造函数）→ 自己确保 provider 已装。
        proto::crypto::provider();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let mut stls = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert], key)
            .unwrap();
        stls.alpn_protocols = vec![ALPN.to_vec()];

        let mut server = s2n_quic::Server::builder()
            .with_tls(s2n_quic::provider::tls::rustls::Server::from(Arc::new(
                stls,
            )))
            .unwrap()
            .with_io("127.0.0.1:0")
            .unwrap()
            .start()
            .unwrap();
        let addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            while let Some(conn) = server.accept().await {
                tokio::spawn(async move {
                    let (_handle, mut acceptor) = conn.split();
                    let mut first = true;
                    let mut first_hb = true;
                    while let Ok(Some(stream)) = acceptor.accept_bidirectional_stream().await {
                        // ⚠️ 每条流**独立**处理：若在 accept 循环里串行 sleep，第一次
                        // 心跳的延迟会把后续心跳的回包一起堵住，导致连续多次超时。
                        let registration = std::mem::take(&mut first);
                        let delay_long = if registration {
                            None
                        } else {
                            Some(std::mem::take(&mut first_hb))
                        };
                        tokio::spawn(async move {
                            let (mut recv, mut send) = stream.split();
                            let _ = proto::io::read_frame(&mut recv).await;
                            match delay_long {
                                None => {}                                                 // 注册流：立刻回
                                Some(true) => tokio::time::sleep(first_reply_delay).await, // 首次心跳：拖长
                                Some(false) => {} // 其后心跳：立刻回
                            }
                            let _ = send.finish();
                        });
                    }
                });
            }
        });
        addr
    }

    /// 回归测试：**单次心跳超时不得立刻拆掉连接**。
    ///
    /// 旧实现把心跳等待硬编码成 5s（等于默认心跳间隔），一次超时就返回 Err → `run()`
    /// 视为致命 → 主动断开 → 重连又撞握手限时，实测在高并发下形成风暴，期间网关没有
    /// 任何健康 agent（所有请求 503）。
    ///
    /// 服务器只把**第一次**心跳的回包拖长（> 等待上限），之后一律立刻回包；于是
    /// "成功会重置失败计数"这一点与测试里掐的时刻无关：第一次必超时、其后必成功。
    /// 若容忍逻辑被改回"一次失败即退出"，循环会在第一次超时后结束，断言立刻失败。
    #[tokio::test]
    async fn a_single_heartbeat_timeout_does_not_immediately_tear_down_the_connection() {
        let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
        let addr = test_server_that_delays_heartbeat_reply(
            &ca,
            srv_cert,
            srv_key,
            // 远大于等待上限（interval 40ms × 3 = 120ms），保证第一次心跳必然超时；
            // 注意服务器每条流独立处理，所以这次延迟只影响第一次心跳。
            Duration::from_millis(200),
        )
        .await;
        let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
        let cc = tls::rustls_client_tls(
            &cfg.ca_cert,
            cfg.client_cert.clone(),
            cfg.client_key.clone_key(),
        )
        .unwrap();

        let mut handle = connect_for_test(&cfg, cc).await;
        let task = tokio::spawn(heartbeat_loop(
            handle.clone(),
            "agent-z".into(),
            Duration::from_millis(40),
        ));

        // 第一次心跳在 ≈160ms 超时；其后每次心跳都在 40ms 内立刻回包并重置计数。
        // 跨到 1.2s：若"单次失败就退出"的旧行为回来了，任务早已结束。
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(
            !task.is_finished(),
            "单次心跳超时就拆了连接：应当容忍失败，把「连接是否真死」交给网关 stale 判定"
        );
        assert!(
            handle.open_bidirectional_stream().await.is_ok(),
            "连接应当仍然可用"
        );
        task.abort();
    }

    /// 规格（`PROJECT_SCAN` P1-2 的 agent 侧）：越权路径**不得到达上游**，且客户端拿到 400。
    ///
    /// `stream.rs` 里那几条纯函数测试证明判据对；这条证明它**真接在数据路径上**：假网关往一条
    /// 双向流里写记录里的 PoC（`DELETE /v1/../api/delete`），真跑 [`handle_stream`]，断言
    /// ① 回包是一条 `code: 400` 的 Error 帧（网关据此让客户端看到 400，而不是无因果的 502），
    /// ② 上游那个 listener **一次连接都没有**——这才是漏洞本身（上游通常是 agent 同机的
    /// Ollama，`/api/delete` 会直接删模型）。
    #[tokio::test]
    async fn a_traversal_path_never_reaches_the_upstream_and_returns_400() {
        // 上游：只用来数连接，正常实现里 agent 不该连它
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_url = format!("http://{}", upstream.local_addr().expect("addr"));

        let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
        let (addr, mut server_handles) = test_server(&ca, srv_cert, srv_key).await;
        let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
        let cc = tls::rustls_client_tls(
            &cfg.ca_cert,
            cfg.client_cert.clone(),
            cfg.client_key.clone_key(),
        )
        .unwrap();
        let (_agent_handle, mut agent_acceptor) = connect_for_test_with_acceptor(&cfg, cc).await;
        let mut gateway = tokio::time::timeout(Duration::from_secs(5), server_handles.recv())
            .await
            .expect("agent 应当连上")
            .expect("假网关应当拿到连接句柄");

        // 假网关：开一条双向流，写一个越权的 ProxyRequest
        let gw_stream = gateway.open_bidirectional_stream().await.expect("开流");
        let (gw_recv, mut gw_send) = gw_stream.split();
        write_frame(
            &mut gw_send,
            &Frame::ProxyRequest {
                request_id: 7,
                method: "DELETE".into(),
                path: "/v1/../api/delete".into(),
                headers: vec![],
                body: bytes::Bytes::from_static(br#"{"model":"m"}"#),
            },
        )
        .await
        .expect("写请求帧");

        // agent 侧：accept 出流（生产里 `run_loop` 就是这么给的）并真跑
        let agent_stream = tokio::time::timeout(
            Duration::from_secs(5),
            agent_acceptor.accept_bidirectional_stream(),
        )
        .await
        .expect("应当在 5s 内收到流")
        .expect("accept 不该失败")
        .expect("应当是 Some(stream)");
        let task = tokio::spawn(handle_stream(
            agent_stream,
            reqwest::Client::new(),
            upstream_url,
            false,
        ));

        // ① 回包 = 400 Error 帧
        let reply = tokio::time::timeout(Duration::from_secs(5), FrameReader::new(gw_recv).next())
            .await
            .expect("拒绝不该拖延")
            .expect("读帧不该出错")
            .expect("应当有回帧");
        match reply {
            Frame::Error {
                request_id,
                code,
                message,
            } => {
                assert_eq!(request_id, Some(7), "错误帧要能对上请求");
                assert_eq!(code, 400, "网关拿这个 code 当客户端看到的状态码");
                assert!(message.contains("path"), "文案要指出是路径问题：{message}");
            }
            other => panic!("越权路径应当被拒，实际收到 {other:?}"),
        }

        // ② 上游一次都没被连（300ms 内 accept 必须超时）
        assert!(
            tokio::time::timeout(Duration::from_millis(300), upstream.accept())
                .await
                .is_err(),
            "越权路径到达了上游——这正是 P1-2"
        );

        task.await
            .expect("handle_stream 不该 panic")
            .expect("拒绝是正常结束，不该是 Err");
    }

    /// 建立一条到假网关的连接（注册已在 `connect_once` 之外单独调用，这里只连）。
    async fn connect_for_test(
        cfg: &AgentConfig,
        client_config: rustls::ClientConfig,
    ) -> s2n_quic::connection::Handle {
        connect_for_test_with_acceptor(cfg, client_config).await.0
    }

    /// 同 [`connect_for_test`]，但把 agent 侧的 [`Acceptor`] 一起交出来。
    ///
    /// [`handle_stream`] 收的是**已经 accept 出来的流**（生产里由 `run_loop` 的 acceptor 给），
    /// 所以要真跑它就得自己 accept 一次——而 `conn.split()` 出来的那个 acceptor 此前被丢掉了。
    async fn connect_for_test_with_acceptor(
        cfg: &AgentConfig,
        client_config: rustls::ClientConfig,
    ) -> (s2n_quic::connection::Handle, StreamAcceptor) {
        let client = s2n_quic::Client::builder()
            .with_tls(s2n_quic::provider::tls::rustls::Client::from(Arc::new(
                client_config,
            )))
            .unwrap()
            .with_io("0.0.0.0:0")
            .unwrap()
            .start()
            .unwrap();
        let conn = client
            .connect(Connect::new(cfg.cloud_addr).with_server_name(cfg.server_name.clone()))
            .await
            .unwrap();
        let (handle, acceptor) = conn.split();
        (handle, acceptor)
    }

    fn test_agent_config(
        cloud_addr: SocketAddr,
        ca: CertificateDer<'static>,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> AgentConfig {
        AgentConfig {
            cloud_addr,
            server_name: "localhost".into(),
            ca_cert: vec![ca],
            client_cert: vec![cert],
            client_key: key,
            agent_id: "t".into(),
            models: vec!["m".into()],
            max_concurrency: 2,
            upstream_base: "http://127.0.0.1:1".into(),
            heartbeat_interval: Duration::from_millis(50),
            request_log: true,
        }
    }

    #[tokio::test]
    async fn dead_heartbeat_forces_a_reconnect() {
        let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
        let (addr, mut rx) = test_server_that_only_serves_register(&ca, srv_cert, srv_key).await;
        let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
        let cc = tls::rustls_client_tls(
            &cfg.ca_cert,
            cfg.client_cert.clone(),
            cfg.client_key.clone_key(),
        )
        .unwrap();
        let task = tokio::spawn(run(cfg, cc));

        // 第一条连接：注册流被服务端读掉并 finish，所以注册能正常完成
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("agent should connect")
            .expect("first connection");

        // 之后的心跳流会被服务端 reset → 心跳任务结束。这条连接此时在网关眼里已经死了
        // （心跳是网关判定存活状态的唯一依据），所以 agent 必须主动断开重连 ——
        // 而不是抱着一条"看起来还开着"的连接静默等下去（那种状态下网关会把所有请求判 503，
        // 两侧都没有日志，只能人工重启）。没有这个断言，这条静默路径可以再次溜回去。
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a dead heartbeat must force a reconnect, not a silent zombie")
            .expect("second connection");

        task.abort();
    }

    #[tokio::test]
    async fn heartbeat_loop_breaks_when_connection_closed() {
        let handle = test_connection().await;
        // 关闭连接：之后 open_bidirectional_stream 必然失败 → 心跳循环返回 Err
        handle.close(0u32.into());
        let result = heartbeat_loop(handle, "agent-x".into(), Duration::from_millis(10)).await;
        assert!(
            result.is_err(),
            "heartbeat should fail after connection closed"
        );
    }

    #[tokio::test]
    async fn heartbeat_loop_sends_frames_on_live_connection() {
        let mut handle = test_connection().await;
        // 间隔 20ms、运行 120ms：心跳任务会反复开流（写帧 + 等 EOF）
        let task = tokio::spawn(heartbeat_loop(
            handle.clone(),
            "agent-y".into(),
            Duration::from_millis(20),
        ));
        tokio::time::sleep(Duration::from_millis(120)).await;
        // 连接仍存活（未被心跳逻辑破坏）
        assert!(handle.open_bidirectional_stream().await.is_ok());
        task.abort();
    }

    #[tokio::test]
    async fn run_loop_retries_when_connect_fails() {
        let (ca, _srv_cert, _srv_key, cli_cert, cli_key) = gen_pki();
        let cfg = test_agent_config(
            SocketAddr::from(([127, 0, 0, 1], 1)), // 必然连接失败
            ca,
            cli_cert,
            cli_key,
        );
        let cc = tls::rustls_client_tls(
            &cfg.ca_cert,
            cfg.client_cert.clone(),
            cfg.client_key.clone_key(),
        )
        .unwrap();
        let task = tokio::spawn(run(cfg, cc));
        // 第一次连接失败 → Err 分支 → 退避重试（覆盖 71/73-74 行）
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert!(!task.is_finished(), "run loop should keep retrying");
        task.abort();
    }

    #[tokio::test]
    async fn run_loop_handles_clean_disconnect() {
        let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
        let (addr, mut rx) = test_server(&ca, srv_cert, srv_key).await;
        let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
        let cc = tls::rustls_client_tls(
            &cfg.ca_cert,
            cfg.client_cert.clone(),
            cfg.client_key.clone_key(),
        )
        .unwrap();
        let task = tokio::spawn(run(cfg, cc));
        // 等 agent 连上
        let server_handle = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("agent should connect")
            .unwrap();
        // 服务端主动关闭连接 → agent 干净断开（Ok 分支）→ 退避重连
        server_handle.close(0u32.into());
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert!(
            !task.is_finished(),
            "run loop should keep running after disconnect"
        );
        task.abort();
    }

    /// Agent::start 在客户端证书/私钥无效时报错（不 panic）。
    #[test]
    fn start_rejects_invalid_client_key() {
        use rustls::pki_types::PrivatePkcs8KeyDer;
        let (ca, _srv_cert, _srv_key, cli_cert, _cli_key) = gen_pki();
        let bad_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![0x01; 16]));
        let cfg = AgentConfig {
            cloud_addr: "127.0.0.1:1".parse().unwrap(),
            server_name: "localhost".into(),
            ca_cert: vec![ca],
            client_cert: vec![cli_cert],
            client_key: bad_key,
            agent_id: "t".into(),
            models: vec!["m".into()],
            max_concurrency: 2,
            upstream_base: "http://127.0.0.1:1".into(),
            heartbeat_interval: Duration::from_millis(50),
            request_log: true,
        };
        assert!(Agent::start(cfg).is_err(), "invalid key should fail start");
    }
}
