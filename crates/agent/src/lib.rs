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
        // 双 provider（ring + aws-lc-rs）共存时必须显式安装，见 proto::install_ring_crypto_provider
        proto::install_ring_crypto_provider();
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

async fn run(cfg: AgentConfig, client_config: rustls::ClientConfig) {
    let mut delay = Duration::from_millis(500);
    loop {
        match connect_once(&cfg, client_config.clone()).await {
            Ok(()) => {
                info!("disconnected from cloud, reconnecting");
                delay = Duration::from_millis(500);
            }
            Err(e) => warn!("agent error: {e}; retrying in {delay:?}"),
        }
        tokio::time::sleep(delay).await;
        delay = std::cmp::min(delay.saturating_mul(2), Duration::from_secs(30));
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

    // 保活：周期 = (协商后的空闲超时 × 3/4) 与 max_keep_alive_period（默认 30s）取小
    // —— 这里是 min(10s × 3/4, 30s) = 7.5s，小于 10s 的空闲超时，网关才不会把连接判空闲关掉。
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
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, SanType,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use s2n_quic::connection::Handle;
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
        proto::install_ring_crypto_provider();

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
        proto::install_ring_crypto_provider();

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
        proto::install_ring_crypto_provider();

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
        reply_delay: Arc<std::sync::Mutex<Duration>>,
    ) -> SocketAddr {
        proto::install_ring_crypto_provider();

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
                let reply_delay = reply_delay.clone();
                tokio::spawn(async move {
                    let (_handle, mut acceptor) = conn.split();
                    let mut first = true;
                    while let Ok(Some(stream)) = acceptor.accept_bidirectional_stream().await {
                        let (mut recv, mut send) = stream.split();
                        let _ = proto::io::read_frame(&mut recv).await;
                        if first {
                            first = false; // 注册流：立刻 finish，注册成功
                            let _ = send.finish();
                        } else {
                            // 心跳流：按当前设置延迟回包（0 = 立刻回，模拟正常）
                            let d = *reply_delay.lock().unwrap();
                            if !d.is_zero() {
                                tokio::time::sleep(d).await;
                            }
                            let _ = send.finish();
                        }
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
    /// 时间轴（间隔 10ms、等待上限 30ms、服务端把回包拖到 70ms）：
    /// - t≈10ms 发心跳 1 → 服务端 70ms 才回 → t≈40ms 超时（第 1 次失败）
    /// - 旧实现：t≈40ms 循环返回 Err → 任务结束
    /// - 新实现：容忍失败继续，下一次心跳 t≈50ms，因服务端仍在睡而很快失败……
    /// 所以"在 t≈60ms 时任务仍在运行"就足以证明容忍生效，且此时失败数（≤2）尚未到上限。
    #[tokio::test]
    async fn a_single_heartbeat_timeout_does_not_immediately_tear_down_the_connection() {
        let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
        let delay = Arc::new(std::sync::Mutex::new(Duration::from_millis(70)));
        let addr =
            test_server_that_delays_heartbeat_reply(&ca, srv_cert, srv_key, delay.clone()).await;
        let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
        let cc = tls::rustls_client_tls(
            &cfg.ca_cert,
            cfg.client_cert.clone(),
            cfg.client_key.clone_key(),
        )
        .unwrap();

        let mut handle = connect_for_test(&cfg, cc).await;
        let interval = Duration::from_millis(10);
        let task = tokio::spawn(heartbeat_loop(handle.clone(), "agent-z".into(), interval));

        // 第一次超时发生在 t≈interval+wait=40ms；旧实现在那之后就结束了
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(
            !task.is_finished(),
            "单次心跳超时就拆了连接：应当容忍失败，把「连接是否真死」交给网关 stale 判定"
        );

        // 服务端恢复正常回包 → 心跳应重新成功、循环继续存活、连接仍可用
        *delay.lock().unwrap() = Duration::ZERO;
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!task.is_finished(), "心跳恢复正常后循环不应退出");
        assert!(
            handle.open_bidirectional_stream().await.is_ok(),
            "连接应当仍然可用"
        );
        task.abort();
    }

    /// 建立一条到假网关的连接（注册已在 `connect_once` 之外单独调用，这里只连）。
    async fn connect_for_test(
        cfg: &AgentConfig,
        client_config: rustls::ClientConfig,
    ) -> s2n_quic::connection::Handle {
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
        let (handle, _acceptor) = conn.split();
        handle
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
