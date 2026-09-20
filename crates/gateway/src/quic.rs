//! QUIC 服务端：接受 edge-agent 连接，处理 Register / Heartbeat 控制流。

use proto::{io::read_frame, Frame};
use s2n_quic::Connection;
use tracing::{debug, error, info, warn};

use crate::metrics::Metrics;
use crate::registry::Registry;

/// `stream_ceiling` = 每条连接允许的在途隧道流数（见 `Options::max_open_tunnel_streams`）。
/// 它只用于**注册时的一致性告警**：agent 声明的 `max_concurrency` 超过这个额度时，网关侧
/// 会先撞流额度而不是先撞容量闸——表现是"开流排队超时"，排查起来比容量不足隐蔽得多。
pub async fn accept_loop(
    mut server: s2n_quic::Server,
    registry: Registry,
    metrics: Metrics,
    stream_ceiling: u32,
) {
    let _accepting = metrics.mark_accepting();
    while let Some(conn) = server.accept().await {
        let registry = registry.clone();
        let metrics = metrics.clone();

        let remote = match conn.remote_addr() {
            Ok(remote) => remote,
            Err(e) => {
                debug!(%e, "connection closed before remote_addr; skipping");
                continue;
            }
        };
        info!(%remote, "edge connected");

        tokio::spawn(async move {
            metrics.agent_connected();
            if let Err(e) = handle_conn(conn, registry, stream_ceiling).await {
                warn!("agent connection error: {e}");
            }
            metrics.agent_disconnected();
        });
    }

    // `accept()` 返回 None 只有两种可能：UDP I/O 驱动失效，或端点被关闭（quinn 源码
    // endpoint.rs:647-675）。前者是真实故障——入口从此不再接受任何新 agent，而进程照常
    // 运行、HTTP 入口照常服务、systemd 显示健康，网关日志里却什么都没有。所以这里必须
    // 把后果说清楚。正常关停不会走到这里（Gateway::shutdown 直接 abort 本任务）。
    error!(
        "QUIC 隧道入口已停止接受连接（端点被关闭或 UDP 驱动已失效）：已有 agent 连接不受影响，\
             但新的 edge 节点将无法接入，需要重启网关；hlmg_quic_accepting=0 可用于告警"
    );
}

async fn handle_conn(
    conn: Connection,
    registry: Registry,
    stream_ceiling: u32,
) -> anyhow::Result<()> {
    // split 消耗连接，只能一次。Handle: Clone（给 registry 存一份）；
    // StreamAcceptor: 单消费者且不可 Clone（acceptor.rs:182 只有 Debug），按 &mut 传下去。
    let (handle, mut acceptor) = conn.split();
    let mut agent_id: Option<(String, usize)> = None;
    let result = handle_conn_inner(
        &handle,
        &mut acceptor,
        &registry,
        &mut agent_id,
        stream_ceiling,
    )
    .await;
    // 无论正常/异常退出，都尝试摘除（仅当仍是同一连接）
    if let Some((id, sid)) = &agent_id {
        registry.remove_if_same(id, *sid);
    }
    result
}

async fn handle_conn_inner(
    handle: &s2n_quic::connection::Handle,
    acceptor: &mut s2n_quic::connection::StreamAcceptor,
    registry: &Registry,
    agent_id: &mut Option<(String, usize)>,
    stream_ceiling: u32,
) -> anyhow::Result<()> {
    loop {
        match acceptor.accept_bidirectional_stream().await {
            Ok(Some(stream)) => {
                let (mut recv, mut send) = stream.split();
                match read_frame(&mut recv).await? {
                    Some(Frame::Register {
                        agent_id: id,
                        models,
                        max_concurrency,
                        ..
                    }) => {
                        // stable_id 由 register 发号并返回——不能自己再算一个（如 handle.id()），
                        // 否则与 Entry.stable_id 对不上，连接结束时 remove_if_same 永远摘不掉条目。
                        // 声明容量 > 端点流额度 = 配置不一致：网关会先撞流额度，把
                        // "排队等额度"误解成"隧道卡住"。这里必须吵一声，否则复现路径极难查。
                        if max_concurrency > stream_ceiling {
                            warn!(
                                agent = %id,
                                max_concurrency,
                                stream_ceiling,
                                "agent declares more concurrency than the gateway's per-connection stream ceiling; \
                                 raise max_open_tunnel_streams (gateway) or lower max_concurrency (agent), \
                                 otherwise tunnel opens will queue and time out before capacity is reached"
                            );
                        }
                        let stable_id =
                            registry.register(id.clone(), models, max_concurrency, handle.clone());
                        *agent_id = Some((id.clone(), stable_id));
                        let _ = send.finish();
                        info!(agent = %id, "agent registered");
                    }
                    Some(Frame::Heartbeat {
                        agent_id: id,
                        inflight,
                        ..
                    }) => {
                        registry.heartbeat(&id);
                        debug!(agent = %id, inflight, "heartbeat");
                        let _ = send.finish();
                    }
                    Some(other) => {
                        warn!("unexpected frame on control stream: {other:?}");
                        let _ = send.finish();
                    }
                    None => {
                        let _ = send.finish();
                    }
                }
            }
            Ok(None) => return Ok(()),
            Err(e) => {
                warn!("accept stream failed: {e}");
                return Ok(()); // 连接已经没了，没有下一条流可接；绝不能再 continue
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{metrics::Metrics, registry::Registry};
    use std::{sync::Arc, time::Duration};

    /// 起一个本地 s2n-quic server：只为把 accept 循环跑起来，不接任何连接。
    /// 证书自签、不做客户端认证——本测试不握手，TLS 只要求能构造出配置。
    fn test_server() -> s2n_quic::Server {
        use rcgen::{CertificateParams, KeyPair};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        // 本测试直接构建 rustls 配置（绕过 tls 构造函数）→ 自己确保 provider 已装。
        proto::crypto::provider();

        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        tls.alpn_protocols = vec![proto::ALPN.to_vec()];

        s2n_quic::Server::builder()
            // 传入的已经是 Provider，所以这里的错误类型是 Infallible
            // （s2n-quic/src/provider/macros.rs 的 blanket impl），unwrap 不会 panic。
            .with_tls(s2n_quic::provider::tls::rustls::Server::from(Arc::new(tls)))
            .unwrap()
            .with_io("127.0.0.1:0")
            .unwrap()
            .start()
            .unwrap()
    }

    /// 规格：隧道入口「是否仍在接受新 agent」必须能从进程外看见——入口停摆时进程照常运行、
    /// HTTP 入口照常服务、systemd 显示健康，网关日志里可能一行都没有，只有
    /// `hlmg_quic_accepting` 能用来告警。
    ///
    /// 本测试盯住守卫的两端：进入 accept 循环后置 1；任务结束后必须回到 0。
    /// 后半段才是这条规格真正的保险：`mark_accepting` 用 Drop 而不是「循环之后写一句」，
    /// 正因为任务被 abort（`Gateway::shutdown` 就是这么关停的）或 panic 时，
    /// 循环之后的语句根本不会执行——那种情况下 gauge 会永远卡在 1，等于谎报健康。
    #[tokio::test]
    async fn accept_loop_marks_entry_accepting_and_releases_on_abort() {
        let metrics = Metrics::default();
        assert_eq!(metrics.quic_accepting(), 0, "未启动时不应是「接受中」");

        let task = tokio::spawn(accept_loop(
            test_server(),
            Registry::default(),
            metrics.clone(),
            1024,
        ));

        // 循环进入等待后应标记为「接受中」
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while metrics.quic_accepting() == 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(metrics.quic_accepting(), 1, "运行中应标记为接受中");

        // abort = 关停路径；await 到任务真正结束再断言，否则会读到竞态中间态。
        task.abort();
        let _ = task.await;
        assert_eq!(
            metrics.quic_accepting(),
            0,
            "任务被 abort 后必须回到 0（Drop 守卫的全部意义），否则会一直谎报「接受中」"
        );
    }

    // ⚠️ 覆盖退化，需要记号：quinn → s2n-quic 之后，这条测试少了一半。
    //
    // quinn 版还能测「端点被关闭 → accept() 返回 None → 循环结束并留下 error! 痕迹」，
    // 靠的是 `endpoint.close(0u32.into(), b"test close")`。s2n-quic 没有对应物：
    // `Server` 没有 close()，也没有可外传的关闭句柄——公开方法只有
    // builder/accept/poll_accept/local_addr（s2n-quic-1.88.0/src/server.rs），
    // 而 accept_loop 又是**按值**拿走 Server 的，测试侧拿不到任何能把 accept() 推成 None 的把手。
    // （官方那个能造 I/O 故障的 provider 在 provider/io/testing.rs，但被
    //  `#[cfg(any(test, feature = "unstable-provider-io-testing"))]` 挡着，要开 unstable feature
    //  才可用——那已经超出「只改测试代码」的范围。）
    //
    // 因此 `accept_loop` 里那条 error!（"QUIC 隧道入口已停止接受连接…"）目前**只由代码审查
    // 保证，不再由测试保证**。要恢复覆盖，得先给测试留个把手（都属非测试代码）：
    //   ① 让 accept_loop 接收一个可被外部关闭的东西（例如自建包装类型持有 Server，
    //      Gateway 与测试各持一份句柄）；
    //   ② 或者用自定义 io provider（绑定后立即报错）构造 accept() == None 的场景。
    // 在此之前，「入口停摆必须留下痕迹」这条规格只剩 abort 路径有测试覆盖。
}
