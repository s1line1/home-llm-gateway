//! QUIC 服务端：接受 edge-agent 连接，处理 Register / Heartbeat 控制流。

use proto::{io::read_frame, Frame};
use quinn::Connection;
use tracing::{debug, error, info, warn};

use crate::metrics::Metrics;
use crate::registry::Registry;

pub async fn accept_loop(endpoint: quinn::Endpoint, registry: Registry, metrics: Metrics) {
    // 入口「接受中」标记：运行期为 1，守卫 Drop 时置 0（被 abort / panic 也不会漏）。
    let _accepting = metrics.mark_accepting();
    while let Some(incoming) = endpoint.accept().await {
        let registry = registry.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    metrics.agent_connected();
                    if let Err(e) = handle_conn(conn, registry).await {
                        warn!("agent connection error: {e}");
                    }
                    metrics.agent_disconnected();
                }
                Err(e) => warn!("connection attempt failed: {e}"),
            }
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

async fn handle_conn(conn: Connection, registry: Registry) -> anyhow::Result<()> {
    let remote = conn.remote_address();
    info!(%remote, "edge connected");

    let mut agent_id: Option<(String, usize)> = None;
    let result = handle_conn_inner(&conn, &registry, &mut agent_id).await;
    // 无论正常/异常退出，都尝试摘除（仅当仍是同一连接）
    if let Some((id, sid)) = &agent_id {
        registry.remove_if_same(id, *sid);
    }
    result
}

async fn handle_conn_inner(
    conn: &Connection,
    registry: &Registry,
    agent_id: &mut Option<(String, usize)>,
) -> anyhow::Result<()> {
    loop {
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(_) => return Ok(()), // 连接关闭
        };

        match read_frame(&mut recv).await? {
            Some(Frame::Register {
                agent_id: id,
                models,
                max_concurrency,
                ..
            }) => {
                let stable_id = conn.stable_id();
                registry.register(id.clone(), models, max_concurrency, conn.clone());
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{metrics::Metrics, registry::Registry};
    use std::{sync::Arc, time::Duration};

    /// 起一个本地 QUIC server endpoint（只为触发 accept 循环的结束，不接任何连接）。
    fn test_endpoint() -> quinn::Endpoint {
        use quinn::crypto::rustls::QuicServerConfig;
        use rcgen::{CertificateParams, KeyPair};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        proto::install_ring_crypto_provider();
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        let quic = QuicServerConfig::try_from(tls).unwrap();
        let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(quic));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
        scfg.transport_config(Arc::new(transport));
        quinn::Endpoint::server(scfg, "127.0.0.1:0".parse().unwrap()).unwrap()
    }

    /// 规格：隧道入口停止接受连接时**必须留下可观测的痕迹**，不能静默消失。
    ///
    /// quinn 的 `accept()` 只在两种情况下返回 `None`（quinn/src/endpoint.rs:647-675）：
    /// ① UDP I/O 驱动任务失效；② 端点被关闭。① 是真实故障——入口从此不再接受任何新
    /// agent，而网关进程照常运行、HTTP 入口照常服务、systemd 显示健康，网关自己的日志里
    /// **一行都没有**（quinn 只会在内部打一句 I/O error，不说后果）。已有连接还活着，
    /// 所以表面完全正常，实际新节点永远接不进来。
    #[tokio::test]
    async fn accept_loop_marks_tunnel_entry_dead_when_it_stops() {
        let metrics = Metrics::default();
        assert_eq!(metrics.quic_accepting(), 0, "未启动时不应是「接受中」");

        let endpoint = test_endpoint();
        let task = tokio::spawn(accept_loop(
            endpoint.clone(),
            Registry::default(),
            metrics.clone(),
        ));

        // 循环进入等待后应标记为「接受中」
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while metrics.quic_accepting() == 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(metrics.quic_accepting(), 1, "运行中应标记为接受中");

        // 端点关闭 → accept() 返回 None → 循环必须结束，并留下可告警的痕迹
        endpoint.close(0u32.into(), b"test close");
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("accept_loop 必须结束，不能挂死")
            .unwrap();
        assert_eq!(
            metrics.quic_accepting(),
            0,
            "隧道入口停止后必须可观测（供 Prometheus 告警），而不是静默消失"
        );
    }
}
