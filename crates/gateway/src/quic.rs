//! QUIC 服务端：接受家端 agent 连接，处理 Register / Heartbeat 控制流。

use proto::{io::read_frame, Frame};
use quinn::Connection;
use tracing::{debug, info, warn};

use crate::registry::Registry;

pub async fn accept_loop(endpoint: quinn::Endpoint, registry: Registry) {
    while let Some(incoming) = endpoint.accept().await {
        let registry = registry.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = handle_conn(conn, registry).await {
                        warn!("agent connection error: {e}");
                    }
                }
                Err(e) => warn!("connection attempt failed: {e}"),
            }
        });
    }
}

async fn handle_conn(conn: Connection, registry: Registry) -> anyhow::Result<()> {
    let remote = conn.remote_address();
    info!(%remote, "home agent connected");

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
            Some(Frame::Register { agent_id: id, models, max_concurrency, .. }) => {
                let stable_id = conn.stable_id();
                registry.register(id.clone(), models, max_concurrency, conn.clone());
                *agent_id = Some((id.clone(), stable_id));
                let _ = send.finish();
                info!(agent = %id, "agent registered");
            }
            Some(Frame::Heartbeat { agent_id: id, inflight, .. }) => {
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
