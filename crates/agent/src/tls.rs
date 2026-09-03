//! TLS 客户端配置构造与 PEM 加载（agent 侧，mTLS）。

use std::{sync::Arc, time::Duration};

use quinn::crypto::rustls::QuicClientConfig;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    RootCertStore,
};

/// 构造 QUIC ClientConfig：信任云端 CA，并携带 agent 客户端证书（mTLS）。
/// 配置 keepalive + 空闲超时，保证网关重启后能及时发现断线并重连。
pub fn client_config(
    ca: &[CertificateDer<'static>],
    cert: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ClientConfig, crate::error::AgentError> {
    let mut roots = RootCertStore::empty();
    for c in ca {
        roots.add(c.clone())?;
    }
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert, key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic = QuicClientConfig::try_from(tls)
        .map_err(|e| crate::error::AgentError::Other(format!("quic config: {e}")))?;

    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(5)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(20)
            .try_into()
            .map_err(|e| crate::error::AgentError::Other(format!("transport: {e}")))?,
    ));
    // 与 gateway 侧一致：并发流上限 100 → 1000（单连接多路复用所有代理请求）
    transport.max_concurrent_bidi_streams(1000u32.into());

    let mut cfg = quinn::ClientConfig::new(Arc::new(quic));
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}
