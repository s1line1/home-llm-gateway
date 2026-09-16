//! TLS 客户端配置构造与 PEM 加载（agent 侧，mTLS）。

use proto::ALPN;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    RootCertStore,
};

use crate::error::AgentError;

/// 构造 s2n-quic ClientConfig：信任云端 CA，并携带 agent 客户端证书（mTLS）。
/// 配置 keepalive + 空闲超时，保证网关重启后能及时发现断线并重连。
pub fn rustls_client_config(
    ca: &[CertificateDer<'static>],
    cert: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ClientConfig, AgentError> {
    proto::install_ring_crypto_provider();
    let mut roots = RootCertStore::empty();
    for c in ca {
        roots.add(c.clone())?
    }

    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert, key)?;

    client_config.alpn_protocols = vec![ALPN.to_vec()];

    Ok(client_config)
}
