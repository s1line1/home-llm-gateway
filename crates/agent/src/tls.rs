//! TLS 客户端配置构造与 PEM 加载（agent 侧，mTLS）。

use proto::ALPN;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    RootCertStore,
};

use crate::error::AgentError;

/// 构造 s2n-quic ClientConfig：信任云端 CA，并携带 agent 客户端证书（mTLS）。
///
/// 这里只管 TLS。keepalive 和空闲超时都不是 TLS 配置项：前者是每连接的
/// `conn.keep_alive(true)`，后者是端点侧的 `Limits::with_max_idle_timeout(..)`，
/// 两者都在 `crate::connect_once` 里设置。
pub fn rustls_client_tls(
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
