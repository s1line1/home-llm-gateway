//! TLS 配置构造与 PEM 加载。

use std::{io::Cursor, sync::Arc, time::Duration};

use quinn::crypto::rustls::QuicServerConfig;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    RootCertStore,
};

/// 隧道 ALPN 标识（自定义协议，不必是真正的 h3）。
pub const ALPN: &[u8] = b"h3";

/// 构造 QUIC ServerConfig：校验 edge-agent 的客户端证书（mTLS）。
pub fn server_config(
    ca: &[CertificateDer<'static>],
    cert: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig, crate::error::GatewayError> {
    let mut roots = RootCertStore::empty();
    for c in ca {
        roots.add(c.clone())?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| crate::error::GatewayError::Other(format!("client verifier: {e}")))?;
    let mut tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert, key)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let quic = QuicServerConfig::try_from(tls)
        .map_err(|e| crate::error::GatewayError::Other(format!("quic config: {e}")))?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(quic));
    // 空闲超时：agent 失联（掉线/断电）后及时释放连接；agent 侧 keepalive 会维持存活
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(20)
            .try_into()
            .map_err(|e| crate::error::GatewayError::Other(format!("transport: {e}")))?,
    ));
    // 一条 QUIC 连接多路复用所有代理请求的流：quinn 默认并发流上限 100，
    // 多客户端高并发时会排队等流、延迟爆炸（压测实测：VUS 500+ 延迟飙到 15s）。
    // 单 agent 单连接场景调大到 1000。
    transport.max_concurrent_bidi_streams(1000u32.into());
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

/// 构造 HTTPS（公网 API 入口）的 rustls ServerConfig，由 PEM 字节构建。
pub fn https_server_config(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> anyhow::Result<rustls::ServerConfig> {
    let mut cert_reader = Cursor::new(cert_pem);
    let certs = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    let mut key_reader = Cursor::new(key_pem);
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key in PEM"))?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, SanType,
    };

    /// 生成 (CA, 服务端证书, 服务端私钥, 客户端证书, 客户端私钥) 的 PEM 文本。
    fn gen_pem() -> (String, String, String, String, String) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "test CA");
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
            ca_cert.pem(),
            srv_cert.pem(),
            srv_key.serialize_pem(),
            cli_cert.pem(),
            cli_key.serialize_pem(),
        )
    }

    fn parse_certs(pem: &str) -> Vec<CertificateDer<'static>> {
        rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn parse_key(pem: &str) -> PrivateKeyDer<'static> {
        rustls_pemfile::private_key(&mut Cursor::new(pem.as_bytes()))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn https_server_config_builds_from_pem() {
        let (_, srv_pem, srv_key_pem, _, _) = gen_pem();
        let config = https_server_config(srv_pem.as_bytes(), srv_key_pem.as_bytes()).unwrap();
        // 无客户端认证的 TLS 服务端配置可构造
        let _ = config;
    }

    #[test]
    fn https_server_config_rejects_garbage() {
        assert!(https_server_config(b"not pem", b"not key").is_err());
        // 证书合法但私钥缺失
        let (_, srv_pem, _, _, _) = gen_pem();
        assert!(https_server_config(srv_pem.as_bytes(), b"no key here").is_err());
    }

    #[test]
    fn server_config_builds_mtls() {
        let (ca_pem, srv_pem, srv_key_pem, _, _) = gen_pem();
        let ca = parse_certs(&ca_pem);
        let cert = parse_certs(&srv_pem);
        let key = parse_key(&srv_key_pem);
        let config = server_config(&ca, cert, key).unwrap();
        // mTLS 服务端配置构造成功（不校验握手细节）
        let _ = config;
    }
}
