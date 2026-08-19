//! TLS 客户端配置构造与 PEM 加载（agent 侧，mTLS）。

use std::{fs::File, io::BufReader, path::Path, sync::Arc, time::Duration};

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
) -> anyhow::Result<quinn::ClientConfig> {
    let mut roots = RootCertStore::empty();
    for c in ca {
        roots.add(c.clone())?;
    }
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert, key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic = QuicClientConfig::try_from(tls)?;

    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(5)));
    transport.max_idle_timeout(Some(Duration::from_secs(20).try_into()?));

    let mut cfg = quinn::ClientConfig::new(Arc::new(quic));
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

/// 从 PEM 文件加载证书链。
pub fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

/// 从 PEM 文件加载私钥。
pub fn load_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, IsCa, KeyPair, SanType};

    fn gen_pem() -> (String, String, String) {
        // (ca, 客户端证书, 客户端私钥) PEM
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "test CA");
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let cli_key = KeyPair::generate().unwrap();
        let mut cli = CertificateParams::default();
        cli.distinguished_name
            .push(DnType::CommonName, "test-agent");
        cli.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
        let cli_cert = cli.signed_by(&cli_key, &ca_cert, &ca_key).unwrap();

        (
            ca_cert.pem(),
            cli_cert.pem(),
            cli_key.serialize_pem(),
        )
    }

    #[test]
    fn load_certs_and_key_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let (ca_pem, cli_pem, cli_key_pem) = gen_pem();
        let ca_path = dir.path().join("ca.crt");
        let cert_path = dir.path().join("client.crt");
        let key_path = dir.path().join("client.key");
        std::fs::write(&ca_path, &ca_pem).unwrap();
        std::fs::write(&cert_path, &cli_pem).unwrap();
        std::fs::write(&key_path, &cli_key_pem).unwrap();

        let ca = load_certs(&ca_path).unwrap();
        assert_eq!(ca.len(), 1);
        let cert = load_certs(&cert_path).unwrap();
        assert_eq!(cert.len(), 1);
        let key = load_key(&key_path).unwrap();
        assert!(!key.secret_der().as_ref().is_empty());
    }

    #[test]
    fn load_key_rejects_file_without_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no-key.pem");
        std::fs::write(&path, "not a private key").unwrap();
        assert!(load_key(&path).is_err());
    }
}
