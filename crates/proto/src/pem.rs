//! PEM 证书/私钥加载（gateway 与 agent 共享，避免两份重复实现）。

use std::{fs::File, io::BufReader, path::Path};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

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
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};

    fn gen_pem() -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "test cert");
        params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn load_certs_and_key_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = gen_pem();
        let cert_path = dir.path().join("cert.crt");
        let key_path = dir.path().join("cert.key");
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();

        let certs = load_certs(&cert_path).unwrap();
        assert_eq!(certs.len(), 1);
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

    #[test]
    fn load_missing_file_errors() {
        assert!(load_certs(Path::new("/nonexistent/ca.crt")).is_err());
        assert!(load_key(Path::new("/nonexistent/ca.key")).is_err());
    }
}
