//! PEM 证书/私钥加载（gateway 与 agent 共享，避免两份重复实现）。

use std::{fs::File, io::BufReader, path::Path};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// 从 PEM 文件加载证书链。文件里没有任何证书 → **报错**（返回空列表绝无用处）。
///
/// 为什么必须报错：空证书链/空信任根不会在加载期暴露——agent 会带着空 roots 一路跑到
/// 握手失败，然后无限重连（日志里只有 `UnknownIssuer`），运维很难定位到"ca 指错文件了"。
/// 最常见的手滑是把 `ca:` 指向私钥文件，或指向了一个不含 CERTIFICATE 块的文件。
pub fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        anyhow::bail!(
            "no certificates found in {}（是否把 ca/cert 指向了私钥或其他不含 CERTIFICATE 的文件？）",
            path.display()
        );
    }
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

    /// 规格：文件里**没有证书**时必须报配置错，而不是静默返回空列表。
    ///
    /// 空信任根/空证书链不会在加载期暴露：agent 会带着它一路跑到握手失败，然后无限
    /// 重连（日志里只有 UnknownIssuer），运维很难定位到"ca 指错文件了"。
    /// 最常见的手滑就是把 `ca:` 指向私钥文件 —— 用这个场景做用例。
    #[test]
    fn load_certs_rejects_file_without_certificates() {
        let dir = tempfile::tempdir().unwrap();

        // ① 只有私钥的 PEM（把 ca/cert 指到 key 文件）
        let (_, key_pem) = gen_pem();
        let key_path = dir.path().join("client.key");
        std::fs::write(&key_path, &key_pem).unwrap();
        let err = load_certs(&key_path).unwrap_err();
        assert!(
            err.to_string().contains("client.key"),
            "错误信息应指出是哪个文件: {err}"
        );

        // ② 完全空的文件
        let empty_path = dir.path().join("empty.pem");
        std::fs::write(&empty_path, "").unwrap();
        assert!(load_certs(&empty_path).is_err(), "空文件也不该静默通过");
    }
}
