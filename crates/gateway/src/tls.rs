//! TLS 材料与 rustls 配置构造。
//!
//! 两类材料各是一个适配器：隧道侧的 mTLS（[`TunnelTls`]）与公网入口的 HTTPS（[`TlsPem`]）。
//! 每个都持有"材料 + 用自己的材料构造 rustls 配置"这两件事，所以放在同一个模块里；
//! 装配（五阶段启动）仍在 `gateway.rs`。

use std::{io::Cursor, path::Path, sync::Arc};

use proto::ALPN;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    RootCertStore,
};

use crate::error::GatewayError;

/// HTTPS 证书 PEM 内容。
#[derive(Debug)]
pub struct TlsPem {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

impl TlsPem {
    /// 从两个 PEM 文件装载（生产路径）。
    pub fn from_pem_files(cert: &Path, key: &Path) -> Result<Self, GatewayError> {
        Ok(Self {
            cert: std::fs::read(cert)
                .map_err(|e| GatewayError::Other(format!("cannot read {}: {e}", cert.display())))?,
            key: std::fs::read(key)
                .map_err(|e| GatewayError::Other(format!("cannot read {}: {e}", key.display())))?,
        })
    }

    /// 构建公网 HTTPS 入口的 rustls 配置。
    ///
    /// 与隧道侧不同：这里**不要求**客户端证书（浏览器没有），所以 `with_no_client_auth`。
    /// 错误消息保持原样——运维就是靠它定位"证书与私钥不匹配"。
    pub(crate) fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, GatewayError> {
        https_server_config(&self.cert, &self.key)
            .map(Arc::new)
            .map_err(|e| {
                GatewayError::Config(format!("tls_cert/tls_key 无法构建 HTTPS 服务端配置: {e}"))
            })
    }
}

/// 隧道侧的 mTLS 身份材料。**必填**，没有它网关证明不了任何 agent 的身份。
///
/// 刻意**不给 `Default`、也不放进 `crate::Options`**：`PrivateKeyDer` 本身没有 `Default`，
/// 所以"忘了配证书"在类型层面就构造不出来。反面例子是**空的** `ca_cert`——那在 rustls 里
/// 是一套"谁也不信"的信任根：网关照常启动、日志照常写 ready，而每个 agent 的握手都被拒，
/// 表现成"agent 永远注册不上"。
///
/// 字段**私有** + 只有一个校验构造器 [`TunnelTls::from_der`]：光靠"没有 `Default`"挡不住
/// 空的 CA（那正是上面那个反面例子），所以这个不变量由构造点兜住。
#[derive(Debug)]
pub struct TunnelTls {
    /// 签发 agent 客户端证书的 CA 证书。
    ca_cert: Vec<CertificateDer<'static>>,
    server_cert: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
}

impl TunnelTls {
    /// 从已解析的 DER 材料构造隧道身份。**空 CA / 空证书链一律拒绝**。
    ///
    /// 这是本类型的唯一构造入口（外加读 PEM 的 [`Self::from_pem_files`]）。空的 `ca_cert`
    /// 在 rustls 里是一套"谁也不信"的信任根：不拦的话网关照常启动、日志 ready，而每个 agent
    /// 的握手都被拒，表现成"agent 永远注册不上"——排查成本极高。让它在**构造点**失败。
    pub fn from_der(
        ca_cert: Vec<CertificateDer<'static>>,
        server_cert: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
    ) -> Result<Self, GatewayError> {
        if ca_cert.is_empty() {
            return Err(GatewayError::Config(
                "tunnel ca_cert is empty: rustls would build a trust root that trusts nobody, \
                 so every agent handshake fails while the gateway still looks healthy"
                    .into(),
            ));
        }
        if server_cert.is_empty() {
            return Err(GatewayError::Config("tunnel server_cert is empty".into()));
        }
        Ok(Self {
            ca_cert,
            server_cert,
            server_key,
        })
    }

    /// 从三个 PEM 文件装载（生产路径）。文件缺失 / 解析失败 / 材料为空一律**启动即失败**。
    pub fn from_pem_files(ca: &Path, cert: &Path, key: &Path) -> Result<Self, GatewayError> {
        Self::from_der(
            proto::pem::load_certs(ca).map_err(|e| {
                GatewayError::Other(format!("cannot load ca cert {}: {e}", ca.display()))
            })?,
            proto::pem::load_certs(cert).map_err(|e| {
                GatewayError::Other(format!("cannot load cert {}: {e}", cert.display()))
            })?,
            proto::pem::load_key(key).map_err(|e| {
                GatewayError::Other(format!("cannot load key {}: {e}", key.display()))
            })?,
        )
    }

    /// 构建 QUIC 隧道用的 mTLS rustls 配置。调用方拿到 `Arc` 才能交给 s2n-quic。
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, GatewayError> {
        rustls_server_tls(
            &self.ca_cert,
            self.server_cert.clone(),
            self.server_key.clone_key(),
        )
        .map(Arc::new)
    }
}

/// 构造 HTTPS（公网 API 入口）的 rustls ServerConfig，由 PEM 字节构建。
pub fn https_server_config(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> anyhow::Result<rustls::ServerConfig> {
    // workspace 同时链接 ring 与 aws-lc-rs，rustls 无法自动选 provider，
    // 不装任何 `Config::builder()` 都会 panic（见 proto::crypto 的模块说明）。
    proto::crypto::provider();
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

pub fn rustls_server_tls(
    ca: &[CertificateDer<'static>],
    cert: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig, GatewayError> {
    // 自己确保 provider 已装（`proto::crypto::provider` 幂等，是**唯一**入口）：
    // 否则这个构造函数就**隐含依赖**"别的代码先装过 provider"——`cargo test` 下同进程里
    // 总有别的测试先装（所以一直没暴露），但 nextest 每条测试一个进程，
    // `tls::tests::server_config_builds_mtls` 单独跑就崩。
    proto::crypto::provider();
    let mut roots = RootCertStore::empty();
    for c in ca {
        roots.add(c.clone())?
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let mut tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert, key)?;

    tls.alpn_protocols = vec![ALPN.to_vec()];
    Ok(tls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, SanType,
    };

    /// 规格：**空的身份材料在构造点就被拒绝**。
    ///
    /// 空的 `ca_cert` 是 rustls 的"谁也不信"信任根：不拦的话网关照常启动、日志 ready，
    /// 而每个 agent 握手都被拒（表现成"agent 永远注册不上"）。
    #[test]
    fn tunnel_tls_rejects_empty_identity_material() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        fn der(b: u8) -> CertificateDer<'static> {
            CertificateDer::from(vec![b])
        }
        fn key() -> PrivateKeyDer<'static> {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![0u8]))
        }

        assert!(
            TunnelTls::from_der(vec![], vec![der(1)], key()).is_err(),
            "空 CA 必须被拒绝（它是'谁也不信'的信任根）"
        );
        assert!(
            TunnelTls::from_der(vec![der(1)], vec![], key()).is_err(),
            "空服务端证书链必须被拒绝"
        );
        assert!(TunnelTls::from_der(vec![der(1)], vec![der(2)], key()).is_ok());
    }

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
        let config = rustls_server_tls(&ca, cert, key).unwrap();
        // mTLS 服务端配置构造成功（不校验握手细节）
        let _ = config;
    }
}
