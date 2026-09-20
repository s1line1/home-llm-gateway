use std::{path::PathBuf, sync::Arc};

use gateway::{config, error::GatewayError};
use proto::ALPN;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    RootCertStore,
};
use s2n_quic::provider::tls::rustls::Server;
use tracing::error;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = PathBuf::from("gateway-config.yml");
    let cfg = config::from_path(&path)?;

    // 示例直接构建 rustls 配置 → 自己确保 provider 已装。
    proto::crypto::provider();

    // 身份材料在 `cfg.tunnel` 下（必填），可调旋钮在 `cfg.opts` 下。
    let tls = rustls_server_config(
        &cfg.tunnel.ca_cert,
        cfg.tunnel.server_cert.clone(),
        cfg.tunnel.server_key.clone_key(),
    )?; // 上面那份，含 mTLS
    let mut server = s2n_quic::Server::builder()
        .with_tls(Server::from(Arc::new(tls)))? // ← From<Arc<rustls::ServerConfig>>（s2n-quic-rustls/src/server.rs:60）
        .with_io(cfg.opts.quic_bind)? // SocketAddr 可直接传（provider/io.rs:57 impl_socket_addrs!(SocketAddr)）
        .start()?;

    loop {
        match server.accept().await {
            Some(mut conn) => {
                /* tokio::spawn 处理这条连接 */
                match conn.accept_bidirectional_stream().await {
                    Ok(Some(stream)) => {
                        let id = stream.id();
                        let (mut receive_stream, mut send_stream) = stream.split();
                        tokio::spawn(async move {
                            let mut stdout = tokio::io::stdout();
                            if let Err(e) = tokio::io::copy(&mut receive_stream, &mut stdout).await
                            {
                                println!("Failed to copy data from server. Error: {e}");
                            }
                        });

                        println!("connect success ,id = {id}");

                        // copy data from stdin and send it to the server
                        let mut stdin = tokio::io::stdin();
                        tokio::io::copy(&mut stdin, &mut send_stream).await?;
                    }
                    Ok(None) => break,
                    Err(e) => {
                        error!("accept stream failed: {e}");
                        break;
                    }
                }
            }
            None => {
                error!("隧道入口已停止接受连接（endpoint 关闭）");
                break;
            } // 文档明确：None 之后不应再调 accept
        }
    }
    Ok(())
}

fn rustls_server_config(
    ca: &[CertificateDer<'static>],
    cert: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig, GatewayError> {
    let mut roots = RootCertStore::empty();
    for c in ca {
        roots.add(c.clone())?
    }
    // let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
    //     .build()
    //     .map_err(|e| GatewayError::Other(format!("client verifier: {e}")))?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let mut tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert, key)?;

    tls.alpn_protocols = vec![ALPN.to_vec()];

    Ok(tls)
}
