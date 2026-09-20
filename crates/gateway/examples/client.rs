use std::{path::PathBuf, sync::Arc};

use agent::{config, error::AgentError};
use proto::ALPN;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    RootCertStore,
};
use s2n_quic::{client::Connect, provider::tls::rustls::Client};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = PathBuf::from("agent-config.yml");
    let cfg = config::from_path(&path)?;

    // 示例直接构建 rustls 配置 → 自己确保 provider 已装。
    proto::crypto::provider();

    let tls = rustls_client_config(&cfg.ca_cert, cfg.client_cert, cfg.client_key)?; // 上面那份，含 mTLS
    let client = s2n_quic::Client::builder()
        .with_tls(Client::from(Arc::new(tls)))?
        .with_io("0.0.0.0:0")?
        .start()?;

    // ③ 拨号：server_name 必须 = 网关证书的 SAN（保持可配，别学 simple-kv 写死 "localhost"）
    let mut conn = client
        .connect(Connect::new(cfg.cloud_addr).with_server_name(cfg.server_name.clone()))
        .await?; // 1.88 里 connect() 返回 ConnectionAttempt（是个 Future），await 得到 Connection

    conn.keep_alive(true)?;

    // open a new stream and split the receiving and sending sides
    let stream = conn.open_bidirectional_stream().await?;
    let client_id = stream.id();
    println!("client id : {client_id}");
    let (mut receive_stream, mut send_stream) = stream.split();

    println!("Connected to server {}", conn.remote_addr()?);

    // spawn a task that copies responses from the server to stdout
    tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        if let Err(e) = tokio::io::copy(&mut receive_stream, &mut stdout).await {
            println!("Failed to copy data from server. Error: {e}");
        }
    });

    // copy data from stdin and send it to the server
    let mut stdin = tokio::io::stdin();
    tokio::io::copy(&mut stdin, &mut send_stream).await?;

    Ok(())
}

fn rustls_client_config(
    ca: &[CertificateDer<'static>],
    cert: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ClientConfig, AgentError> {
    // 示例直接构建 rustls 配置 → 自己确保 provider 已装。
    proto::crypto::provider();
    let mut roots = RootCertStore::empty();
    for c in ca {
        roots.add(c.clone())?
    }

    // let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert, key)?;

    tls.alpn_protocols = vec![ALPN.to_vec()];

    Ok(tls)
}
