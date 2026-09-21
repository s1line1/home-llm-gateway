use std::path::PathBuf;

use gateway::config;
use s2n_quic::provider::tls::rustls::Server;
use tracing::error;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = PathBuf::from("gateway-config.yml");
    let cfg = config::from_path(&path)?;

    // 身份材料在 `cfg.tunnel` 下（必填），可调旋钮在 `cfg.opts` 下。
    // `TunnelTls::server_config()` 直接给出 mTLS 的 rustls 配置：它含 ALPN，并自己确保
    // rustls crypto provider 已安装（幂等）——所以这里不再自己复制一份构造逻辑。
    let tls = cfg.tunnel.server_config()?;
    let mut server = s2n_quic::Server::builder()
        .with_tls(Server::from(tls))? // ← From<Arc<rustls::ServerConfig>>（s2n-quic-rustls/src/server.rs:60）
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
