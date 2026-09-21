//! 监听端口绑定：**只有抬过 NOFILE 的调用方才能绑**（顺序由类型保证，不靠注释）。
//!
//! 单独成一个模块的唯一理由就是这个签名约束：`Sockets::bind` 要求一份
//! [`nofile::Raised`]，而它只能由 `nofile::install()` 产出，于是"先绑端口、后抬额度"
//! 这种顺序错误写不出来——借用检查器会先要求那个值存在。

use std::{net::SocketAddr, sync::Arc};

use crate::{error::GatewayError, nofile, options::Options};

/// 已绑好的两个入口。两个地址都是**真实**地址（配置 `:0` 时是内核分配的临时端口）。
pub(crate) struct Sockets {
    pub http: tokio::net::TcpListener,
    pub server: s2n_quic::Server,
    pub http_addr: SocketAddr,
    pub quic_addr: SocketAddr,
}

impl Sockets {
    /// 先绑 QUIC（UDP），再绑 HTTP（TCP）。任一步失败都返回 `Err`，已经绑上的那个随返回值
    /// drop——**不会留下"半个网关"**。
    ///
    /// 两个入参各自是一份"必须先发生过"的证据：
    /// - `_raised`：只有 [`nofile::install`] 能产出它 → 抬额度必然在绑端口之前；
    /// - `quic_tls`：已经**校验通过**的 mTLS 配置（`Arc<ServerConfig>` 只能由
    ///   `TunnelTls::server_config` 产出）→ 证书材料必然在绑端口之前构建成功。
    pub(crate) async fn bind(
        _raised: &nofile::Raised,
        quic_tls: Arc<rustls::ServerConfig>,
        opts: &Options,
    ) -> Result<Self, GatewayError> {
        // 隧道流额度：网关**自己**能同时开多少条双向流（每个 agent 连接一份）。
        //
        // 必须显式设置，且必须 ≥ agent 声明的 max_concurrency。默认的
        // `InitialMaxStreamsBidi::RECOMMENDED = 100` 是给"一条连接跑少量请求"的场景定的；
        // 我们一条连接就是一整台 agent 的流量，100 会让第 101 条请求去排队等额度，
        // 上游慢时排过 `tunnel_op_timeout` → 被当成坏隧道摘除（见 `Options` 字段注释）。
        //
        // 幂等性/安全性：这只是**上限**，真正的在途量由注册表按 agent 声明的
        // max_concurrency 做准入控制（`try_acquire`），所以这里给大不会放大并发。
        // 0 → 默认值的归一在 `Options::stream_ceiling()` 里，只此一处。
        let ceiling = opts.stream_ceiling();
        let limits = s2n_quic::provider::limits::Limits::new()
            .with_max_open_local_bidirectional_streams(u64::from(ceiling))
            .map_err(|e| {
                GatewayError::Config(format!(
                    "max_open_tunnel_streams={ceiling} 不是合法的 QUIC 流额度: {e}"
                ))
            })?;

        let quic_server = s2n_quic::Server::builder()
            .with_tls(s2n_quic::provider::tls::rustls::Server::from(quic_tls))?
            .with_io(opts.quic_bind)?
            .with_limits(limits)?
            .start()?;
        let quic_addr = quic_server.local_addr()?;

        let http = tokio::net::TcpListener::bind(opts.http_bind).await?;
        let http_addr = http.local_addr()?;

        Ok(Self {
            http,
            server: quic_server,
            http_addr,
            quic_addr,
        })
    }
}
