use futures_util::StreamExt;
use proto::{
    headers::{is_client_credential, is_hop_by_hop},
    io::{write_frame, FrameReader},
    Frame,
};
use reqwest::{header::HeaderValue, RequestBuilder};
use s2n_quic::stream::{BidirectionalStream, SendStream};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
use tracing::warn;

// /// 单帧最大字节数（64 MiB）。
// pub const MAX_FRAME: usize = 64 * 1024 * 1024;

// // 长度前缀只有 u32：MAX_FRAME 必须装得下，否则下面 `as u32` 会静默截断。
// const _: () = assert!(MAX_FRAME <= u32::MAX as usize);

// /// 帧级读写对象：next() 取消安全（半读状态在 self 上），send() 整帧写出。
// pub struct FrameStream<S> {
//     inner: S,
//     rbuf: Vec<u8>, // 半读字节（= 现在 FrameReader 的状态）
//     want: Option<usize>,
// }

// impl<S: AsyncRead + AsyncWrite + Unpin> FrameStream<S> {
//     pub fn new(inner: S) -> Self {
//         Self {
//             inner,
//             rbuf: Vec::new(),
//             want: None,
//         }
//     }

//     /// 写一帧（[u32 大端长度][postcard]，沿用现有 write_frame 的逻辑）
//     pub async fn send(&mut self, frame: &Frame) -> io::Result<()> {
//         /* write_all 一次写完 */
//         let bytes = postcard::to_allocvec(frame)
//             .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
//         if bytes.len() > MAX_FRAME {
//             return Err(io::Error::new(
//                 io::ErrorKind::InvalidData,
//                 "frame too large",
//             ));
//         }
//         let len = bytes.len() as u32;
//         let mut buf = Vec::with_capacity(4 + bytes.len());
//         buf.extend_from_slice(&len.to_be_bytes());
//         buf.extend_from_slice(&bytes);
//         self.inner.write_all(&buf).await?;
//         Ok(())
//     }

//     /// 读下一帧；落败可安全重入（= 现在 FrameReader::next 的逻辑原样搬进来）
//     pub async fn next(&mut self) -> io::Result<Option<Frame>> {
//         /* 单次 read + 增量拼帧 */
//         loop {
//             // 1) 先用已有字节试着凑一帧（这段不 await，不会被从中间打断）
//             if let Some(frame) = self.take_frame()? {
//                 return Ok(Some(frame));
//             }
//             // 2) 还差字节：进度都留在 self 上，故这里的 await 是取消安全的
//             let mut chunk = [0u8; 8 * 1024];
//             let n = self.inner.read(&mut chunk).await?;
//             if n == 0 {
//                 // EOF：正好落在帧边界 = 干净关闭；帧中途 = 截断
//                 if self.rbuf.is_empty() && self.want.is_none() {
//                     return Ok(None);
//                 }
//                 return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "early eof"));
//             }
//             self.rbuf.extend_from_slice(&chunk[..n]);
//         }
//     }

//     /// 缓冲区里若已凑齐完整一帧则取出解码（不 await，故可安全地在中途调用）。
//     fn take_frame(&mut self) -> io::Result<Option<Frame>> {
//         if self.want.is_none() {
//             if self.rbuf.len() < 4 {
//                 return Ok(None);
//             }
//             let len =
//                 u32::from_be_bytes(self.rbuf[..4].try_into().expect("4 bytes checked")) as usize;
//             if len > MAX_FRAME {
//                 return Err(io::Error::new(
//                     io::ErrorKind::InvalidData,
//                     "frame too large",
//                 ));
//             }
//             self.want = Some(4 + len);
//         }
//         let total = self.want.expect("just set above");
//         if self.rbuf.len() < total {
//             return Ok(None);
//         }
//         let payload = self.rbuf[4..total].to_vec();
//         self.rbuf.drain(..total);
//         self.want = None;
//         let frame = postcard::from_bytes(&payload)
//             .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
//         Ok(Some(frame))
//     }
// }

/// 处理一条代理流：读 ProxyRequest → 转发本地 LLM → 流式回传响应帧。
/// `request_log` 控制每请求的 INFO 日志（received/responded/done/cancelled）。
pub async fn handle_stream(
    stream: BidirectionalStream,
    http: reqwest::Client,
    upstream: String,
    request_log: bool,
) -> anyhow::Result<()> {
    // let mut frame_stream = FrameStream::new(stream);

    let (recv, send) = stream.split();

    let mut reader = FrameReader::new(recv);

    let Some(Frame::ProxyRequest {
        request_id,
        method,
        path,
        headers,
        body,
    }) = reader.next().await?
    else {
        anyhow::bail!("expect ProxyRequest frame");
    };

    // 再把 reader 移交给监听任务：它只负责之后的 Cancel / EOF
    let cancel = CancellationToken::new();
    let c = cancel.clone();

    let listener = tokio::spawn(async move {
        loop {
            match reader.next().await {
                Ok(Some(Frame::Cancel { .. })) | Ok(None) => {
                    c.cancel();
                    break;
                }
                Ok(Some(_)) => {} // 别的帧忽略（协议上不该有）
                Err(_) => {
                    c.cancel();
                    break;
                } // 流坏 = 也当取消
            }
        }
    });

    let url = format!("{upstream}{path}");
    let rb = http.request(reqwest::Method::from_bytes(method.as_bytes())?, url);

    // ③ 干活：只持有 send 半
    let result = forward(send, request_id, rb, headers, body, request_log, &cancel).await;

    listener.abort(); // 无论成败都收掉监听任务
    result
}

async fn forward(
    mut send: SendStream,
    request_id: u64,
    mut rb: RequestBuilder,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    _request_log: bool,
    cancel: &CancellationToken,
) -> anyhow::Result<()> {
    for (k, v) in headers {
        // 逐跳头 + 调用方凭据都不转发：凭据只属于「客户端 ↔ 网关」那一跳，不该到上游
        // （网关侧已经剥过一层，这里是纵深防御，也覆盖"新 agent 配旧网关"的混版本场景）。
        let name = k.as_str();
        if !is_hop_by_hop(name) && !is_client_credential(name) {
            if let Ok(v) = HeaderValue::from_str(&v) {
                rb = rb.header(k, v);
            }
        }
    }

    rb = rb.body(body);

    // 等响应头：唯一需要 select 的地方（此刻 agent 既不写也不读，纯等上游）
    let send_fut = rb.send();
    tokio::pin!(send_fut);
    let resp = tokio::select! {
        r = &mut send_fut => r?,
        _ = cancel.cancelled() => {
            return send_cancelled(&mut send, request_id).await;
        }
    };

    // ③ 响应头 → ProxyResponseHead 帧
    let status = resp.status().as_u16();
    let mut out_headers = Vec::new();
    for (k, v) in resp.headers() {
        let name = k.as_str();
        if is_hop_by_hop(name) {
            continue;
        }
        if let Ok(v) = v.to_str() {
            out_headers.push((name.to_string(), v.to_string()));
        }
    }
    write_frame(
        &mut send,
        &Frame::ProxyResponseHead {
            request_id,
            status,
            headers: out_headers,
        },
    )
    .await?;
    // if request_log {
    //     tracing::info!(request_id, status, "upstream responded");
    // }

    // ④ 流式回传：纯线性，无 select
    let mut body_stream = resp.bytes_stream();
    let mut ok = true;

    loop {
        let chunk = tokio::select! {
            c = body_stream.next() => match c {
                Some(Ok(b)) => b,
                Some(Err(e)) => { warn!(request_id, "upstream stream error: {e}"); ok = false; break; }
                None => break,
            },
            _ = cancel.cancelled() => return send_cancelled(&mut send, request_id).await,
        };
        write_frame(
            &mut send,
            &Frame::ProxyResponseBody {
                request_id,
                chunk: chunk.to_vec(),
            },
        )
        .await?;
    }

    // ⑤ 结束帧 + 半关闭写方向
    write_frame(&mut send, &Frame::ProxyResponseEnd { request_id, ok }).await?;
    // send.finish()?;
    send.shutdown().await?;
    Ok(())
}

async fn send_cancelled(send: &mut SendStream, request_id: u64) -> anyhow::Result<()> {
    let _ = write_frame(
        send,
        &Frame::Error {
            request_id: Some(request_id),
            code: 499,
            message: "cancelled by client".into(),
        },
    )
    .await;
    send.shutdown().await?;
    Ok(())
}
