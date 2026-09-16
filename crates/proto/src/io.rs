//! 帧的读写：长度前缀 + postcard 序列化，兼容任何 tokio AsyncRead/AsyncWrite
//! （如 quinn 的 SendStream/RecvStream）。

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Frame;

/// 单帧最大字节数（64 MiB）。
pub const MAX_FRAME: usize = 64 * 1024 * 1024;

// 长度前缀只有 u32：MAX_FRAME 必须装得下，否则下面 `as u32` 会静默截断。
const _: () = assert!(MAX_FRAME <= u32::MAX as usize);

/// 写入一帧：`[u32 大端长度][postcard 字节]`。
pub async fn write_frame<W>(w: &mut W, frame: &Frame) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let bytes =
        postcard::to_allocvec(frame).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if bytes.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let len = bytes.len() as u32;
    let mut buf = Vec::with_capacity(4 + bytes.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&bytes);
    w.write_all(&buf).await?;

    Ok(())
}

/// 读取一帧。流被对端干净关闭时返回 `Ok(None)`。
///
/// ⚠️ **不可安全取消**：内部是 `read_exact`，在 `select!` 中落败会丢掉已读字节。
/// 凡是要在 `select!` 里一边等帧一边等别的东西（如同时监听 `Cancel`），
/// 必须改用 [`FrameReader::next`]。
pub async fn read_frame<R>(r: &mut R) -> io::Result<Option<Frame>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    if let Err(e) = r.read_exact(&mut len_buf).await {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(e);
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    let frame =
        postcard::from_bytes(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(frame))
}

/// 可安全取消的帧读取器：把半读状态（已收字节 + 目标长度）保存在**自身**，
/// 因此使用方在 `select!` 中落败（future 被 drop）时不会丢掉已读字节。
///
/// 为什么必须有这个类型：`read_frame` 内部用 `read_exact`，tokio 明确标注它
/// **not cancellation safe**——落败时"已读进局部缓冲的字节"随之消失，下一次读取
/// 就会按错误偏移解析长度前缀（帧错位）。本类型唯一的 await 是
/// `AsyncReadExt::read`（tokio 保证取消安全：落败时"没有读到任何数据"），
/// 且解析进度全部落在字段上，所以任何 await 点被打断都可安全重入。
///
/// 用法：凡是要在 `select!` 里同时等帧和等别的东西，都必须用它而不是 `read_frame`。
pub struct FrameReader<R> {
    inner: R,
    /// 已收到、尚未组成完整帧的字节（长度前缀 + 载荷）。
    buf: Vec<u8>,
    /// 当前帧总长度（4 字节前缀 + 载荷）；None = 前缀尚未凑齐。
    want: Option<usize>,
}

impl<R> FrameReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            want: None,
        }
    }
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// 读下一帧。流被对端干净关闭时返回 `Ok(None)`。
    ///
    /// **可安全取消**：任何 await 点被打断都不丢字节，重入后继续拼同一帧。
    pub async fn next(&mut self) -> io::Result<Option<Frame>> {
        loop {
            // 1) 先用已有字节试着凑一帧（这段不 await，不会被从中间打断）
            if let Some(frame) = self.take_frame()? {
                return Ok(Some(frame));
            }
            // 2) 还差字节：进度都留在 self 上，故这里的 await 是取消安全的
            let mut chunk = [0u8; 8 * 1024];
            let n = self.inner.read(&mut chunk).await?;
            if n == 0 {
                // EOF：正好落在帧边界 = 干净关闭；帧中途 = 截断
                if self.buf.is_empty() && self.want.is_none() {
                    return Ok(None);
                }
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "early eof"));
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// 缓冲区里若已凑齐完整一帧则取出解码（不 await，故可安全地在中途调用）。
    fn take_frame(&mut self) -> io::Result<Option<Frame>> {
        if self.want.is_none() {
            if self.buf.len() < 4 {
                return Ok(None);
            }
            let len =
                u32::from_be_bytes(self.buf[..4].try_into().expect("4 bytes checked")) as usize;
            if len > MAX_FRAME {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "frame too large",
                ));
            }
            self.want = Some(4 + len);
        }
        let total = self.want.expect("just set above");
        if self.buf.len() < total {
            return Ok(None);
        }
        let payload = self.buf[4..total].to_vec();
        self.buf.drain(..total);
        self.want = None;
        let frame = postcard::from_bytes(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Some(frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Frame;

    #[tokio::test]
    async fn roundtrip_all_frame_types() {
        let frames = vec![
            Frame::Register {
                agent_id: "home-1".into(),
                models: vec!["mock-llm".into()],
                max_concurrency: 4,
                version: "0.1.0".into(),
            },
            Frame::Heartbeat {
                agent_id: "home-1".into(),
                inflight: 3,
            },
            Frame::ProxyRequest {
                request_id: 42,
                method: "POST".into(),
                path: "/v1/chat/completions?stream=true".into(),
                headers: vec![("content-type".into(), "application/json".into())],
                body: b"{\"model\":\"x\"}".to_vec(),
            },
            Frame::ProxyResponseHead {
                request_id: 42,
                status: 200,
                headers: vec![("content-type".into(), "text/event-stream".into())],
            },
            Frame::ProxyResponseBody {
                request_id: 42,
                chunk: b"data: {...}\n\n".to_vec(),
            },
            Frame::ProxyResponseEnd {
                request_id: 42,
                ok: true,
            },
            Frame::Cancel { request_id: 42 },
            Frame::Error {
                request_id: Some(42),
                code: 502,
                message: "upstream error".into(),
            },
        ];

        let mut buf: Vec<u8> = Vec::new();
        for f in &frames {
            write_frame(&mut buf, f).await.unwrap();
        }

        let mut reader = buf.as_slice();
        let mut out = Vec::new();
        while let Some(f) = read_frame(&mut reader).await.unwrap() {
            out.push(f);
        }
        assert_eq!(out, frames);
    }

    #[tokio::test]
    async fn clean_eof_returns_none() {
        let mut empty: &[u8] = &[];
        assert!(read_frame(&mut empty).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_len_prefix_rejected() {
        // 长度前缀超过 MAX_FRAME → 直接拒绝，不分配大块内存
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32::MAX.to_be_bytes());
        let err = read_frame(&mut buf.as_slice()).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("too large"), "err: {err}");
    }

    #[tokio::test]
    async fn invalid_postcard_payload_rejected() {
        // 长度合法但字节不是合法 postcard → 反序列化错误
        let mut buf = Vec::new();
        buf.extend_from_slice(&4u32.to_be_bytes());
        buf.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        let err = read_frame(&mut buf.as_slice()).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn truncated_frame_errors_not_none() {
        // 声明 10 字节只给了 3 字节：中途 EOF 应报错（区别于干净 EOF 的 None）
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u32.to_be_bytes());
        buf.extend_from_slice(&[1, 2, 3]);
        let err = read_frame(&mut buf.as_slice()).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn large_body_roundtrip() {
        // 64KiB body 跨长度前缀正确编解码
        let frame = Frame::ProxyResponseBody {
            request_id: 7,
            chunk: vec![0xabu8; 64 * 1024],
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).await.unwrap();
        assert!(
            buf.len() > 64 * 1024,
            "serialized size should exceed body size"
        );
        let mut reader = buf.as_slice();
        let got = read_frame(&mut reader).await.unwrap().unwrap();
        assert_eq!(got, frame);
    }

    /// 总是返回错误的读取器，用于触发非 EOF 的读错误分支。
    struct ErrReader;

    impl tokio::io::AsyncRead for ErrReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::Error::other("boom")))
        }
    }

    #[tokio::test]
    async fn non_eof_read_error_propagates() {
        // 非 EOF 的底层读错误应直接向上传播（区别于干净 EOF 的 None）
        let mut reader = ErrReader;
        let err = read_frame(&mut reader).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert_eq!(err.to_string(), "boom");
    }

    /// 每次只吐 2 字节、且每轮之间插入一次 Pending 的读取器。
    /// 效果：任何一帧都必然跨多次 poll，因此"中途被 drop"必然落在**帧内部**
    /// （而不会恰好落在帧边界上），从而把"丢字节"暴露成可断言的失败。
    struct DribbleReader {
        data: Vec<u8>,
        pos: usize,
        /// true = 本轮吐字节；false = 本轮返回 Pending（并自我唤醒，保证仍会推进）
        deliver: bool,
    }

    impl DribbleReader {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                pos: 0,
                deliver: true,
            }
        }
    }

    impl tokio::io::AsyncRead for DribbleReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            let me = self.get_mut();
            if !me.deliver {
                me.deliver = true;
                cx.waker().wake_by_ref(); // 之后仍会被唤醒，保证继续推进（不会死等）
                return std::task::Poll::Pending;
            }
            me.deliver = false;
            let n = (me.data.len() - me.pos).min(2).min(buf.remaining());
            buf.put_slice(&me.data[me.pos..me.pos + n]);
            me.pos += n;
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// 把若干帧序列化成一条 wire 字节流。
    async fn wire_of(frames: &[Frame]) -> Vec<u8> {
        let mut buf = Vec::new();
        for f in frames {
            write_frame(&mut buf, f).await.unwrap();
        }
        buf
    }

    /// 规格：帧读取**必须可安全取消**——在 `select!` 中落败（future 被 drop）后
    /// 不得丢失已读字节，下一次读取仍要拿到完整的帧。
    ///
    /// 背景：`read_frame` 内部是 `read_exact`，tokio 明确标注它 **not cancellation
    /// safe**（落败时"some data may already have been read into buf"）。而 agent 的
    /// `handle_stream` 直接把它当作 `select!` 分支用：落败分支一赢就丢掉半读的帧，
    /// 后续按长度前缀错位解析——网关发来的 `Cancel` 被静默丢弃，取消传播失效、
    /// 上游 token 继续白烧（与设计意图相反）。
    #[tokio::test]
    async fn frame_reader_survives_cancel_mid_frame() {
        let body = Frame::ProxyResponseBody {
            request_id: 7,
            chunk: vec![1, 2, 3],
        };
        let cancel = Frame::Cancel { request_id: 7 };
        let wire = wire_of(&[body.clone(), cancel.clone()]).await;
        let mut reader = FrameReader::new(DribbleReader::new(wire));

        // biased：先 poll 读分支（不足一帧 → Pending），再由立即就绪的分支获胜
        // → 读 future 被 drop 在**帧中间**（此时长度前缀已被消费掉一部分）。
        tokio::select! {
            biased;
            r = reader.next() => unreachable!("dribble reader 需多次 poll，读分支不应获胜: {r:?}"),
            _ = std::future::ready(()) => {}
        }

        // 落败不得丢字节：两帧都必须完整读出。
        assert_eq!(
            reader.next().await.unwrap(),
            Some(body),
            "落败的读取丢掉了已读字节（长度前缀错位）"
        );
        assert_eq!(reader.next().await.unwrap(), Some(cancel));
    }

    /// FrameReader 必须与 `read_frame` 保持完全相同的帧语义——本次为了取消安全性
    /// 重写了长度前缀解析，以下四条是那次重写的护栏（EOF / 截断 / 超大前缀 / 全帧型）。
    #[tokio::test]
    async fn frame_reader_roundtrip_all_frame_types() {
        let frames = vec![
            Frame::Register {
                agent_id: "home-1".into(),
                models: vec!["mock-llm".into()],
                max_concurrency: 4,
                version: "0.1.0".into(),
            },
            Frame::Heartbeat {
                agent_id: "home-1".into(),
                inflight: 3,
            },
            Frame::ProxyRequest {
                request_id: 42,
                method: "POST".into(),
                path: "/v1/chat/completions?stream=true".into(),
                headers: vec![("content-type".into(), "application/json".into())],
                body: b"{\"model\":\"x\"}".to_vec(),
            },
            Frame::ProxyResponseHead {
                request_id: 42,
                status: 200,
                headers: vec![("content-type".into(), "text/event-stream".into())],
            },
            Frame::ProxyResponseBody {
                request_id: 42,
                chunk: b"data: {...}\n\n".to_vec(),
            },
            Frame::ProxyResponseEnd {
                request_id: 42,
                ok: true,
            },
            Frame::Cancel { request_id: 42 },
            Frame::Error {
                request_id: Some(42),
                code: 502,
                message: "upstream error".into(),
            },
        ];
        let wire = wire_of(&frames).await;

        // 整块可读的 reader
        let mut reader = FrameReader::new(wire.as_slice());
        let mut out = Vec::new();
        while let Some(f) = reader.next().await.unwrap() {
            out.push(f);
        }
        assert_eq!(out, frames, "FrameReader 必须与 read_frame 解码结果一致");

        // 逐 2 字节慢喂的 reader：缓冲累积逻辑也必须正确（跨多次 poll 拼帧）
        let mut dribble = FrameReader::new(DribbleReader::new(wire));
        let mut out2 = Vec::new();
        while let Some(f) = dribble.next().await.unwrap() {
            out2.push(f);
        }
        assert_eq!(out2, frames, "慢速 reader 下也必须逐帧拼对");
    }

    #[tokio::test]
    async fn frame_reader_clean_eof_returns_none() {
        let mut reader = FrameReader::new(&[][..]);
        assert!(reader.next().await.unwrap().is_none());
    }

    /// 大帧必须跨多次内部 read 正确拼装，且拼完后下一帧仍对齐
    /// （LLM 响应体动辄几十 KiB，这是生产主路径）。
    #[tokio::test]
    async fn frame_reader_large_body_spans_multiple_reads() {
        let big = Frame::ProxyResponseBody {
            request_id: 7,
            chunk: vec![0xab; 64 * 1024], // 远超内部 8KiB 读块
        };
        let next = Frame::ProxyResponseEnd {
            request_id: 7,
            ok: true,
        };
        let wire = wire_of(&[big.clone(), next.clone()]).await;

        let mut reader = FrameReader::new(wire.as_slice());
        assert_eq!(reader.next().await.unwrap(), Some(big.clone()));
        assert_eq!(
            reader.next().await.unwrap(),
            Some(next.clone()),
            "大帧后必须仍对齐"
        );
        assert!(reader.next().await.unwrap().is_none());

        // 慢喂（每次 2 字节）下同样要拼对
        let mut dribble = FrameReader::new(DribbleReader::new(wire));
        assert_eq!(dribble.next().await.unwrap(), Some(big));
        assert_eq!(dribble.next().await.unwrap(), Some(next));
    }

    #[tokio::test]
    async fn frame_reader_truncated_frame_errors() {
        // 声明 10 字节只给了 3 字节：中途 EOF 应报错（区别于干净 EOF 的 None）
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u32.to_be_bytes());
        buf.extend_from_slice(&[1, 2, 3]);
        let mut reader = FrameReader::new(buf.as_slice());
        let err = reader.next().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn frame_reader_oversized_len_prefix_rejected() {
        // 长度前缀超过 MAX_FRAME → 直接拒绝，不分配大块内存
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut reader = FrameReader::new(buf.as_slice());
        let err = reader.next().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("too large"), "err: {err}");

        // 慢速 reader 下同样必须在"凑齐前缀"后立刻拒绝
        let mut dribble = FrameReader::new(DribbleReader::new(buf));
        let err = dribble.next().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
