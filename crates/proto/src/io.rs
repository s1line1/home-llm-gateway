//! 帧的读写：长度前缀 + postcard 序列化，兼容任何 tokio AsyncRead/AsyncWrite
//! （如 quinn 的 SendStream/RecvStream）。

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Frame;

/// 单帧最大字节数（64 MiB）。
pub const MAX_FRAME: usize = 64 * 1024 * 1024;

/// 写入一帧：`[u32 大端长度][postcard 字节]`。
pub async fn write_frame<W>(w: &mut W, frame: &Frame) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let bytes =
        postcard::to_allocvec(frame).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&bytes).await?;
    Ok(())
}

/// 读取一帧。流被对端干净关闭时返回 `Ok(None)`。
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
}
