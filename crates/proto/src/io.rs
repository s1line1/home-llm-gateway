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
/// "干净关闭"的判据是**一个字节都没读到**：长度前缀只收到一部分（1–3 字节）就 EOF
/// 属于**截断**，返回 `UnexpectedEof`——与 [`FrameReader::next`] 的判据一致。
/// （曾经这里把前缀 `read_exact` 的任何 `UnexpectedEof` 都当成干净关闭，于是半个帧头
/// 被说成"对端正常收工"，协议违规在指标里变成对端的有序关闭。）
///
/// ⚠️ **不可安全取消**：在读满当前帧之前落败会丢掉已读字节。
/// 凡是要在 `select!` 里一边等帧一边等别的东西（如同时监听 `Cancel`），
/// 必须改用 [`FrameReader::next`]。
pub async fn read_frame<R>(r: &mut R) -> io::Result<Option<Frame>>
where
    R: AsyncRead + Unpin,
{
    // 前缀只能自己逐段读：`read_exact` 把"一字节没读到"和"读到一半"都报成
    // `UnexpectedEof`，却不告诉你它填了几个字节。
    let mut len_buf = [0u8; 4];
    let mut filled = 0;
    while filled < len_buf.len() {
        match r.read(&mut len_buf[filled..]).await {
            Ok(0) => {
                return if filled == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "early eof: truncated frame header",
                    ))
                };
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
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
    use std::time::Duration;

    use super::*;
    use crate::Frame;
    use bytes::Bytes;

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
                body: Bytes::from_static(b"{\"model\":\"x\"}"),
            },
            Frame::ProxyResponseHead {
                request_id: 42,
                status: 200,
                headers: vec![("content-type".into(), "text/event-stream".into())],
            },
            Frame::ProxyResponseBody {
                request_id: 42,
                chunk: Bytes::from_static(b"data: {...}\n\n"),
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

    /// 规格（记录 R4）：**半个长度前缀不算干净关闭**。
    ///
    /// 触发：对端只写出 1–3 字节的长度前缀就 FIN（写入中途被放弃、进程被杀、
    /// 连接被掐）。以前 `read_frame` 把前缀 `read_exact` 的任何 `UnexpectedEof`
    /// 都映射成 `Ok(None)`，于是这种截断被当成"对端有序收工"：`forward` 侧记成
    /// `UpstreamClosed` 而不是读取错误，`quic` 侧记成"注册前就关了"。
    /// 只有**一个字节都没读到**才是干净关闭。
    #[tokio::test]
    async fn a_truncated_length_prefix_is_not_a_clean_close() {
        // 0 字节 = 干净关闭（对端开了流又什么都不发就关，是合法的）
        let mut empty: &[u8] = &[];
        assert!(read_frame(&mut empty).await.unwrap().is_none());

        // 1–3 字节 = 截断
        for n in 1..4usize {
            let mut prefix: &[u8] = &vec![0u8; n];
            let err = read_frame(&mut prefix)
                .await
                .expect_err("只给了前缀的一部分就 EOF，不该当成干净关闭");
            assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof, "n={n}");
        }

        // 慢喂（每次 1 字节）下同样要认出来——不能依赖"一次 read 就能拿到整段前缀"
        let mut dribble = DribbleReader::new(vec![0u8; 3]);
        let err = read_frame(&mut dribble).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn large_body_roundtrip() {
        // 64KiB body 跨长度前缀正确编解码
        let frame = Frame::ProxyResponseBody {
            request_id: 7,
            chunk: vec![0xabu8; 64 * 1024].into(),
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
            chunk: vec![1u8, 2, 3].into(),
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
                body: Bytes::from_static(b"{\"model\":\"x\"}"),
            },
            Frame::ProxyResponseHead {
                request_id: 42,
                status: 200,
                headers: vec![("content-type".into(), "text/event-stream".into())],
            },
            Frame::ProxyResponseBody {
                request_id: 42,
                chunk: Bytes::from_static(b"data: {...}\n\n"),
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
            chunk: vec![0xab; 64 * 1024].into(), // 远超内部 8KiB 读块
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

    /// 规格（记录 R4）：两个读取器对"半个长度前缀"必须给出**同一个**判断。
    ///
    /// 两个实现分叉过一次：`read_frame` 说那是干净关闭，`FrameReader` 说那是
    /// `early eof`。同一条线上的同一段字节不该有两种解释。
    #[tokio::test]
    async fn both_readers_agree_that_a_half_header_is_truncation_not_eof() {
        for n in 0..4usize {
            let bytes = vec![0u8; n];
            let plain = read_frame(&mut bytes.as_slice()).await;
            let mut reader = FrameReader::new(bytes.as_slice());
            let cancellable = reader.next().await;
            match (&plain, &cancellable) {
                (Ok(None), Ok(None)) => assert_eq!(n, 0, "只有 0 字节才算干净关闭"),
                (Ok(None), _) | (_, Ok(None)) => {
                    panic!(
                        "n={n}: 两个读取器判断不一致——plain={plain:?} cancellable={cancellable:?}"
                    )
                }
                (Err(a), Err(b)) => assert_eq!(a.kind(), b.kind(), "n={n}"),
                _ => panic!("n={n}: plain={plain:?} cancellable={cancellable:?}"),
            }
        }
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

    /// 规格：帧里的 `body`/`chunk` 从 `Vec<u8>` 换成 [`bytes::Bytes`]（H6：让 postcard 走
    /// `serialize_bytes` 一次写整块）**不改变线上格式**。
    ///
    /// 为什么必须钉：隧道两端可以版本不一致（新网关 + 旧 agent，或反过来）。`Bytes` 用
    /// `serialize_bytes`、`Vec<u8>` 用"元素序列"，是两条不同的 serde 路径；postcard 恰好把两者
    /// 都编成 `varint 长度 + 原始字节`，这里用一个**变体顺序与字段顺序完全一致**的镜像枚举
    /// 逐字节比对，把"恰好"变成判据。（镜像里变体顺序也必须一致——postcard 的枚举是"变体序号 +
    /// 字段"，所以这个测试顺带钉住"变体顺序不能改"。）
    #[test]
    fn bytes_body_encodes_identically_to_a_plain_vec() {
        // 只构造 ProxyRequest/ProxyResponseBody；其余变体存在的意义是**对齐变体序号**
        // （postcard 的枚举编码 = 变体序号 + 字段），所以这里允许它们"未被构造"。
        #[derive(serde::Serialize)]
        #[allow(dead_code)]
        enum PlainFrame {
            Register {
                agent_id: String,
                models: Vec<String>,
                max_concurrency: u32,
                version: String,
            },
            Heartbeat {
                agent_id: String,
                inflight: u32,
            },
            ProxyRequest {
                request_id: u64,
                method: String,
                path: String,
                headers: Vec<(String, String)>,
                body: Vec<u8>,
            },
            ProxyResponseHead {
                request_id: u64,
                status: u16,
                headers: Vec<(String, String)>,
            },
            ProxyResponseBody {
                request_id: u64,
                chunk: Vec<u8>,
            },
            ProxyResponseEnd {
                request_id: u64,
                ok: bool,
            },
            Cancel {
                request_id: u64,
            },
            Error {
                request_id: Option<u64>,
                code: u16,
                message: String,
            },
        }

        // 边界：空、单字节、跨 0x80、1KiB
        for body in [
            Vec::new(),
            vec![0u8],
            vec![0x7f, 0x80, 0xff],
            vec![b'x'; 1024],
        ] {
            let headers = vec![("content-type".to_string(), "application/json".into())];
            let frame = Frame::ProxyRequest {
                request_id: 7,
                method: "POST".into(),
                path: "/v1/chat/completions".into(),
                headers: headers.clone(),
                body: Bytes::copy_from_slice(&body),
            };
            let plain = PlainFrame::ProxyRequest {
                request_id: 7,
                method: "POST".into(),
                path: "/v1/chat/completions".into(),
                headers,
                body: body.clone(),
            };
            assert_eq!(
                postcard::to_allocvec(&frame).expect("encode"),
                postcard::to_allocvec(&plain).expect("encode"),
                "body={} 字节时线上格式变了（旧 agent 会解不开）",
                body.len()
            );

            let chunk = Frame::ProxyResponseBody {
                request_id: 9,
                chunk: Bytes::copy_from_slice(&body),
            };
            let plain_chunk = PlainFrame::ProxyResponseBody {
                request_id: 9,
                chunk: body.clone(),
            };
            assert_eq!(
                postcard::to_allocvec(&chunk).expect("encode"),
                postcard::to_allocvec(&plain_chunk).expect("encode"),
                "chunk={} 字节时线上格式变了",
                body.len()
            );
        }

        // 反向：旧端（`Vec<u8>` 编码）写出的字节，新端必须解成同一个帧
        let plain_bytes = postcard::to_allocvec(&PlainFrame::ProxyResponseBody {
            request_id: 3,
            chunk: b"hello".to_vec(),
        })
        .expect("encode");
        match postcard::from_bytes::<Frame>(&plain_bytes).expect("decode") {
            Frame::ProxyResponseBody { request_id, chunk } => {
                assert_eq!(request_id, 3);
                assert_eq!(&chunk[..], b"hello");
            }
            other => panic!("应当解出 ProxyResponseBody，实际 {other:?}"),
        }
    }

    /// 规格（并集报告 H8 的机制那一半）：**写到一半被超时放弃的帧，只在对端留下一个严格前缀**。
    ///
    /// `write_frame` 是**一次** `write_all`（长度前缀 + 载荷在同一缓冲里），而 `write_all` 内部
    /// 是"部分写 + 循环"：超时把它 drop 掉时，剩下的字节**再也不会**写到这条流上。所以对端最多
    /// 拿到真帧的一个前缀，`FrameReader` 的 `read_exact` 永远等不齐——请求不可能被执行。
    ///
    /// 这条钉住的是那个前提。另一半（网关不会把剩余字节补写到同一条流、而是换新流重试）在
    /// `proxy::routing::open_and_send` 的重试循环里，见那里的注释与 e2e
    /// `write_backpressure::e2e_a_write_that_times_out_mid_frame_never_reaches_the_agent_as_a_request`。
    #[tokio::test]
    async fn a_timed_out_write_leaves_only_a_strict_prefix_of_the_frame() {
        /// 前 `limit` 字节照收、之后永远 `Pending`（且**不唤醒**）的 writer——模拟"对端不读"。
        struct StallingWriter {
            limit: usize,
            buf: Vec<u8>,
        }

        impl AsyncWrite for StallingWriter {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<io::Result<usize>> {
                if self.buf.len() >= self.limit {
                    return std::task::Poll::Pending; // 卡住，永不就绪
                }
                let n = buf.len().min(self.limit - self.buf.len());
                self.buf.extend_from_slice(&buf[..n]);
                std::task::Poll::Ready(Ok(n))
            }

            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }

        let frame = Frame::ProxyRequest {
            request_id: 1,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: vec![],
            body: Bytes::from(vec![b'x'; 4096]),
        };
        // 完整帧的字节（长度前缀 + postcard 载荷）
        let payload = postcard::to_allocvec(&frame).expect("encode");
        let mut full = Vec::with_capacity(4 + payload.len());
        full.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        full.extend_from_slice(&payload);
        assert!(full.len() > 64, "前提：这一帧要比注入的前缀长");

        let mut writer = StallingWriter {
            limit: 64,
            buf: Vec::new(),
        };
        let timed_out =
            tokio::time::timeout(Duration::from_millis(50), write_frame(&mut writer, &frame)).await;
        assert!(timed_out.is_err(), "对端不读时写应当超时");
        assert_eq!(writer.buf.len(), 64, "超时前应当恰好写满注入的前缀");
        assert!(
            full.starts_with(&writer.buf),
            "对端拿到的必须是真帧的前缀（否则线上格式已变）"
        );
        assert!(
            writer.buf.len() < full.len(),
            "前缀必须**严格短于**整帧——等长的意思是对端可能已经解出完整请求"
        );
    }
}
