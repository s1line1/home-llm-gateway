//! 给客户端连接加上「写入停滞就断开」的超时。
//!
//! 为什么必须有：hyper 往 socket 写响应时**没有写超时**。客户端只要连上、读完响应头就不再读
//! （socket 缓冲写满后 hyper 就永久阻塞在 `poll_write` 上），这条连接会一直挂着，而
//! **准入票据（`Admission`）是绑在 response body 上的**——body 不被丢弃，票据就不释放。
//! 实测（2026-09-18 云端）就是这样沉淀出 8 个永不归还的槽位：`hlmg_active_requests`
//! 恒定 8、`hlmg_request_count − Σ状态码 = 8`，配了 `max_concurrent_requests` 的网关被
//! 只增不减地吃掉闸门，只能重启恢复。
//!
//! 应用层的"响应体停滞超时"（`proxy::send_to_client`）**修不掉这一半**：它只能让
//! *我们自己的任务* 不再 park；数据已经在 hyper 的缓冲与 socket 缓冲里，hyper 不解开写阻塞，
//! body 就不会被 drop。所以必须在 IO 层给写方向设上限。
//!
//! 语义与其它停滞超时一致（见 `Options::client_stall`）：**有进展就不超时**——
//! 每次 `poll_write` 只要被接受（哪怕只写进去 1 字节）就重新计时，只有连续 `stall` 时间
//! 一个字节都写不进去才判定客户端僵住并返回 `TimedOut`，让 hyper 关掉这条连接
//! （连接一结束，body 随连接任务一起被 drop，票据随之归还）。

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 写方向停滞超时包装器。读方向**不**包装：请求头读取由 hyper 的 `header_read_timeout`
/// 负责，请求体读取由 `proxy::read_body_with_stall` 负责。
pub struct WriteStall<S> {
    inner: S,
    stall: Duration,
    /// 本次阻塞开始的时间点（`None` = 上一次写成功了，还没开始计时）。
    armed: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> WriteStall<S> {
    pub fn new(inner: S, stall: Duration) -> Self {
        Self {
            inner,
            stall,
            armed: None,
        }
    }
}

/// 把一次 `poll_write/poll_flush` 的结果统一处理：成功即解除计时，Pending 则计时并在
/// 到点后转成 `TimedOut` 错误。
fn poll_with_stall<F, T>(
    armed: &mut Option<Pin<Box<tokio::time::Sleep>>>,
    stall: Duration,
    cx: &mut Context<'_>,
    f: F,
) -> Poll<io::Result<T>>
where
    F: FnOnce(&mut Context<'_>) -> Poll<io::Result<T>>,
{
    match f(cx) {
        Poll::Ready(r) => {
            *armed = None;
            Poll::Ready(r)
        }
        Poll::Pending => {
            let sleep = armed.get_or_insert_with(|| Box::pin(tokio::time::sleep(stall)));
            if sleep.as_mut().poll(cx).is_ready() {
                *armed = None;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "client write stalled: no byte could be written within the stall window",
                )));
            }
            Poll::Pending
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WriteStall<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let stall = this.stall;
        let armed = &mut this.armed;
        let inner = &mut this.inner;
        poll_with_stall(armed, stall, cx, |cx| {
            Pin::new(&mut *inner).poll_write(cx, buf)
        })
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let stall = this.stall;
        let armed = &mut this.armed;
        let inner = &mut this.inner;
        poll_with_stall(armed, stall, cx, |cx| Pin::new(&mut *inner).poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 关连接不走停滞计时：这是收尾动作，卡住了也没有"客户端不读"的含义。
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WriteStall<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// 一个永远写不进去的 IO（模拟"客户端不读、socket 缓冲已满"）。
    struct NeverWritable;
    impl AsyncWrite for NeverWritable {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncRead for NeverWritable {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    /// 前 `pending_times` 次写返回 Pending，之后接受写入。用来验证"有进展就不超时"。
    struct EventuallyWritable {
        pending: Arc<Mutex<usize>>,
    }
    impl AsyncWrite for EventuallyWritable {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut p = self.pending.lock().unwrap();
            if *p > 0 {
                *p -= 1;
                // 唤醒自己，模拟"过一会儿又能写了"
                tokio::spawn(async {});
                return Poll::Pending;
            }
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncRead for EventuallyWritable {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    /// 规格：**写不进去超过 stall 就必须报 TimedOut**。
    ///
    /// 这是"客户端不读 → 准入票据永不释放"的唯一出口：报错后 hyper 会结束这条连接，
    /// 绑在 response body 上的票据随连接任务一起被 drop。
    #[tokio::test]
    async fn a_write_that_never_lands_times_out() {
        let mut io = WriteStall::new(NeverWritable, Duration::from_millis(50));
        let started = std::time::Instant::now();
        let err = tokio::io::AsyncWriteExt::write_all(&mut io, b"hello")
            .await
            .expect_err("写不进去必须报错，而不是一直等");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "错误类型要能被识别");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "必须在 stall 量级返回"
        );
    }

    /// 规格：**只要还能写进去就绝不超时**（停滞 ≠ 慢）。
    ///
    /// 慢客户端（弱网）每个 RTT 只前进一点，但只要在动就不能被切断——否则会把
    /// "网络慢"误伤成"客户端僵住"。这里的 IO 每次写都先 Pending 若干次再接受，
    /// 总时长远大于 stall 也必须全部写完。
    #[tokio::test]
    async fn steady_progress_is_never_cut_off() {
        let pending = Arc::new(Mutex::new(0usize));
        let io = WriteStall::new(
            EventuallyWritable {
                pending: pending.clone(),
            },
            Duration::from_millis(20),
        );
        let mut io = io;
        tokio::io::AsyncWriteExt::write_all(&mut io, b"ok")
            .await
            .expect("只要最终能写进去就不该报错");
    }
}
