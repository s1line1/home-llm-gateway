//! 请求体读取：**带停滞超时**的逐块读取与大小上限。
//!
//! 单独成模块的理由与 [`crate::openai`] / [`crate::auth`] 相同——它的消费者跨越了代理层的
//! 边界：路由层要用同一个 [`MAX_REQUEST_BODY`] 去配 `DefaultBodyLimit`（"提取器放行、
//! 这里拒绝"这种漂移正是要避免的鬼故事），代理层则要自己逐块读。
//!
//! 为什么不直接用 `Bytes` 提取器：它等到 body 读完为止、**没有任何超时**。客户端发完
//! headers（声明一个大 `Content-Length`）就不再发 body，这个请求会永久占住准入票据——
//! 实测云端沉淀过 8 个这样的僵尸槽位。语义是**停滞**而不是**总时长**：每收到一块就
//! 重新计时，所以"慢但一直在传"的大 body 上传不会被误杀。

use std::time::Duration;

use axum::body::Bytes;

/// 请求体上限。**只此一处定义**：`http.rs` 的 `DefaultBodyLimit` 层的值取自这里，
/// 而手动逐块读 body 时（见 `read_body_with_stall`）也用它——两处若各写一个数字，
/// 早晚会漂移成一个"提取器放行、这里拒绝（或反过来）"的鬼故事。
pub const MAX_REQUEST_BODY: usize = 16 * 1024 * 1024;

/// 读 body 的结果。`Stalled` 与 `TooLarge`/`Failed` 必须分开：它们对客户端的
/// 语义（408 / 413 / 400）和运维含义都不同。
pub(crate) enum BodyRead {
    Body(Bytes),
    Stalled,
    TooLarge,
    Failed(String),
}

/// 逐块读取请求体，**每块之间**用停滞超时兜底。
///
/// 为什么不能用 `Bytes` 提取器：它会一直等到 body 读完，**没有任何超时**。客户端只要发完
/// headers（声明一个大 `Content-Length`）就不再发 body，这个请求就会永久占住准入票据
/// （`Admission`）——实测云端沉淀了 8 个这样的僵尸槽位（`hlmg_active_requests` 恒为 8、
/// `request_count − Σ状态码 = 8`），而且只增不减，配了 `max_concurrent_requests` 的网关
/// 会被慢慢吃光闸门（生产口径约 32，8 个 = 25%），只能重启恢复。
///
/// 语义是**停滞**而不是**总时长**：每收到一块就重新计时，所以"慢但一直在传"的大 body
/// 上传不会被误杀（移动网络下的 16MB 上传可以合法地超过一分钟），只有该方向真的没有
/// 字节再流动才放弃。
pub(crate) async fn read_body_with_stall(
    body: axum::body::Body,
    stall: Duration,
    limit: usize,
) -> BodyRead {
    use http_body_util::BodyExt;
    let mut stream = body.into_data_stream();
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match tokio::time::timeout(stall, stream.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    if buf.len() + data.len() > limit {
                        return BodyRead::TooLarge;
                    }
                    buf.extend_from_slice(&data);
                }
                // 非数据帧（trailers）忽略：本网关只转发 body 字节
            }
            Ok(Some(Err(e))) => return BodyRead::Failed(e.to_string()),
            Ok(None) => return BodyRead::Body(Bytes::from(buf)),
            Err(_) => return BodyRead::Stalled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 造一个"分块到来"的 body：每块之间 sleep `gap`，共 `chunks` 块。
    fn delayed_body(chunks: usize, gap: Duration, size: usize) -> axum::body::Body {
        use futures_util::stream;
        let s = stream::unfold(0usize, move |i| async move {
            if i >= chunks {
                return None;
            }
            tokio::time::sleep(gap).await;
            Some((
                Ok::<_, std::io::Error>(Bytes::from(vec![b'x'; size])),
                i + 1,
            ))
        });
        axum::body::Body::from_stream(s)
    }

    /// 规格：判定的是**停滞**而不是**总时长**。
    ///
    /// 这是本次修复的核心语义：慢而持续的上传必须能读完（移动网络下 16MB 合法地要几十秒），
    /// 只有该方向真的没有字节再流动才放弃。若实现改成"整个读取总时长超时"，慢客户端会被
    /// 误杀——所以这条用"总时长 > stall、但每块间隔 < stall"把语义钉死。
    #[tokio::test]
    async fn body_read_survives_a_slow_but_steady_client_and_gives_up_on_a_stall() {
        let stall = Duration::from_millis(100);
        // 3 块 × 40ms = 120ms > stall(100ms)，但每块间隔 40ms < stall → 必须读完
        let body = delayed_body(3, Duration::from_millis(40), 4);
        match read_body_with_stall(body, stall, 1024).await {
            BodyRead::Body(b) => assert_eq!(b.len(), 12, "三块各 4 字节，一块都不能少"),
            BodyRead::Stalled => panic!("慢但一直在传的客户端不该被放弃（判成了总时长超时）"),
            _ => panic!("不该是别的结果"),
        }

        // 一块之后彻底停住 → 必须在 stall 量级返回 Stalled，而不是无限等下去
        let body = delayed_body(1, Duration::from_secs(30), 4);
        let started = std::time::Instant::now();
        let outcome = read_body_with_stall(body, stall, 1024).await;
        assert!(
            matches!(outcome, BodyRead::Stalled),
            "停下来不发的客户端必须被判为 Stalled"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "必须在 stall 量级就返回，而不是等客户端那 30s"
        );
    }

    /// 上限由本进程判（改成手动读 body 之后，提取器层的 `DefaultBodyLimit` 不再生效），
    /// 且必须与 `http.rs` 那一层用**同一个常量**。
    #[tokio::test]
    async fn body_read_enforces_the_size_limit() {
        let body = delayed_body(3, Duration::from_millis(1), 1024);
        assert!(
            matches!(
                read_body_with_stall(body, Duration::from_secs(5), 2048).await,
                BodyRead::TooLarge
            ),
            "超过上限必须 TooLarge（→ 413），而不是默默截断"
        );
        assert_eq!(MAX_REQUEST_BODY, 16 * 1024 * 1024, "上限值是契约的一部分");
    }
}
