use anyhow::Context as _;
use futures_util::StreamExt;
use proto::{
    headers::{is_client_credential, is_hop_by_hop},
    io::{write_frame, FrameReader},
    Frame,
};
use reqwest::{header::HeaderValue, RequestBuilder};
use s2n_quic::stream::{BidirectionalStream, SendStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// 隧道帧的 `path` 字段是「路径[?query]」（见 [`Frame::ProxyRequest`]）；切出**路径部分**
/// 单独过守卫。
///
/// query 必须切掉再判：判据本身（[`proto::path::safe_upstream_path`]）只判路径——点段放不进
/// query，而 `%2f` 出现在 query 里是合法的。整串一起判会让 agent **比网关更严**，把网关刚放行
/// 的合法请求 400 掉（判据不一致 = 两道防线之间出现新的夹缝）。
fn split_target(target: &str) -> (&str, &str) {
    match target.find('?') {
        Some(i) => (&target[..i], &target[i..]),
        None => (target, ""),
    }
}

/// 拼上游 URL；路径不可安全转发 → `None`（调用方回 400，**不转发**）。
///
/// 这是纵深防御的**第二道**（第一道在网关，见 `proto::path`）：网关已经拒过一次，但那道防线
/// 在**远端**，而这里拼出来的 URL 会交给 URL 解析器按 WHATWG 归一——`/v1/../api/delete` 就此
/// 变成 `/api/delete`。agent 的上游通常与 agent 同机（Ollama 的 `/api/delete` 直接删模型），
/// 所以"隧道另一端的输入不再受信"时，本端必须自己挡（与 [`forward`] 里"再剥一次凭据头"
/// 同一个理由：深处那层不能假设外层永远做对了）。
fn upstream_url(upstream: &str, target: &str) -> Option<String> {
    let (path, query) = split_target(target);
    let path = proto::path::safe_upstream_path(path)?;
    Some(format!("{upstream}{path}{query}"))
}

/// 拒绝一条不可安全转发的路径：回 `code: 400` 的 [`Frame::Error`]，并半关闭写方向。
///
/// 为什么是 400 而不是直接断流：网关拿帧里的 `code` **直接当客户端看到的 HTTP 状态**
/// （`proxy/head.rs` 的 `StatusCode::from_u16`），于是拒绝会以 `400 invalid request path`
/// 原样到达调用方——断流则只会变成一条没有因果的 502。
///
/// 泛型只是为了让这条**跨层契约**测得动：生产传 `SendStream`，测试传内存 writer。
async fn reject_unsafe_path<W>(send: &mut W, request_id: u64, path: &str) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    warn!(
        request_id,
        path = %path,
        "rejecting request: path cannot be forwarded safely (dot segment, backslash or encoded separator)"
    );
    let _ = write_frame(
        send,
        &Frame::Error {
            request_id: Some(request_id),
            code: 400,
            message: "invalid request path".into(),
        },
    )
    .await;
    send.shutdown().await?;
    Ok(())
}

/// 监听任务的所有权守卫：**丢弃即 abort**（P3-2）。
///
/// 这条路径原来靠"函数末尾手写 `listener.abort()`"收尾，而中间任何一条提前 `return` 都会绕过它
/// ——方法非法那条 `return` 就因此泄漏了一个仍持有读半边的任务（实测：返回后对端还能继续往这条流
/// 写帧，直到流被关闭才恢复）。改成 RAII 之后，"忘了 abort"在结构上不再可能。
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// 一条请求的**跨任务信号**（转发任务与监听任务共享）。
///
/// - `cancel`：取消上游请求（显式 `Cancel` 帧 / 请求方向 EOF 兜底 / 流坏）；
/// - `response_started`：响应头是否已经写出去 —— 监听任务用它分辨"EOF 是契约违背还是合法收尾"
///   （P3-3）。打包成一个结构是因为 `forward` 的参数已经到 clippy 的上限了，而这两个信号确实是
///   同一件事（"这条请求现在处于什么状态"）的两面。
#[derive(Default)]
struct RequestSignals {
    cancel: CancellationToken,
    response_started: AtomicBool,
}

/// 处理一条代理流：读 ProxyRequest → 转发本地 LLM → 流式回传响应帧。
/// `request_log` 控制每请求的 INFO 日志（received/responded/done/cancelled）。
pub async fn handle_stream(
    stream: BidirectionalStream,
    http: reqwest::Client,
    upstream: String,
    request_log: bool,
) -> anyhow::Result<()> {
    // let mut frame_stream = FrameStream::new(stream);

    let (recv, mut send) = stream.split();

    let mut reader = FrameReader::new(recv);

    let first = reader
        .next()
        .await
        .context("reading the first frame of a proxy stream")?;
    let Some(Frame::ProxyRequest {
        request_id,
        method,
        path,
        headers,
        body,
    }) = first
    else {
        // 记录 P2-2：这条以前是静默的（错误被 spawn 处的 `let _ =` 吞掉）
        anyhow::bail!("first frame is not a ProxyRequest: {first:?}");
    };

    // 记录 P2-2 的另一半：`request_log`（默认 true）以前是**空操作**——成功路径一行日志都没有。
    // 现在按文档承诺打 received / responded / done / cancelled 四条 INFO。
    if request_log {
        info!(request_id, method = %method, path = %path, "proxy request received");
    }

    // 拼 URL 前的守卫（纵深防御第二道）：不合法就当场回 400，既不发上游、也不起监听任务。
    let Some(url) = upstream_url(&upstream, &path) else {
        return reject_unsafe_path(&mut send, request_id, &path).await;
    };

    // 方法非法的守卫**必须排在建监听任务之前**（P3-2）：以前它在 `tokio::spawn` 之后，
    // 于是这条 `return` 绕过了末尾的 `abort()`，泄漏一个仍持有读半边的任务。回 400 的口径与
    // 路径守卫一致（客户端发来的请求本身有问题），别让它变成一条"上游关闭了"的通用 502
    // （记录 P2-2：这条以前也是静默的）。
    let Ok(method) = reqwest::Method::from_bytes(method.as_bytes()) else {
        warn!(
            request_id,
            method = %method,
            "rejecting request: invalid HTTP method"
        );
        let _ = write_frame(
            &mut send,
            &Frame::Error {
                request_id: Some(request_id),
                code: 400,
                message: "invalid request method".into(),
            },
        )
        .await;
        // 带上与 `forward` 失败同款的上下文（记录 P2-2：accept 循环只打一行 `{e:#}`）
        return Err(anyhow::anyhow!(
            "invalid HTTP method in ProxyRequest: {method:?}"
        ))
        .with_context(|| format!("request_id={request_id} path={path}"));
    };
    let rb = http.request(method, url);

    // 校验都过了，才把 reader 移交给监听任务：它只负责之后的 Cancel / EOF。
    //
    // **取消契约（P3-3）**：取消只由 `Frame::Cancel` 表达。但监听任务把请求方向的**干净 EOF**
    // 也当取消（兜底）——今天网关每条"放弃一个还活着的请求"的路径都先 `tunnel_cancel` 再
    // `finish()`（见 `proxy/{head,forward}.rs`），所以 EOF 兜底只在"对端什么都没说就半关了"
    // 这种异常情况下才起作用。这个标志用来分辨响应是否已经开始：EOF 早于响应 = 契约被破坏，
    // 必须留痕（否则只会表现成一条看不见原因的 cancelled）。
    let signals = Arc::new(RequestSignals::default());
    let listener_signals = signals.clone();

    let _listener = AbortOnDrop(tokio::spawn(async move {
        loop {
            match reader.next().await {
                Ok(Some(Frame::Cancel { .. })) => {
                    debug!(request_id, "gateway cancelled the request");
                    listener_signals.cancel.cancel();
                    break;
                }
                Ok(None) => {
                    if listener_signals.response_started.load(Ordering::Relaxed) {
                        debug!(
                            request_id,
                            "gateway closed the request stream after the response; nothing to cancel"
                        );
                    } else {
                        warn!(
                            request_id,
                            "gateway closed the request stream before the response; treating it as a cancel (the gateway is expected to send Frame::Cancel first)"
                        );
                    }
                    listener_signals.cancel.cancel();
                    break;
                }
                Ok(Some(_)) => {} // 别的帧忽略（协议上不该有）
                Err(_) => {
                    listener_signals.cancel.cancel();
                    break;
                } // 流坏 = 也当取消
            }
        }
    }));

    // ③ 干活：只持有 send 半
    let result = forward(send, request_id, rb, headers, body, request_log, &signals).await;

    // 记录 P2-2：把"哪个请求、哪条路径"挂进错误链。调用方（`connect_once` 的 accept 循环）
    // 用 `{e:#}` 打一行，于是每条失败都有一条带上下文的 warn，而不是静默消失。
    if request_log {
        info!(request_id, ok = result.is_ok(), "proxy request done");
    }
    // 记录 P2-2：把"哪个请求、哪条路径"挂进错误链；调用方（accept 循环）用 `{e:#}` 打一行。
    result.with_context(|| format!("request_id={request_id} path={path}"))
}

async fn forward(
    mut send: SendStream,
    request_id: u64,
    mut rb: RequestBuilder,
    headers: Vec<(String, String)>,
    body: bytes::Bytes,
    request_log: bool,
    signals: &RequestSignals,
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
        r = &mut send_fut => match r {
            Ok(resp) => resp,
            Err(e) => {
                // 记录 P2-2：本地上游连不上（LLM 没起、崩了、端口不对）是运维最常见的一类故障。
                // 以前它表现成"客户端拿到通用 502 upstream closed before responding、agent 一行
                // 日志都没有"。现在：客户端拿到一条**点名原因但不说内部拓扑**的 502，细节进日志。
                let _ = write_frame(
                    &mut send,
                    &Frame::Error {
                        request_id: Some(request_id),
                        code: 502,
                        // 故意不带 reqwest 的原文（里面有内网地址/端口）
                        message: "local upstream request failed".into(),
                    },
                )
                .await;
                return Err(e).context("sending the request to the local upstream");
            }
        },
        _ = signals.cancel.cancelled() => {
            return send_cancelled(&mut send, request_id, request_log).await;
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
        // 记录 P3-16：`to_str()` 只认可见 ASCII，中文响应头值会被整条丢掉。帧里装的是
        // `String`，按 UTF-8 原样带走；真·非 UTF-8 的字节只能丢（并留一行日志，不伪造空值）。
        match std::str::from_utf8(v.as_bytes()) {
            Ok(value) => out_headers.push((name.to_string(), value.to_string())),
            Err(_) => warn!(
                header = name,
                len = v.as_bytes().len(),
                "dropping an upstream response header whose value is not valid UTF-8"
            ),
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
    // 响应头已经写出去 = 从这一刻起"对端半关写半边"是正常收尾而不是契约违背（见 `handle_stream`
    // 里的监听任务）。顺序要紧：先写帧、再置位。
    signals.response_started.store(true, Ordering::Relaxed);
    if request_log {
        info!(request_id, status, "upstream responded");
    }

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
            _ = signals.cancel.cancelled() => {
                return send_cancelled(&mut send, request_id, request_log).await
            }
        };
        // 切块后逐片回传：`MAX_RESPONSE_CHUNK` 是**网关侧的内存边界**（那边通道按条数有界，
        // 见该常量的文档 / 记录 R9）。`Bytes::split_to` 零拷贝：只动引用计数与偏移。
        let mut rest = chunk;
        while let Some(piece) = proto::frame::take_chunk_piece(&mut rest) {
            write_frame(
                &mut send,
                &Frame::ProxyResponseBody {
                    request_id,
                    chunk: piece,
                },
            )
            .await?;
        }
    }

    // ⑤ 结束帧 + 半关闭写方向
    write_frame(&mut send, &Frame::ProxyResponseEnd { request_id, ok }).await?;
    // send.finish()?;
    send.shutdown().await?;
    Ok(())
}

async fn send_cancelled(
    send: &mut SendStream,
    request_id: u64,
    request_log: bool,
) -> anyhow::Result<()> {
    if request_log {
        info!(request_id, "proxy request cancelled by client");
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 判据的**前提**：裸拼接真的会被 URL 解析器归一掉——这正是守卫存在的原因。
    ///
    /// 同时钉住放行时的收益：合法路径经过同一个解析器必须**逐字**不变。
    #[test]
    fn the_url_parser_would_normalize_a_dot_segment_away() {
        let upstream = "http://127.0.0.1:11434";
        let naive = format!("{upstream}{}", "/v1/../api/delete");
        assert_eq!(
            reqwest::Url::parse(&naive).expect("能解析").path(),
            "/api/delete",
            "WHATWG 归一：裸拼接会把持 key 者送到上游的任意端点（Ollama 的 /api/delete 会删模型）"
        );
        let ok = format!("{upstream}{}", "/v1/chat/completions");
        assert_eq!(
            reqwest::Url::parse(&ok).expect("能解析").path(),
            "/v1/chat/completions",
            "放行的路径必须逐字不变——守卫的收益就是这一点"
        );
    }

    /// 规格（`PROJECT_SCAN` P1-2 的 agent 侧）：越权路径**不得**拼进上游 URL。
    #[test]
    fn upstream_url_rejects_paths_that_would_escape_the_v1_prefix() {
        let up = "http://127.0.0.1:11434";
        for bad in [
            "/v1/../api/delete", // 记录里的 PoC
            "/v1/../../etc/passwd",
            "/v1/./models",
            "/v1//models",
            "/v1/",
            "/v1",
            "/api/delete", // 就算不带点段也越出了 `/v1/`
            "/v2/chat",
            "/v1/%2e%2e/x", // 上游解码后是 `..`
            "/v1/%2E%2E/x",
            "/v1/%2fapi",   // 上游解码后是分隔符
            "/v1/a%5Cb",    // 编码的反斜杠
            "/v1/a\\..\\b", // WHATWG 在 http 下把 `\` 当 `/`
        ] {
            assert_eq!(
                upstream_url(up, bad),
                None,
                "{bad} 必须被拒（不得拼出传给 reqwest 的 URL）"
            );
        }
    }

    /// 规格：合法 target 逐字转发（路径不归一、query 原样保留）。
    #[test]
    fn upstream_url_forwards_safe_targets_verbatim() {
        let up = "http://127.0.0.1:11434";
        for ok in [
            "/v1/chat/completions",
            "/v1/models",
            "/v1/a/b-c_d.e",
            "/v1/..hidden", // 以点开头但不是点段
            "/v1/chat/completions?stream=true",
        ] {
            let url = upstream_url(up, ok).unwrap_or_else(|| panic!("{ok} 应当放行"));
            assert_eq!(url, format!("{up}{ok}"), "拼接必须与改动前逐字一致");
            let parsed = reqwest::Url::parse(&url).expect("能解析");
            let got = match parsed.query() {
                Some(q) => format!("{}?{q}", parsed.path()),
                None => parsed.path().to_string(),
            };
            assert_eq!(
                got, ok,
                "放行的 target 必须逐字到达上游（解析器不得改写它）"
            );
        }
    }

    /// 规格：query **不参与**路径判据——否则 agent 会比网关更严，把合法请求拒掉。
    ///
    /// 网关只判 `uri.path()`、之后才拼 query（`proxy/mod.rs`），所以 query 里出现 `/../`、
    /// `%2f` 是合法的；agent 若把整串一起判就会 400 掉这些请求（判据不一致 = 两道防线之间
    /// 出现新的夹缝）。
    #[test]
    fn query_is_not_judged_as_part_of_the_path() {
        let up = "http://127.0.0.1:11434";
        for ok in [
            "/v1/chat/completions?x=/../api/delete",
            "/v1/embeddings?model=a%2fb",
            "/v1/models?next=http://evil.example/v1/",
        ] {
            assert_eq!(
                upstream_url(up, ok),
                Some(format!("{up}{ok}")),
                "{ok} 应当放行"
            );
        }
    }

    /// 规格（跨层契约）：拒绝 = 一条 `code: 400` 的 Error 帧。
    ///
    /// 网关拿帧里的 `code` 直接当**客户端看到的 HTTP 状态**（`proxy/head.rs` 的
    /// `StatusCode::from_u16`），所以"400 + 说明原因"是这条防线对外的全部表现，值得钉住；
    /// 这条测试同时证明拒绝路径**不碰上游**（只写帧就返回）。
    #[tokio::test]
    async fn rejecting_an_unsafe_path_sends_a_400_error_frame() {
        let mut buf: Vec<u8> = Vec::new();
        reject_unsafe_path(&mut buf, 42, "/v1/../api/delete")
            .await
            .expect("写内存 writer 不该失败");

        assert!(buf.len() > 4, "应当写出一个带长度前缀的帧");
        let len = u32::from_be_bytes(buf[..4].try_into().expect("4 字节前缀")) as usize;
        assert_eq!(len, buf.len() - 4, "长度前缀应当与载荷一致");
        match postcard::from_bytes::<Frame>(&buf[4..]).expect("能解出帧") {
            Frame::Error {
                request_id,
                code,
                message,
            } => {
                assert_eq!(request_id, Some(42), "错误帧要能对上请求");
                assert_eq!(code, 400, "网关会用这个 code 回客户端");
                assert!(
                    message.contains("path"),
                    "文案要指出是路径问题，实际：{message}"
                );
            }
            other => panic!("拒绝应当写出 Error 帧，实际 {other:?}"),
        }
    }

    /// 规格（P3-2）：`AbortOnDrop` 被丢弃时必须 abort 掉它持有的任务。
    ///
    /// 为什么单独测这个：它是"以后在 `tokio::spawn` 与函数结尾之间再加提前 `return` 也不会再
    /// 泄漏监听任务"的保险；而"守卫被删掉"这种改动，路径上的行为测试**抓不到**（那条泄漏只在
    /// 流被长时间挂住时才显形）。
    #[tokio::test]
    async fn abort_on_drop_aborts_the_task() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        use std::time::Duration;

        async fn delayed(flag: Arc<AtomicBool>) {
            tokio::time::sleep(Duration::from_millis(50)).await;
            flag.store(true, Ordering::SeqCst);
        }

        // 对照：不包裹时任务会跑完——否则下面的断言可能只是"任务压根没起来"。
        let control = Arc::new(AtomicBool::new(false));
        tokio::spawn(delayed(control.clone())).await.unwrap();
        assert!(control.load(Ordering::SeqCst), "对照：任务应当跑完");

        // 包裹后丢弃 → 不得跑完（abort 是异步生效的，留 3 倍余量）
        let ran = Arc::new(AtomicBool::new(false));
        drop(AbortOnDrop(tokio::spawn(delayed(ran.clone()))));
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !ran.load(Ordering::SeqCst),
            "丢弃 AbortOnDrop 必须 abort 它持有的任务"
        );
    }
}
