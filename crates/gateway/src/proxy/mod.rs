//! 代理转发：认证 → 限流 → 编码为隧道帧转发（从 `http` 模块拆出，保持路由层精简）。

mod forward;
mod head;
mod routing;
mod tunnel;
mod usage;

use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::Response,
};
use proto::{io::FrameReader, Frame};

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

use crate::body::{read_body_with_stall, BodyRead, MAX_REQUEST_BODY};
use crate::openai::error_response;
use crate::usage_meter;
use crate::{auth::authenticate, state::AppState};
use forward::forward_body;

/// 解析请求体的失败原因：`Invalid` 是客户端的问题（400），`Internal` 是网关自己的（500）。
#[derive(Debug, PartialEq, Eq)]
enum FactsError {
    Invalid,
    Internal,
}

/// 大 body 的解析挪去阻塞池的最小体积。
///
/// `request_facts` 是一次**全量 JSON 解析**：16MiB 实测 ~77ms（debug 构建），压在 async worker
/// 上会连带卡住同一个线程上的其它请求（H6 说的队头阻塞）。小 body（聊天请求常见几 KB）原地
/// 解析——每次请求多一次 `spawn_blocking` 的线程池往返还更亏。阈值是**实测权衡**，不是协议值。
const PARSE_OFFLOAD_MIN_BYTES: usize = 256 * 1024;

/// 取请求侧解析结果：大 body 走阻塞池，小 body 原地解析。
async fn request_facts_for(
    body: &axum::body::Bytes,
) -> Result<usage_meter::RequestFacts, FactsError> {
    if body.len() < PARSE_OFFLOAD_MIN_BYTES {
        return usage_meter::request_facts(body).map_err(|_| FactsError::Invalid);
    }
    // `Bytes` 克隆是引用计数：把所有权移进阻塞任务**不拷贝** body 内容
    let owned = body.clone();
    match tokio::task::spawn_blocking(move || usage_meter::request_facts(&owned)).await {
        Ok(facts) => facts.map_err(|_| FactsError::Invalid),
        Err(e) => {
            tracing::error!("request body parsing task failed: {e}");
            Err(FactsError::Internal)
        }
    }
}

pub async fn proxy(State(state): State<AppState>, req: Request) -> Response {
    // 先取 method/uri/headers，body 留到**认证之后再读**：
    // 以前 `Bytes` 是提取器，于是未认证的请求也能让网关先缓冲 16MB（认证在 handler 里，
    // 比提取器晚一步）。现在认证在最前，读 body 在后，顺带把这个放大面收掉。
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    // 隧道 id 与 HTTP 层同源（crate::request_id）：middleware 已把规范化的 req-{n}
    // 写回入站 headers，UUID 客户端也不例外，于是两边不会再各自计数、周期性撞号。
    let request_id = crate::request_id::tunnel_id_from_headers(&headers);

    // 认证 + 限流（per-key 令牌桶）：拿不到身份的唯一出路就是把它还给客户端。
    let key = match authenticate(&state, &headers).await {
        Ok(key) => key,
        Err(rejection) => return rejection.into_response(),
    };

    // 路径守卫：**认证之后、读 body 之前**。放在这里有两个理由：① 未认证的探测拿不到
    // 路径校验的信息（先 401）；② 越权路径不必先让我们读进 16MiB 的 body。
    //
    // 判据本身在 `proto::path::safe_upstream_path`——**与 agent 侧共享同一份实现**：同一条
    // 规则的两道防线（这里拒一次、agent 拼上游 URL 前再拒一次），两份实现会漂移，而漂移的
    // 方向恰好会是"后面那道更松"，纵深防御就静默失效了。网关这一步管的是**越权请求的
    // 状态码**（客户端拿 400），agent 那一步管的是**隧道另一端不再受信时的兜底**。
    // 详见 `PROJECT_SCAN` P1-2。
    let Some(guarded_path) = proto::path::safe_upstream_path(uri.path()) else {
        warn!(
            request_id,
            path = %uri.path(),
            "rejecting request: path cannot be forwarded safely (dot segment, backslash or encoded separator)"
        );
        return error_response(StatusCode::BAD_REQUEST, "invalid request path");
    };
    // 通过守卫之后才拼 query：原样转发（query 不参与点段判定）
    let path = match uri.query() {
        Some(q) => format!("{guarded_path}?{q}"),
        None => guarded_path.to_string(),
    };

    // 读请求体：停滞/超限/读失败各自有明确状态码，且**都会归还准入票据**（随本函数返回而
    // Drop）——这正是修掉"槽位永久泄漏"的地方。
    let body =
        match read_body_with_stall(req.into_body(), state.client_stall, MAX_REQUEST_BODY).await {
            BodyRead::Body(b) => b,
            BodyRead::Stalled => {
                state.metrics.record_client_stall("request-body");
                warn!(
                request_id,
                stall_ms = state.client_stall.as_millis(),
                "client stalled while sending the request body; dropping the request and its slot"
            );
                return error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    "client stalled while sending the request body",
                );
            }
            BodyRead::TooLarge => {
                return error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large")
            }
            BodyRead::Failed(e) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    format!("request body read failed: {e}"),
                )
            }
        };
    // 一次解析同时拿到路由要的 model 与 prompt 估算（H6：以前这里解析一遍、
    // 下面估算又解析一遍）。解析失败/缺 model 的语义与拆分前一致 → 400。
    let facts = match request_facts_for(&body).await {
        Ok(f) => f,
        Err(FactsError::Invalid) => {
            return error_response(StatusCode::BAD_REQUEST, "model is required in request body")
        }
        // 阻塞池任务 panic/被取消：这是网关自己的故障，别让客户端以为是自己 body 的问题
        Err(FactsError::Internal) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error while parsing the request body",
            )
        }
    };
    let model = facts.model;
    // prompt 估算（仅在无 usage 时使用）：来自上面那次解析的字符数，**不再解析一遍**
    let prompt_est = usage_meter::estimate_tokens_from_chars(facts.prompt_chars).max(1);
    // request_id 在函数最开头就算好了（因为它要出现在"读 body 停滞"这类早期日志里）。
    // 隧道 request_id 与 HTTP 层 x-request-id 同源（crate::request_id）：
    // middleware 注入规范化的 req-{n}，本函数沿用它，响应头/日志/隧道帧三方同一个数字。
    // 请求帧在选路之前就构造好：重试换的是连接，请求内容不变（body 已整包在手，可重放）。
    let request = Frame::ProxyRequest {
        request_id,
        method: method.to_string(),
        path,
        headers: filter_headers(&headers),
        body,
    };

    let (entry, slot, recv, mut send) =
        match routing::open_and_send(&state, &model, &request, request_id).await {
            Ok(routed) => routed,
            Err(failure) => return error_response(failure.status, failure.message),
        };

    debug!(request_id, "proxying request to agent");

    // **读路径只有一条**（记录 R3）：头与体共用同一个 `FrameReader`，且它**拥有** `recv`
    // （`FrameReader::new(recv)` 是移动）。这样"读完响应头时已经预读进缓冲的体字节"会被
    // 下一阶段继续消费，而不是随临时 reader 一起丢掉；同时它天生取消安全
    // （见 `proto::io` 的 `FrameReader`），所以 `forward_body` 里的 `select!` 落败也不丢字节。
    let mut reader = FrameReader::new(recv);

    // 读取响应头：超时窗口、慢/死判据的渲染、Cancel 与 finish 全在 `head` 模块里
    // （一处改动理由 = 上游响应头契约），这里只把失败渲染成响应。
    let (status, mut out_headers) =
        match head::await_head(&state, &mut reader, &mut send, &entry, request_id).await {
            Ok(v) => v,
            Err(failure) => return error_response(failure.status, failure.message),
        };
    out_headers.retain(|(k, _)| !proto::headers::is_hop_by_hop(k.as_str()));

    // 流式回写响应体：后台任务把响应帧转进通道，HTTP 客户端从通道逐块读取。
    // 客户端断开（通道接收端被丢弃）→ 自动向 agent 发 Cancel，避免白算 token。
    // slot 守卫随任务结束释放，期间该请求计入 agent 在途并发。
    // usage 收集：提取上游 usage；无 usage（估算/取消/断流）→ 估算降级。
    let (tx, rx) = mpsc::channel::<Result<Bytes, String>>(32);
    let idle = state.timeout;
    let op_timeout = state.tunnel_op_timeout;
    let state_client_stall = state.client_stall;
    let metrics = state.metrics.clone();
    let key_store = state.key_store.clone();
    // 关闭阶段的接收端：`Terminating` 时这条流要带一个明确事件收尾（见 `forward.rs`）。
    let shutdown = state.subscribe_shutdown();
    // SSE 响应是流式（usage 在每个 chunk 尾部，逐块预过滤）；非 SSE 为整包 JSON
    let is_stream = out_headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.contains("text/event-stream"));
    tokio::spawn(async move {
        let end = forward_body(
            &mut reader,
            &mut send,
            request_id,
            tx,
            idle,
            state_client_stall,
            op_timeout,
            slot,
            // clone：下面还要用同一个 `Metrics` 记退出原因（记录 P2-14）
            metrics.clone(),
            key_store,
            key.key_id,
            key.key_name,
            prompt_est,
            is_stream,
            shutdown,
        )
        .await;
        // 记录 P2-14：这条 `debug!` 是**唯一**消费 ForwardEnd 的地方，于是七条以上的
        // "状态码已是 200 的失败"在指标上完全不可见；现在每个出口都留一个计数。
        metrics.record_forward_end(end.label());
        debug!(request_id, end = ?end, "response forwarding finished");
    });

    let mut builder = Response::builder().status(status);
    for (k, v) in out_headers {
        if let Some((name, value)) = relayable_response_header(&k, &v) {
            builder = builder.header(name, value);
        }
    }
    match builder.body(Body::from_stream(ReceiverStream::new(rx))) {
        Ok(resp) => resp,
        // 防御性分支：`status` 与每个 header 都已经过校验（`relayable_response_header` 只放行
        // 解析成功的名字/值），所以这里实际上到不了。**仍然**只回固定文案、细节进日志：
        // 这是**公开端点**，文案全仓一致（对照 `:135` 的 "internal error while parsing the
        // request body"），别把 `http::Error` 的原文当成对外契约（SL-P3-20 的同类）。
        Err(e) => {
            warn!(request_id, error = %e, "failed to build the response; returning 500");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error while building the response",
            )
        }
    }
}

/// 把隧道帧里的响应头装进对客户端的响应（记录 P3-16 的复核）。
///
/// **这里本来就没坏**：实测 `HeaderValue::from_str` 接受非 ASCII（中文 OK），真正只认可见
/// ASCII 的是 `to_str()`——坑在另外两处（网关的 `filter_headers`、agent 的响应头回传），
/// 都已改成按 UTF-8 取字节。抽成函数是为了把"非法名/非法值丢该头、不伪造值"这条行为用单测
/// 钉住（含 CR/LF 仍被拒）。
fn relayable_response_header(name: &str, value: &str) -> Option<(HeaderName, HeaderValue)> {
    let name = match HeaderName::from_bytes(name.as_bytes()) {
        Ok(n) => n,
        Err(_) => {
            warn!(
                header = name,
                "dropping a response header with an invalid name"
            );
            return None;
        }
    };
    match HeaderValue::from_str(value) {
        Ok(v) => Some((name, v)),
        Err(_) => {
            warn!(header = %name, "dropping a response header with an invalid value");
            None
        }
    }
}

/// 过滤要放进隧道帧的头：剔除逐跳头**与调用方凭据**。
///
/// 凭据（`authorization` / `cookie`）只在「客户端 ↔ 网关」这一跳有意义：客户端持有的是
/// **网关签发**的 API key（对全部模型有效、能打公网网关），而 edge 与上游属于另一个信任域，
/// 三种上游（Ollama/vLLM/llama.cpp）又都不认证——透传零收益、纯风险：edge 一旦被攻破，
/// 攻击者白得一把可用的公网凭据，edge / 上游日志里还会留下吊销不掉的副本。
/// 上游确实需要认证时，应在 **agent 侧**配置上游自己的凭据。
///
/// 注意凭据**不是**逐跳头（RFC 语义上端到端），因此这里用两条独立规则，
/// 规则常量见 `proto::headers`。
fn filter_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            let name = k.as_str();
            if proto::headers::is_hop_by_hop(name) || proto::headers::is_client_credential(name) {
                return None;
            }
            // 记录 P3-16：**不能**用 `to_str()`——它只接受可见 ASCII，而 HTTP 允许 obs-text
            // （0x80–0xFF），于是"UTF-8 头值"（中文名、中文文件名等很常见）会被判失败。
            // 以前那句 `to_str().unwrap_or_default()` 把它变成**空串**：上游看到的是"有这个头、
            // 值为空"，与"没有这个头"是两回事（可能让上游走错分支，签名类头更糟）。
            // 帧里本来就是 `String`，UTF-8 完全装得下 ⇒ 按 UTF-8 原样透传。
            match std::str::from_utf8(v.as_bytes()) {
                Ok(value) => Some((name.to_string(), value.to_string())),
                Err(_) => {
                    // 真·非 UTF-8 的字节装不进 `String`（改线格式属冻结范围）⇒ 只能丢这个头。
                    // 但**不伪造空值**。值本身可能是任意二进制，故只记头名与长度。
                    warn!(
                        header = name,
                        len = v.as_bytes().len(),
                        "dropping a header whose value is not valid UTF-8 (it cannot ride the frame's String)"
                    );
                    None
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 规格（记录 P3-16）：**响应方向**也按 UTF-8 原样透传，且注入防线不变。
    #[test]
    fn relayable_response_header_keeps_utf8_values_and_still_rejects_injection() {
        let (name, value) =
            relayable_response_header("x-echo", "张三").expect("中文响应头值应当能装进响应");
        assert_eq!(name.as_str(), "x-echo");
        assert_eq!(value.as_bytes(), "张三".as_bytes());

        assert!(
            relayable_response_header("x-echo", "a\r\nX-Evil: 1").is_none(),
            "CRLF 必须仍然被拒（注入防线不许因为放宽编码而失守）"
        );
        assert!(
            relayable_response_header("bad name", "v").is_none(),
            "非法头名仍要丢"
        );
    }

    /// 规格（记录 P3-16）：**非 ASCII（中文 UTF-8）头值必须逐字透传**，不许被清成空串。
    ///
    /// hyper 的 `HeaderValue` 收得下这类值（HTTP 允许 obs-text 0x80–0xFF），
    /// 但 `to_str()` 只认可见 ASCII —— 这就是原缺陷：值变 `""`、头还在。
    #[test]
    fn filter_headers_keeps_utf8_header_values_verbatim() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-user-name",
            HeaderValue::from_bytes("张三".as_bytes()).unwrap(),
        );
        assert_eq!(
            filter_headers(&headers),
            vec![("x-user-name".to_string(), "张三".to_string())],
            "UTF-8 头值必须原样透传（修好前这里会是空串）"
        );
    }

    /// 规格（记录 P3-16 的另一半）：**真·非 UTF-8** 的值丢头，而不是伪造空值。
    #[test]
    fn filter_headers_drops_non_utf8_values_instead_of_emptying_them() {
        let mut headers = HeaderMap::new();
        headers.insert("x-binary", HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap());
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let out = filter_headers(&headers);
        let names: Vec<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
        assert!(
            !names.contains(&"x-binary"),
            "非 UTF-8 值必须丢头，不能留下空值：{out:?}"
        );
        assert!(names.contains(&"content-type"), "其它头照旧转发：{out:?}");
    }

    #[test]
    fn filter_headers_strips_hop_by_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        headers.insert("connection", HeaderValue::from_static("keep-alive"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("content-length", HeaderValue::from_static("42"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let out = filter_headers(&headers);
        let names: Vec<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"content-type"));
        for hop in proto::headers::HOP_BY_HOP {
            assert!(!names.contains(hop), "hop-by-hop header leaked: {hop}");
        }
    }

    /// 规格：调用方的凭据**不得**随隧道帧离开网关。
    ///
    /// 客户端用的是**网关签发**的 API key（对全部模型有效、能打公网网关），而 edge 与上游
    /// 属于另一个信任域：三种上游（Ollama/vLLM/llama.cpp）都不认证，透传零收益纯风险——
    /// edge 一旦被攻破，攻击者就白得一把可用的公网凭据；而且 edge / 上游日志里会留下
    /// 一份吊销不掉的副本。上游确实需要认证时，应在 agent 侧配置上游自己的凭据。
    #[test]
    fn filter_headers_never_forwards_client_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer sk-secret"),
        );
        headers.insert("cookie", HeaderValue::from_static("session=topsecret"));

        let out = filter_headers(&headers);
        let names: Vec<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"content-type"), "普通头照旧转发: {names:?}");
        assert!(
            !names.contains(&"authorization"),
            "网关自己的 API key 不得进入隧道帧: {names:?}"
        );
        assert!(
            !names.contains(&"cookie"),
            "客户端 cookie 同样不得进入隧道帧: {names:?}"
        );
        // 值也不得出现在帧里（防「改了头名但仍漏出」）
        let joined: String = out
            .iter()
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
            .join("|");
        assert!(
            !joined.contains("sk-secret") && !joined.contains("topsecret"),
            "凭据值不得出现在隧道帧里: {joined}"
        );
    }

    /// 规格（H6）：**大 body 走阻塞池、结果与小 body 一致**。
    ///
    /// 这条覆盖的是"分支正确"，不是"真的不阻塞"（后者由 `spawn_blocking` 的语义保证，测不了）；
    /// 它同时钉住阈值两侧都返回同一份 facts——否则大于 256KiB 的请求会静默走另一条路。
    #[tokio::test]
    async fn request_facts_for_offloads_large_bodies_and_keeps_the_same_result() {
        // 造一个刚好跨过阈值、含 messages 的合法 chat body
        let filler = "x".repeat(PARSE_OFFLOAD_MIN_BYTES);
        let body = serde_json::to_vec(&serde_json::json!({
            "model": "qwen2.5",
            "messages": [{"role": "user", "content": filler}],
        }))
        .unwrap();
        assert!(
            body.len() >= PARSE_OFFLOAD_MIN_BYTES,
            "前提：这个 body 必须走阻塞池那条路（实际 {}）",
            body.len()
        );
        let bytes = axum::body::Bytes::from(body);
        let facts = request_facts_for(&bytes)
            .await
            .expect("大 body 也必须解析成功");
        assert_eq!(facts.model, "qwen2.5");
        assert_eq!(
            facts.prompt_chars, PARSE_OFFLOAD_MIN_BYTES as u64,
            "字符数必须与小 body 路径一致（同样是 messages[].content 的长度）"
        );

        // 小 body：原地解析（同一条规格的另一侧）
        let small = axum::body::Bytes::from_static(br#"{"model":"m","messages":[]}"#);
        assert_eq!(request_facts_for(&small).await.expect("小 body").model, "m");
        // 非法 JSON 仍然是"客户端的问题"（400），不是 500
        let bad = axum::body::Bytes::from(vec![b'x'; PARSE_OFFLOAD_MIN_BYTES]);
        assert!(
            matches!(request_facts_for(&bad).await, Err(FactsError::Invalid)),
            "非法 JSON 必须报 Invalid（400），不能报 Internal（500）"
        );
    }

    /// 规格：路由只认**顶层**的 `model` 字符串（等价于拆分前 `extract_model` 的判据）。
    ///
    /// 判据本体搬去了 `usage_meter::request_facts`（一次解析同时算 prompt 估算，见 H6），
    /// 这条从调用方的角度把"哪些 body 会被路由"钉住：嵌套的 `model` 不算、空串不算、
    /// 非字符串不算、非法 JSON 不算。
    #[test]
    fn routing_takes_the_top_level_model_string_only() {
        let model = |b: &[u8]| crate::usage_meter::request_facts(b).map(|f| f.model);
        assert_eq!(
            model(br#"{"model":"qwen2.5","messages":[]}"#).unwrap(),
            "qwen2.5"
        );
        // model 只出现在 messages 里（嵌套路径）→ 不算
        assert!(model(br#"{"messages":[{"role":"user","content":"model?"}]}"#).is_err());
        assert!(model(br#"{"messages":[]}"#).is_err(), "缺失 model");
        assert!(model(br#"{"model":123}"#).is_err(), "非字符串 model");
        assert!(model(br#"{"model":""}"#).is_err(), "空串 model");
        assert!(model(b"not json").is_err(), "非法 JSON");
    }
}
