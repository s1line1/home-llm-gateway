//! 选路 + 隧道建立：挑一条**能服务该模型**的健康 agent，写出请求帧；
//! 开流 / 写帧失败时决定"换一条重试"还是报错。
//!
//! 这里集中了整仓库最微妙的一组判定，背后都有实测事故：
//!
//! - **忙 ≠ 死**：开流超时若发生在该连接的承载上限之内，那只是背压排队，**不能摘除**——
//!   摘除等于把"局部过载"升级成"整台 agent 下线"（实测一次 30s 压测 +6835 次
//!   `registry-empty`）。只有"没到上限却开不出流"才是坏连接。
//! - **只有"帧从未送达"才重试**：开流 / 写请求帧失败时请求帧没到 agent，换连接重放是安全的
//!   （body 已整包在手）。**响应头超时（504）不在重试之列**——请求可能已在模型侧执行，
//!   重试会重复计费、重复生成，那条由调用方直接报错。
//! - **"忙"不写进 `last_failure`**：否则最后挑不出候选时，客户端拿到的是误导性的
//!   502"隧道坏了"，而真实原因是容量不足（429）。
//!
//! 状态码与文案在**判定处就地决定**（只有那里知道是忙是死、注册表处于什么状态），
//! 调用方只负责把 [`RouteFailure`] 渲染成响应。

use axum::http::StatusCode;
use proto::Frame;
use s2n_quic::stream::{ReceiveStream, SendStream};
use tracing::warn;

use crate::registry::{AcquireError, Entry, EvictCause, SlotGuard};
use crate::state::AppState;

use super::tunnel::{open_tunnel, tunnel_write, OpenFailure};

/// 一次请求的路由失败：状态码 + 给客户端的文案。
///
/// **刻意不做成 `Err(Response)`**：`Response` 是 128+ 字节，塞进 `Err` 会触发 clippy 的
/// `result_large_err`（CI 曾因此失败），而这里只需要两个字段。
pub(super) struct RouteFailure {
    pub status: StatusCode,
    pub message: String,
}

/// 选路成功的结果：注册表条目、占用中的 agent 槽位、隧道流的两半。
type Routed = (Entry, SlotGuard, ReceiveStream, SendStream);

pub(super) async fn open_and_send(
    state: &AppState,
    model: &str,
    request: &Frame,
    request_id: u64,
) -> Result<Routed, RouteFailure> {
    // 隧道建立阶段允许**换一个 agent 重试**。
    //
    // 只有"开流 / 写请求帧"失败才重试：那时**请求帧从未送达 agent**，换一条连接重放
    // 是安全的（body 已整包在手，可重放）。**响应头超时（504）不在其中**——请求可能
    // 已在模型侧执行，重试会重复计费、重复生成，所以那条仍然直接把错误返回客户端：
    // 宁可报错，也不做不安全的重复。
    //
    // 实测（云端 2 vCPU、4 agent、768 并发）失败**全部**是 502（开流/写帧超时）、
    // 504 为 0，所以这条重试正好覆盖实际发生的失败。
    const MAX_TUNNEL_ATTEMPTS: usize = 2;
    let mut tried: Vec<usize> = Vec::with_capacity(MAX_TUNNEL_ATTEMPTS);
    let mut last_failure: Option<String> = None;

    let (entry, slot, recv, send) = loop {
        let acquired = state
            .registry
            .try_acquire_excluding(state.agent_stale_after, model, &tried);
        let (mut entry, slot) = match acquired {
            Ok(x) => x,
            // 三种拒绝**必须分开记录**：它们的运维含义完全不同，而客户端看到的
            // 503/404/429 不足以区分。尤其"NoAgent"有两种成因——注册表空，或注册表里
            // 有人但全部心跳超时（stale）——只看状态码会把后者误判成"agent 掉了"。
            Err(
                reason @ (AcquireError::NoAgent | AcquireError::NoModel | AcquireError::AtCapacity),
            ) => {
                let st = state.registry.status(state.agent_stale_after);
                let why = match reason {
                    AcquireError::NoAgent if st.registered == 0 => "registry-empty",
                    AcquireError::NoAgent => "all-candidates-stale",
                    AcquireError::NoModel => "no-agent-serves-model",
                    _ => "all-candidates-at-capacity",
                };
                state.metrics.record_agent_rejection(why);
                warn!(
                    model = %model,
                    reason = why,
                    registered = st.registered,
                    healthy = st.healthy,
                    stale_after_secs = state.agent_stale_after.as_secs(),
                    oldest_last_seen_secs = st.oldest_last_seen_ago.map(|d| d.as_secs()),
                    "no agent to route to"
                );
                // 已经试过连接却挑不出下一条 → 把**真正的失败原因**（隧道错误）报给客户端，
                // 而不是报一个会误导的 503/404。
                if let Some(err) = last_failure {
                    state.metrics.record_tunnel_retry("no-alternative");
                    return Err(RouteFailure {
                        status: StatusCode::BAD_GATEWAY,
                        message: format!("{err}; no other agent available to retry"),
                    });
                }
                let (status, message) = match reason {
                    AcquireError::NoAgent => (StatusCode::SERVICE_UNAVAILABLE, "no edge available"),
                    AcquireError::NoModel => {
                        (StatusCode::NOT_FOUND, "model not found on any agent")
                    }
                    AcquireError::AtCapacity => {
                        (StatusCode::TOO_MANY_REQUESTS, "agent at capacity")
                    }
                };
                return Err(RouteFailure {
                    status,
                    message: message.to_string(),
                });
            }
        };

        // 记下本次选中的连接：重试时不会再选它（否则重试没有意义）。
        tried.push(entry.stable_id);

        let stream = match open_tunnel(&mut entry, state.tunnel_op_timeout).await {
            Ok(s) => s,
            Err(failure) => {
                // 开流超时有两种成因，**不能用同一个动作处置**：
                //
                //   忙：这条连接的在途请求已经顶到它的承载上限（声明的 max_concurrency
                //       与端点流额度取小），开流是在排队等额度回收 → 排队超时是正常背压。
                //       此时摘除等于把"局部过载"升级成"整台 agent 下线"：连接被关 →
                //       agent 重连 → 注册表瞬间为空 → 期间所有请求 503。实测过一次
                //       30s 压测 +6835 次 registry-empty，根因就在这里。
                //   死：并没到承载上限却开不出流 → 没有任何排队理由，这才是坏连接。
                //
                // 所以只有"死"才摘除；"忙"只记指标 + 换下一条连接（重试逻辑与下面共用）。
                let busy = matches!(failure, OpenFailure::TimedOut)
                    && !entry.open_timeout_is_fatal(state.max_open_tunnel_streams);
                let err = failure.message();
                if busy {
                    state.metrics.record_tunnel_open_timeout("busy");
                    warn!(
                        request_id,
                        agent = %entry.agent_id,
                        inflight = entry.inflight.load(std::sync::atomic::Ordering::Relaxed),
                        max_concurrency = entry.max_concurrency,
                        stream_ceiling = state.max_open_tunnel_streams,
                        timeout_ms = state.tunnel_op_timeout.as_millis(),
                        "tunnel open timed out while agent is at capacity; not evicting, trying another agent"
                    );
                } else {
                    state.metrics.record_tunnel_open_timeout("dead");
                    warn!(
                        agent = %entry.agent_id,
                        timeout_ms = state.tunnel_op_timeout.as_millis(),
                        "tunnel open timed out; evicting agent"
                    );
                    // 打不开流 = 这条连接已经死了 → 摘掉条目（连续超时足够才会真摘），
                    // 然后换个 agent 重试；没有别的候选时把错误报给客户端。
                    state.registry.evict(
                        entry.stable_id,
                        EvictCause::OpenTimeout,
                        state.evict_close_grace,
                    );
                }
                if tried.len() >= MAX_TUNNEL_ATTEMPTS {
                    state.metrics.record_tunnel_retry("failed");
                    return Err(RouteFailure {
                        status: if busy {
                            StatusCode::TOO_MANY_REQUESTS
                        } else {
                            StatusCode::BAD_GATEWAY
                        },
                        message: if busy {
                            "agent at capacity".to_string()
                        } else {
                            err
                        },
                    });
                }
                warn!(
                    request_id,
                    agent = %entry.agent_id,
                    error = %err,
                    "tunnel open failed; retrying on another agent"
                ); // "忙"不算隧道故障：不写进 last_failure，这样即使最后挑不出别的 agent，
                   // 客户端拿到的是"容量不足（429）"而不是误导性的"隧道坏了（502）"。
                   //
                   // 也**不**在这里记 agent_rejections——那个计数器统计的是"最终没被服务的请求"
                   // （按原因分）。这次重试可能成功，提前记会虚增容量告警；真正挑不出候选时，
                   // 下一轮 `try_acquire_excluding` 会自己记 `all-candidates-at-capacity`。
                if !busy {
                    last_failure = Some(err);
                }
                continue;
            }
        };
        let (recv, mut send) = stream.split();

        if let Err(failure) = tunnel_write(
            &mut send,
            request,
            state.tunnel_op_timeout,
            request_id,
            &entry.agent_id,
        )
        .await
        {
            // 写**超时**是连接级背压，不是死亡（与开流臂的 busy 同源）：不摘除，只重试。
            // 只有"写直接失败"才说明这条连接确实不可用，计一次 strike。
            state.metrics.record_tunnel_write_failure(failure.class());
            if failure.is_tunnel_broken() {
                state.registry.evict(
                    entry.stable_id,
                    EvictCause::TunnelWriteFailed,
                    state.evict_close_grace,
                );
            }
            let e = failure.message();
            if tried.len() >= MAX_TUNNEL_ATTEMPTS {
                state.metrics.record_tunnel_retry("failed");
                // 为什么这里保持 502，而不像开流臂的 busy 那样给 429：写超时**没有**"容量已满"
                // 的正面证据——连接级背压由共享发送缓冲/UDP socket 决定，一条流也能把它填满，
                // 在途流数不是有效代理（这正是本臂不复用 open_timeout_is_fatal 的原因）。
                // 429 还会带上 `Retry-After: 60` 与 `error.type=rate_limit_error`，等于把
                // "服务端这次刷不出去"说成"客户端发太多"，并让客户端白等一分钟。
                // 背压与坏连接的区分由 `hlmg_tunnel_write_failures_total{class=…}` 与日志承担。
                return Err(RouteFailure {
                    status: StatusCode::BAD_GATEWAY,
                    message: e,
                });
            }
            warn!(
                request_id,
                agent = %entry.agent_id,
                error = %e,
                "request frame write failed; retrying on another agent"
            );
            last_failure = Some(e);
            continue;
        }

        if tried.len() > 1 {
            // 这次是重试成功的：对客户端是一次不可见的自愈。
            state.metrics.record_tunnel_retry("ok");
        }
        break (entry, slot, recv, send);
    };
    Ok((entry, slot, recv, send))
}
