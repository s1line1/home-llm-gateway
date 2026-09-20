//! 请求 id 的唯一来源：HTTP 层（`x-request-id` 响应头、访问日志）与隧道层（帧内
//! `request_id`）共用**同一个**计数器，"三方对账一致"才谈得上成立。
//!
//! 为什么需要这个模块（TODO 登记过的真实缺口）：拆分 `http.rs` 之前，
//! `metrics_middleware` 与 `proxy` 各自持有一个 `static NEXT_REQUEST_ID`，都从 1 开始。
//! 客户端自带 `req-<u64>` 时两者数值一致，看起来没问题；但 Codex/DSH 发的是 UUID →
//! `proxy` 解析失败，回落到**它自己那个**计数器，于是同一次请求的响应头 id 与隧道
//! `request_id` 是两个不相干的数列，而且两个计数器各自递增会周期性地撞号
//! （HTTP 层的第 7 个请求与隧道的第 7 个请求拿到同一个数字，发给不同的 agent）。
//!
//! 现在的分工：
//! - 隧道 `request_id` 只从本模块取（[`tunnel_id`]），不再有第二个计数器；
//! - 入站 `req-<u64>` 形状仍被沿用（幂等重试时客户端能自己对账）；
//! - 其他形状（UUID、`req-` 后跟非数字、非法头）**丢弃入站数值**、分配新号，
//!   但响应头仍回显客户端原值，并在日志里同时记 `request_id` 与 `client_request_id`
//!   ——两者不一致时靠这条日志对账。
//! - 帧内 `request_id` 保持 `u64`（TODO 里提到的"改用字符串"方案**未**采用）：
//!   改协议字段类型要动 proto/agent/mock-llm 三处，收益只是省掉这条日志映射，
//!   不值得在这个改动里顺手做。

use axum::http::{HeaderMap, HeaderValue};

/// 进程内 id 分配器。两个计数器合并成一个，起点仍是 1（保持日志里的 id 形态与既有
/// 部署可对比）。`Relaxed` 足够：只需要"不重复"，不需要与任何其他内存操作排序。
static NEXT_REQUEST_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// 分配一个新号，进程内不重复。
fn next() -> u64 {
    NEXT_REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// 解析入站 `x-request-id`：只有 `req-<u64>` 形状能充当隧道 id。
///
/// `req-0` 也接受（当前行为一致：客户端选的号就归它，自增号从 1 起不会撞上它）。
fn parse(inbound: &str) -> Option<u64> {
    inbound.strip_prefix("req-")?.parse::<u64>().ok()
}

/// 隧道 `request_id`：入站 id 可用则沿用，否则分配新号。
pub(crate) fn tunnel_id(inbound: Option<&str>) -> u64 {
    inbound.and_then(parse).unwrap_or_else(next)
}

/// 从入站 headers 取隧道 `request_id`（`metrics_middleware` 已把规范化的
/// `req-{n}` 写回 headers，所以这里的兜底分支只在中间件缺席时生效，
/// 例如直接调用 `proxy` 的单元测试）。
pub(crate) fn tunnel_id_from_headers(headers: &HeaderMap) -> u64 {
    tunnel_id(headers.get("x-request-id").and_then(|v| v.to_str().ok()))
}

/// `x-request-id` 的规范形状 `req-{id}`：响应头与访问日志都用它。
pub(crate) fn format(id: u64) -> String {
    format!("req-{id}")
}

/// 把字符串写成头值；非法值（非可见 ASCII）返回 `None`，调用方负责跳过。
pub(crate) fn header_value(s: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_only_accepts_req_number() {
        assert_eq!(parse("req-42"), Some(42));
        assert_eq!(parse("req-0"), Some(0));
        // 真实客户端（Codex/DSH）发的是 UUID 形态 → 不能当隧道 id 用
        assert_eq!(parse("0197f1c2-9f0b-7c31-8a44-1b2c3d4e5f60"), None);
        assert_eq!(parse("req-"), None);
        assert_eq!(parse("req-abc"), None);
        assert_eq!(parse("42"), None);
        assert_eq!(parse("REQ-42"), None);
    }

    #[test]
    fn inbound_req_number_is_reused() {
        assert_eq!(tunnel_id(Some("req-999")), 999);
        assert_eq!(tunnel_id(Some("req-1")), 1);
    }

    #[test]
    fn unusable_inbound_ids_draw_from_the_same_counter() {
        let a = tunnel_id(None);
        let b = tunnel_id(Some("0197f1c2-9f0b-7c31-8a44-1b2c3d4e5f60"));
        assert!(a >= 1, "自增号从 1 起: {a}");
        assert!(b > a, "两次分配必须来自同一计数器且严格递增: {a} -> {b}");
    }

    #[test]
    fn format_is_the_canonical_header_shape() {
        assert_eq!(format(7), "req-7");
        assert_eq!(header_value("req-7").unwrap().to_str().unwrap(), "req-7");
        // 非法头值（此处用换行，HeaderValue 不允许）→ None，调用方跳过写入
        assert!(header_value("req-\n7").is_none());
    }
}
