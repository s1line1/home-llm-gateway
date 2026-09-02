// 网关 API 数据类型（与 crates/gateway/src 的 JSON 契约对齐）。

/** 每个 API key 的 token 用量（/admin/keys 内嵌 + /admin/usage）。 */
export interface KeyUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  requests: number;
  /** 其中多少次请求走了估算降级（上游未提供 usage）。 */
  estimated_requests: number;
  /** 最后使用时间（unix 秒；无请求为 0）。 */
  last_used_at: number;
}

/** GET /admin/keys 返回的 key 记录（明文不落盘，prefix 为固定掩码）。 */
export interface ApiKey {
  id: string;
  name: string;
  created_at: number;
  enabled: boolean;
  prefix: string;
  /** 用量汇总（无记录时各字段为 0）。 */
  usage: KeyUsage;
}

/** /admin/usage 的单条记录（含已吊销 key 的历史，可审计）。 */
export interface UsageRecord {
  key_id: string;
  name: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  requests: number;
  estimated_requests: number;
  last_used_at: number;
}

/** POST /admin/keys 创建成功时返回（明文 key 仅此一次展示）。 */
export interface CreatedKey extends ApiKey {
  key: string;
}

/** GET /healthz 存活探针。 */
export type HealthStatus = { ok: boolean; text: string };

/**
 * GET /admin/agents 的 agent 明细（契约预留）。
 * 当前网关版本尚未实现该端点（registry 为进程内存），实现后返回：
 * agent_id / models / max_concurrency / inflight / last_seen 距现在秒数。
 * 前端在 404 时优雅降级为仅展示 /metrics 中的在线总数。
 */
export interface AgentInfo {
  agent_id: string;
  models: string[];
  max_concurrency: number;
  /** 当前在途请求数。 */
  inflight: number;
  /** 距上次心跳的秒数（越小越健康）。 */
  last_seen_secs_ago: number;
}

/** 从 /metrics 解析出的网关指标快照。 */
export interface MetricsSnapshot {
  fetched_at: number;
  /** 按 HTTP 状态码计数的累计请求数。 */
  requests_by_status: Record<number, number>;
  /** 当前在途请求数（gauge）。 */
  active_requests: number;
  /** 当前在线（已注册）agent 数（gauge）。 */
  agents: number;
  /** 累计转发给客户端的字节数（counter）。 */
  bytes_out: number;
  /** 累计请求耗时（毫秒，sum）。 */
  request_duration_ms: number;
  /** 累计请求数（sum）。 */
  request_count: number;
}

/** 轮询保留的最近采样点数。 */
export const HISTORY_LEN = 60;
