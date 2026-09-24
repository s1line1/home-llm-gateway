// 网关 HTTP 客户端：fetch 封装，Bearer 认证 + 统一错误处理。

import type { AgentInfo, ApiKey, CreatedKey, HealthStatus } from "./types";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

const jsonHeaders = (token: string | null) => ({
  "Content-Type": "application/json",
  ...(token ? { Authorization: `Bearer ${token}` } : {}),
});

/**
 * JSON 边界的**形状**校验。
 *
 * `as T` 不做任何运行时检查：网关版本错配（字段改名/变成错误对象）时，问题会在
 * `data.map(...)` 那类地方炸成一句看不出原因的错误。这里只校最基本的形状（数组/对象），
 * 把失败点前移，并说清是哪个端点、收到的是什么（P3-20）。
 */
function expectArray<T>(value: unknown, what: string): T[] {
  if (!Array.isArray(value)) throw new Error(`${what}: 期望数组，收到 ${describe(value)}`);
  return value as T[];
}

function expectObject<T>(value: unknown, what: string): T {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${what}: 期望对象，收到 ${describe(value)}`);
  }
  return value as T;
}

function describe(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

async function handle<T>(resp: Response): Promise<T> {
  if (!resp.ok) {
    let message = `HTTP ${resp.status}`;
    try {
      const body = (await resp.json()) as { error?: { message?: string } };
      if (body.error?.message) message = body.error.message;
    } catch {
      // 非 JSON 响应，保留状态码
    }
    throw new ApiError(resp.status, message);
  }
  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

/** 网关健康探针（返回纯文本 "ok"）。 */
export async function fetchHealth(): Promise<HealthStatus> {
  try {
    const resp = await fetch("/healthz", { cache: "no-store" });
    return { ok: resp.ok, text: resp.ok ? await resp.text() : `HTTP ${resp.status}` };
  } catch (e) {
    return { ok: false, text: e instanceof Error ? e.message : String(e) };
  }
}

/** 网关 /metrics（Prometheus 文本）。 */
export async function fetchMetricsText(): Promise<string> {
  const resp = await fetch("/metrics", { cache: "no-store" });
  if (!resp.ok) throw new ApiError(resp.status, `metrics: HTTP ${resp.status}`);
  return resp.text();
}

export async function listKeys(token: string): Promise<ApiKey[]> {
  const resp = await fetch("/admin/keys", {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  return expectArray<ApiKey>(await handle<unknown>(resp), "GET /admin/keys");
}

export async function createKey(token: string, name: string): Promise<CreatedKey> {
  const resp = await fetch("/admin/keys", {
    method: "POST",
    headers: jsonHeaders(token),
    body: JSON.stringify({ name }),
  });
  return expectObject<CreatedKey>(await handle<unknown>(resp), "POST /admin/keys");
}

export async function deleteKey(token: string, id: string): Promise<void> {
  const resp = await fetch(`/admin/keys/${encodeURIComponent(id)}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
  });
  await handle<void>(resp);
}

/**
 * Agent 明细（网关已实现；数据来自注册表实时快照）。
 * 返回 null 表示拿不到明细——旧版网关，或该部署未配置 admin_token（`/admin/*` 未挂载）；
 * 由调用方决定降级展示。
 */
export async function fetchAgents(token: string): Promise<AgentInfo[] | null> {
  const resp = await fetch("/admin/agents", {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  if (resp.status === 404) return null;
  return expectArray<AgentInfo>(await handle<unknown>(resp), "GET /admin/agents");
}
