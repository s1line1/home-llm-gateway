// Agents 页：在线 agent 状态。明细来自 /admin/agents（agent_id / models /
// max_concurrency / inflight / last_seen），顶部卡展示在线总数（/metrics）
// 与明细聚合（在途、并发上限合计）。

import { useQuery } from "@tanstack/react-query";

import { fetchAgents } from "../api/client";
import { useAdminToken } from "../hooks/useAdminToken";
import { useMetricsHistory } from "../hooks/useMetricsHistory";
import { Card, EmptyState, StatusPill } from "../components/ui";

function AgentTable({ agents }: { agents: NonNullable<Awaited<ReturnType<typeof fetchAgents>>> }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-slate-100 text-xs text-slate-500">
            <th className="pb-2 pr-4 font-medium">Agent ID</th>
            <th className="pb-2 pr-4 font-medium">模型</th>
            <th className="pb-2 pr-4 font-medium">并发上限</th>
            <th className="pb-2 pr-4 font-medium">在途</th>
            <th className="pb-2 pr-4 font-medium">最后心跳</th>
            <th className="pb-2 font-medium">状态</th>
          </tr>
        </thead>
        <tbody>
          {agents.map((a) => {
            const stale = a.last_seen_secs_ago > 15;
            const full = a.inflight >= (a.max_concurrency || Number.POSITIVE_INFINITY);
            return (
              <tr key={a.agent_id} className="border-b border-slate-50 last:border-0">
                <td className="py-2.5 pr-4 font-mono text-xs font-medium text-slate-800">{a.agent_id}</td>
                <td className="py-2.5 pr-4 text-xs text-slate-600">
                  {a.models.join(", ") || "—"}
                </td>
                <td className="py-2.5 pr-4 tabular-nums text-slate-600">
                  {a.max_concurrency === 0 ? "不限" : a.max_concurrency}
                </td>
                <td className="py-2.5 pr-4 tabular-nums text-slate-600">{a.inflight}</td>
                <td className="py-2.5 pr-4 text-slate-600">{a.last_seen_secs_ago}s 前</td>
                <td className="py-2.5">
                  {stale ? (
                    <StatusPill ok={false} label="失联" />
                  ) : full ? (
                    <StatusPill ok={false} label="已满" />
                  ) : (
                    <StatusPill ok label="在线" />
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default function Agents() {
  const token = useAdminToken();
  const { latest } = useMetricsHistory();

  const detailQuery = useQuery({
    queryKey: ["admin", "agents"],
    queryFn: () => fetchAgents(token),
    enabled: !!token,
    refetchInterval: 5000,
    retry: false,
  });

  const hasDetail = detailQuery.data !== null && !detailQuery.isError;
  // 旧版网关（或未挂载 /admin/* 的部署）返回 404 → 降级为仅显示汇总
  const detailUnavailable = detailQuery.isError && detailQuery.error.message.includes("404");

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Agents 状态</h2>
        <p className="text-sm text-slate-500">edge-agent 在线状态与并发负载</p>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
        <Card title="在线 Agent" subtitle="来自 /metrics 的实时计数">
          <div className="text-2xl font-semibold tabular-nums text-emerald-600">
            {latest ? latest.agents : "—"}
          </div>
        </Card>
        <Card title="在途请求" subtitle="所有 agent 合计">
          <div className="text-2xl font-semibold tabular-nums">{latest ? latest.active_requests : "—"}</div>
        </Card>
        <Card title="并发上限" subtitle="agent 声明值合计，用于 admission control">
          <div className="text-2xl font-semibold tabular-nums">
            {detailQuery.data && detailQuery.data.length > 0
              ? detailQuery.data.some((a) => a.max_concurrency === 0)
                ? "不限"
                : detailQuery.data.reduce((s, a) => s + (a.max_concurrency || 0), 0)
              : "—"}
          </div>
        </Card>
      </div>

      <Card
        title="Agent 明细"
        subtitle={
          hasDetail
            ? "来自 /admin/agents（每 5 秒刷新）"
            : "未取到 /admin/agents 明细（旧版网关或未启用 /admin/*），仅显示汇总"
        }
      >
        {detailQuery.isPending ? (
          <EmptyState text="加载中…" />
        ) : detailUnavailable ? (
          <div className="space-y-3">
            <p className="text-sm text-slate-500">
              <code className="rounded bg-slate-100 px-1 font-mono text-xs">GET /admin/agents</code>{" "}
              返回 404：网关版本较旧，或该部署没有配置 <code className="rounded bg-slate-100 px-1 font-mono text-xs">admin_token</code>
              （`/admin/*` 未挂载）。在线总数见上方卡片。
            </p>
          </div>
        ) : detailQuery.isError ? (
          <EmptyState text={`加载失败：${detailQuery.error.message}`} />
        ) : detailQuery.data === null || detailQuery.data.length === 0 ? (
          <EmptyState text="暂无在线 agent" />
        ) : (
          <AgentTable agents={detailQuery.data} />
        )}
      </Card>
    </div>
  );
}
