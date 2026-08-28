// 总览页：网关健康 + 关键指标卡片 + 在途请求/agent 数趋势。

import { useMetricsHistory } from "../hooks/useMetricsHistory";
import { formatBytes, formatDuration } from "../api/metrics";
import { Sparkline } from "../components/charts";
import { Card, StatCard } from "../components/ui";

export default function Overview() {
  const { latest, history } = useMetricsHistory();

  const active = history.map((h) => h.active_requests);
  const agents = history.map((h) => h.agents);
  const avgMs = latest && latest.request_count > 0 ? latest.request_duration_ms / latest.request_count : 0;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">总览</h2>
        <p className="text-sm text-slate-500">网关实时状态与关键指标（每 5 秒采样）</p>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          label="在线 Agents"
          value={latest ? latest.agents : "—"}
          hint="已注册且未失联"
          tone={latest && latest.agents > 0 ? "ok" : "warn"}
        />
        <StatCard
          label="在途请求"
          value={latest ? latest.active_requests : "—"}
          hint="当前并发转发中"
        />
        <StatCard
          label="累计请求"
          value={latest ? latest.request_count.toLocaleString() : "—"}
          hint={latest && latest.request_count > 0 ? `平均耗时 ${formatDuration(avgMs)}` : undefined}
        />
        <StatCard
          label="累计转发"
          value={latest ? formatBytes(latest.bytes_out) : "—"}
          hint="回传给客户端的字节"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card
          title="在途请求趋势"
          subtitle="最近 60 个采样点（5s 间隔）"
          right={<span className="text-xs text-slate-400">{active.length} 点</span>}
        >
          <Sparkline data={active} stroke="#0f766e" />
        </Card>
        <Card
          title="在线 Agent 数趋势"
          subtitle="最近 60 个采样点"
          right={<span className="text-xs text-slate-400">{agents.length} 点</span>}
        >
          <Sparkline data={agents} stroke="#4338ca" />
        </Card>
      </div>

      <Card title="状态码分布（累计）" subtitle="按 HTTP 状态码的请求计数">
        {latest && Object.keys(latest.requests_by_status).length > 0 ? (
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {Object.entries(latest.requests_by_status)
              .sort(([a], [b]) => Number(a) - Number(b))
              .map(([code, count]) => (
                <div key={code} className="flex items-center justify-between rounded-lg bg-slate-50 px-3 py-2">
                  <span className="font-mono text-sm text-slate-600">{code}</span>
                  <span className="font-mono text-sm font-semibold tabular-nums">{count}</span>
                </div>
              ))}
          </div>
        ) : (
          <p className="py-6 text-center text-sm text-slate-400">暂无请求记录</p>
        )}
      </Card>
    </div>
  );
}
