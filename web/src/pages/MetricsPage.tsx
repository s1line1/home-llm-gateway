// 指标页：轮询采样趋势图 + 状态码分布 + 原始 Prometheus 文本查看。

import { useMetricsHistory } from "../hooks/useMetricsHistory";
import { formatBytes, formatDuration } from "../api/metrics";
import { BarList, Sparkline } from "../components/charts";
import { Button, Card } from "../components/ui";
import { useState } from "react";

export default function MetricsPage() {
  const { latest, history, raw, error } = useMetricsHistory();
  const [showRaw, setShowRaw] = useState(false);

  const active = history.map((h) => h.active_requests);
  const bytes = history.map((h) => h.bytes_out);
  const agents = history.map((h) => h.agents);
  const counts = history.map((h) => h.request_count);

  const statusItems = latest
    ? Object.entries(latest.requests_by_status)
        .sort(([a], [b]) => Number(a) - Number(b))
        .map(([code, value]) => ({ label: code, value }))
    : [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">指标</h2>
          <p className="text-sm text-slate-500">
            每 5 秒轮询 <code className="rounded bg-slate-100 px-1 font-mono text-xs">/metrics</code>，保留最近 60 个采样点
          </p>
        </div>
        <Button variant="secondary" onClick={() => setShowRaw((v) => !v)}>
          {showRaw ? "隐藏原始数据" : "查看原始 Prometheus"}
        </Button>
      </div>

      {error && (
        <p className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-700">
          最近一次拉取失败：{error}（展示的是上一次成功数据）
        </p>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="在途请求" subtitle="gauge：当前并发转发数">
          <Sparkline data={active} stroke="#0f766e" />
        </Card>
        <Card title="在线 Agent 数" subtitle="gauge：已注册 agent 数">
          <Sparkline data={agents} stroke="#4338ca" />
        </Card>
        <Card title="累计请求数" subtitle="counter：自网关启动累计">
          <Sparkline data={counts} stroke="#b45309" />
        </Card>
        <Card title="累计转发字节" subtitle="counter：回传客户端字节数">
          <Sparkline data={bytes} stroke="#be185d" />
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="状态码分布" subtitle="hlmg_requests_total 按状态码">
          {statusItems.length > 0 ? (
            <BarList items={statusItems} />
          ) : (
            <p className="py-6 text-center text-sm text-slate-400">暂无请求记录</p>
          )}
        </Card>
        <Card title="汇总" subtitle="累计值">
          {latest ? (
            <dl className="space-y-2 text-sm">
              {[
                ["累计请求数", latest.request_count.toLocaleString()],
                ["平均耗时", latest.request_count > 0 ? formatDuration(latest.request_duration_ms / latest.request_count) : "—"],
                ["累计耗时", formatDuration(latest.request_duration_ms)],
                ["累计转发", formatBytes(latest.bytes_out)],
                ["在线 Agents", String(latest.agents)],
              ].map(([k, v]) => (
                <div key={k} className="flex items-center justify-between border-b border-slate-50 pb-1.5 last:border-0">
                  <dt className="text-slate-500">{k}</dt>
                  <dd className="font-mono font-medium tabular-nums text-slate-800">{v}</dd>
                </div>
              ))}
            </dl>
          ) : (
            <p className="py-6 text-center text-sm text-slate-400">等待首次采样…</p>
          )}
        </Card>
      </div>

      {showRaw && (
        <Card title="原始 /metrics" subtitle="Prometheus 文本格式">
          <pre className="max-h-96 overflow-auto rounded-lg bg-slate-900 p-4 text-xs leading-relaxed text-slate-200">
            {raw ?? (error ? `拉取失败：${error}` : "等待首次采样…")}
          </pre>
        </Card>
      )}
    </div>
  );
}
