// 轮询 /metrics 并保留最近 N 个采样点（用于趋势图表）。

import { useEffect, useState } from "react";

import { fetchMetricsText } from "../api/client";
import { parseMetrics } from "../api/metrics";
import type { MetricsSnapshot } from "../api/types";

const POLL_MS = 5000;

export interface MetricsHistory {
  /** 最新快照；未取到过时为 null。 */
  latest: MetricsSnapshot | null;
  /** 时间升序的采样历史（最多 HISTORY_LEN 个）。 */
  history: MetricsSnapshot[];
  /** 最近一次成功拉取的原始 Prometheus 文本。 */
  raw: string | null;
  /** 最近一次拉取错误信息（连续失败时保留上次成功数据）。 */
  error: string | null;
  /** 网关是否可达（healthz 失败时为 false，用于总览状态点）。 */
  reachable: boolean;
}

export function useMetricsHistory(intervalMs = POLL_MS): MetricsHistory {
  const [history, setHistory] = useState<MetricsSnapshot[]>([]);
  const [raw, setRaw] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reachable, setReachable] = useState(true);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const tick = async () => {
      try {
        const text = await fetchMetricsText();
        if (cancelled) return;
        const snap = parseMetrics(text);
        setHistory((prev) => {
          const next = [...prev, snap];
          return next.length > 60 ? next.slice(next.length - 60) : next;
        });
        setRaw(text);
        setError(null);
        setReachable(true);
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : String(e));
        // metrics 拉不到不代表网关下线（可能是权限/路由问题），仅标记不可达
        setReachable(false);
      } finally {
        if (!cancelled) timer = setTimeout(tick, intervalMs);
      }
    };

    void tick();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [intervalMs]);

  return {
    latest: history.length > 0 ? history[history.length - 1] : null,
    history,
    raw,
    error,
    reachable,
  };
}
