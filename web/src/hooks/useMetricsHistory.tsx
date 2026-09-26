// 轮询 /metrics 并保留最近 N 个采样点（用于趋势图表）。
//
// **只有一条轮询**（复扫 G4）：它由 [`MetricsHistoryProvider`] 持有，值通过 context 下发。
// 以前这是"每个调用方各一条轮询"，而 `Layout` 与当前页面是**同时**挂着的（侧边栏要 latest，
// Overview / MetricsPage 还要 history 与 raw）⇒ 同一瞬间有 2 条独立请求、采样时刻不同步，
// 侧边栏与页面卡片可以显示两个不同的数字——两个都不算错，但看起来像错的。
//
// 为什么是 provider 而不是模块级单例：与 `api/queryClient.ts` 同一口径——可测性靠**注入**
// （测试自己给 `intervalMs`、自己包 provider），而不是靠"记得在 afterEach 里重置模块状态"。

import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

import { fetchMetricsText } from "../api/client";
import { parseMetrics } from "../api/metrics";
import { HISTORY_LEN, type MetricsSnapshot } from "../api/types";

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
  /** 网关是否可达（最近一次 /metrics 拉取失败时为 false，用于总览状态点）。 */
  reachable: boolean;
}

const MetricsHistoryContext = createContext<MetricsHistory | null>(null);

/**
 * 唯一的 `/metrics` 轮询。挂在**已登录的壳**上（`main.tsx` 里包住 `Layout`）：登录页不该拉
 * `/metrics`，而登录之后整棵树共享同一份历史（切页面不会重启采样）。
 *
 * `intervalMs` 是 provider 的属性而不是每个消费者的参数：一个循环只有一个节奏，让每个调用方
 * 各报一个间隔只会重新制造 G4 那个"多个采样时刻"的问题。
 */
export function MetricsHistoryProvider({
  children,
  intervalMs = POLL_MS,
}: {
  children: ReactNode;
  intervalMs?: number;
}) {
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
          return next.length > HISTORY_LEN ? next.slice(next.length - HISTORY_LEN) : next;
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
    // `intervalMs` 就在本 effect 内被用（`finally` 里 `setTimeout(tick, intervalMs)`），而
    // oxlint 1.85 追踪不到那次引用 —— 这条是误报。注意抑制指令必须**紧贴**目标行，中间
    // 再夹一行说明就失效，所以说明写在上面、指令单独一行。
    // oxlint-disable-next-line react/exhaustive-effect-dependencies
  }, [intervalMs]);

  const value = useMemo<MetricsHistory>(
    () => ({
      latest: history.length > 0 ? history[history.length - 1] : null,
      history,
      raw,
      error,
      reachable,
    }),
    [history, raw, error, reachable],
  );

  return <MetricsHistoryContext.Provider value={value}>{children}</MetricsHistoryContext.Provider>;
}

/**
 * 当前共享的 `/metrics` 历史。
 *
 * 没有 provider 时**抛错**而不是自己退化成一条私有轮询：那样会在"有人忘了包 provider"时
 * 悄悄回到 G4 的多份采样，而症状（两个数字对不上）正是这条修复要消灭的东西。
 */
export function useMetricsHistory(): MetricsHistory {
  const value = useContext(MetricsHistoryContext);
  if (!value) {
    throw new Error(
      "useMetricsHistory 需要 <MetricsHistoryProvider>（一个已登录的壳只挂一个，见该组件文档）",
    );
  }
  return value;
}
