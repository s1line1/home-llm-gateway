import { act, renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { MetricsHistoryProvider, useMetricsHistory } from "./useMetricsHistory";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

const METRICS_TEXT = ["hlmg_agents 3", "hlmg_agents_healthy 1", "hlmg_active_requests 2"].join(
  "\n",
);

/**
 * 在 provider 里渲染 hook。轮询归 provider 所有，所以测试也必须**真的**包一层——顺便就钉住了
 * "没有 provider 会抛错"这条约束（见本文件最后一条）。
 */
function renderShared(intervalMs = 1000) {
  return renderHook(() => useMetricsHistory(), {
    wrapper: ({ children }: { children: ReactNode }) => (
      <MetricsHistoryProvider intervalMs={intervalMs}>{children}</MetricsHistoryProvider>
    ),
  });
}

/**
 * 复扫 G2：`tick()` 里 `await fetchMetricsText()` 原先无超时，而下一次采样只在 `finally`
 * 注册 ⇒ 请求永不 settle 时循环不再调度、`catch` 也不执行 ⇒ `reachable`/`latest` 冻结在上次
 * 成功的值上，界面继续显示"网关在线 · N agents"（假绿）。超时补在 `client.ts` 那一侧，这里钉住
 * **一次失败之后轮询必须继续**。
 */
describe("useMetricsHistory：一次失败不能停掉轮询（复扫 G2）", () => {
  it("拉取失败后标记不可达，并且继续安排下一次采样", async () => {
    let calls = 0;
    vi.stubGlobal("fetch", async () => {
      calls += 1;
      throw new Error("metrics 超时");
    });

    vi.useFakeTimers();
    const { result } = renderShared();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(calls).toBe(1);
    expect(result.current.reachable).toBe(false);
    expect(result.current.error).toContain("超时");

    // 这条才是 G2 的实质：失败**没有**让循环停下来。
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(calls).toBe(2);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(calls).toBe(3);
  });

  it("200 但不是 Prometheus 文本（例如中间缓存塞进来的 HTML）→ 判不可达，而不是展示全 0", async () => {
    // 复扫 G3：网关对 `Accept: text/html` 会在**同一个 `/metrics` URL** 上回 SPA 页面（A5），
    // 一旦缓存按 URI 作键张冠李戴，Dashboard 的 fetch 就会拿到 HTML。原先的解析器把"一行都
    // 解析不出来"当成"所有指标都是 0"，于是界面显示 0 agents / 0 请求——与"网关真的空闲"
    // 完全不可区分。正确的做法是把它当成一次失败：标记不可达，**不**产出快照。
    vi.stubGlobal(
      "fetch",
      async () =>
        new Response('<!doctype html><div id="root">ui</div>', {
          status: 200,
          headers: { "content-type": "text/html; charset=utf-8" },
        }),
    );

    vi.useFakeTimers();
    const { result } = renderShared();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(result.current.reachable).toBe(false);
    expect(result.current.latest).toBeNull();
    expect(result.current.history).toHaveLength(0);
    expect(result.current.error).toBeTruthy();
  });

  it("恢复后 reachable 回到 true，快照与原始文本都重新累积", async () => {
    let failing = true;
    vi.stubGlobal("fetch", async () => {
      if (failing) throw new Error("挂死");
      return new Response(METRICS_TEXT);
    });

    vi.useFakeTimers();
    const { result } = renderShared();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(result.current.reachable).toBe(false);
    expect(result.current.latest).toBeNull();
    expect(result.current.history).toHaveLength(0);

    failing = false;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(result.current.reachable).toBe(true);
    expect(result.current.error).toBeNull();
    expect(result.current.latest?.agents).toBe(3);
    expect(result.current.latest?.agents_healthy).toBe(1);
    expect(result.current.raw).toBe(METRICS_TEXT);
    expect(result.current.history).toHaveLength(1);
  });
});

/**
 * 复扫 G4：`Layout`（侧边栏）与当前页面**同时**挂着，而它们以前各自实例化这个 hook ⇒ 同一瞬间
 * 有 2 条独立 `/metrics` 轮询、采样时刻不同步，侧边栏与页面卡片可以显示两个不同的数字。现在
 * 只有 provider 里的那一条，消费者共享同一次采样。
 */
describe("useMetricsHistory：多个消费者共享一条轮询（复扫 G4）", () => {
  it("两个消费者只产生一次请求，且看到的是同一个快照", async () => {
    let calls = 0;
    vi.stubGlobal("fetch", async () => {
      calls += 1;
      return new Response(METRICS_TEXT);
    });

    vi.useFakeTimers();
    const { result } = renderHook(
      // 侧边栏与页面：同一个 provider 下的两个消费者
      () => ({ sidebar: useMetricsHistory(), page: useMetricsHistory() }),
      {
        wrapper: ({ children }: { children: ReactNode }) => (
          <MetricsHistoryProvider intervalMs={1000}>{children}</MetricsHistoryProvider>
        ),
      },
    );

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(calls).toBe(1);
    expect(result.current.sidebar.latest).not.toBeNull();
    // 同一个对象：两位消费者读的是**同一次**采样，不是两次各自解析的结果
    expect(result.current.sidebar.latest).toBe(result.current.page.latest);
    expect(result.current.sidebar.reachable).toBe(result.current.page.reachable);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(calls).toBe(2);
    expect(result.current.sidebar.history).toHaveLength(2);
    expect(result.current.sidebar.history).toBe(result.current.page.history);
  });

  it("没有 provider 时**抛错**，而不是悄悄退化成一条私有轮询", () => {
    // 静默退化会把 G4 放回来（"两个数字对不上"又变得不可见），所以这里要吵。
    expect(() => renderHook(() => useMetricsHistory())).toThrow(/MetricsHistoryProvider/);
  });
});
