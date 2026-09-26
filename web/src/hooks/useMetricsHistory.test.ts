import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useMetricsHistory } from "./useMetricsHistory";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

const METRICS_TEXT = ["hlmg_agents 3", "hlmg_agents_healthy 1", "hlmg_active_requests 2"].join(
  "\n",
);

/**
 * 复扫 G2：这个 hook 原先在所有测试里都被 mock 掉，"`/metrics` 挂死"这条失败模式因此零覆盖。
 *
 * 机制：`tick()` 里 `await fetchMetricsText()` 无超时，而下一次采样只在 `finally` 注册 ⇒
 * 请求永不 settle 时循环不再调度、`catch` 也不执行 ⇒ `reachable`/`latest` 冻结在上次成功的
 * 值上，界面继续显示"网关在线 · N agents"（假绿）。超时补在 `client.ts` 那一侧，这里钉住
 * hook 的行为：**一次失败之后轮询必须继续**。
 */
describe("useMetricsHistory：一次失败不能停掉轮询（复扫 G2）", () => {
  it("拉取失败后标记不可达，并且继续安排下一次采样", async () => {
    let calls = 0;
    vi.stubGlobal("fetch", async () => {
      calls += 1;
      throw new Error("metrics 超时");
    });

    vi.useFakeTimers();
    const { result } = renderHook(() => useMetricsHistory(1000));
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

  it("恢复后 reachable 回到 true，快照与原始文本都重新累积", async () => {
    let failing = true;
    vi.stubGlobal("fetch", async () => {
      if (failing) throw new Error("挂死");
      return new Response(METRICS_TEXT);
    });

    vi.useFakeTimers();
    const { result } = renderHook(() => useMetricsHistory(1000));
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
