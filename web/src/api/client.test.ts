import { afterEach, describe, expect, it, vi } from "vitest";

import { fetchAgents, fetchMetricsText, listKeys } from "./client";

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("JSON 边界的形状校验（P3-20）", () => {
  it("期望数组却收到对象时给可读错误，而不是让 data.map 炸掉", async () => {
    vi.stubGlobal("fetch", async () => jsonResponse({ not: "an array" }));
    await expect(listKeys("t")).rejects.toThrow(/GET \/admin\/keys: 期望数组，收到 object/);
  });

  it("形状正确时原样返回", async () => {
    vi.stubGlobal("fetch", async () => jsonResponse([{ id: "k1" }]));
    await expect(listKeys("t")).resolves.toEqual([{ id: "k1" }]);
  });

  it("404 折成 null（旧版网关/未挂载 admin），不是抛错", async () => {
    vi.stubGlobal("fetch", async () => jsonResponse({ error: { message: "not found" } }, 404));
    await expect(fetchAgents("t")).resolves.toBeNull();
  });
});

describe("/metrics 取数超时（复扫 G2）", () => {
  it("把 signal 交给 fetch —— 没有它，超时根本不会发生", async () => {
    let seen: AbortSignal | null | undefined;
    vi.stubGlobal("fetch", async (_url: string, init?: RequestInit) => {
      seen = init?.signal;
      // 复扫 G3 之后 `fetchMetricsText` 会校验正文确实是指标文本，所以桩不能再返回 "ok"。
      return new Response("hlmg_agents 1");
    });
    await expect(fetchMetricsText()).resolves.toBe("hlmg_agents 1");
    expect(seen).toBeInstanceOf(AbortSignal);
  });

  it("网关接了连接却不回包时，超时变成可捕获的错误，而不是永远挂着", async () => {
    // 永不 settle 的 fetch：只有 signal 被 abort 时才 reject。
    vi.stubGlobal(
      "fetch",
      (_url: string, init?: RequestInit) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () =>
            reject(new DOMException("The operation timed out", "TimeoutError")),
          );
        }),
    );
    // 用一个很小的超时值走这条路径，不必等默认的 10 秒。
    await expect(fetchMetricsText(20)).rejects.toThrow(/timed out/i);
  });

  it("200 但正文是 HTML → 抛错，绝不把 SPA 页面当成指标（复扫 G3）", async () => {
    // 网关在同一个 `/metrics` URL 上按 `Accept` 也回 SPA 页面（A5）；缓存按 URI 张冠李戴时
    // Dashboard 的 fetch 就会拿到它。原先的解析器把 HTML 解析成"全 0"并在界面上当真实数据。
    // 正文里**故意放一行像样本的行**：这样"靠正文形状兜底"那条守卫不会替内容类型守卫背锅
    // （HTML 里恰好出现一行 `name value` 时，只有内容类型能拦下来）。
    vi.stubGlobal(
      "fetch",
      async () =>
        new Response('<!doctype html>\n<div id="root">ui</div>\nhlmg_agents 3\n', {
          status: 200,
          headers: { "content-type": "text/html; charset=utf-8" },
        }),
    );
    await expect(fetchMetricsText()).rejects.toThrow(/HTML/);
  });

  it("200 但正文一行样本都解析不出来 → 抛错（不是全 0）", async () => {
    vi.stubGlobal("fetch", async () => new Response("not metrics at all"));
    await expect(fetchMetricsText()).rejects.toThrow(/Prometheus/);
  });

  it("对照：真正的指标文本照常返回", async () => {
    vi.stubGlobal("fetch", async () => new Response("hlmg_agents 2\nhlmg_agents_healthy 1"));
    await expect(fetchMetricsText()).resolves.toContain("hlmg_agents 2");
  });

  it("HTTP 错误仍然带状态码（超时没有把普通失败吞掉）", async () => {
    vi.stubGlobal("fetch", async () => new Response("nope", { status: 503 }));
    await expect(fetchMetricsText()).rejects.toThrow(/metrics: HTTP 503/);
  });
});
