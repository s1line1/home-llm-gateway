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
      return new Response("ok");
    });
    await expect(fetchMetricsText()).resolves.toBe("ok");
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

  it("HTTP 错误仍然带状态码（超时没有把普通失败吞掉）", async () => {
    vi.stubGlobal("fetch", async () => new Response("nope", { status: 503 }));
    await expect(fetchMetricsText()).rejects.toThrow(/metrics: HTTP 503/);
  });
});
