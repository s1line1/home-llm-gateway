import { afterEach, describe, expect, it, vi } from "vitest";

import { fetchAgents, listKeys } from "./client";

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
