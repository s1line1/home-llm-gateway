// Agents 页渲染测试：钉住 P3-18① —— "拿不到明细（404）" 与 "零个在线 agent" 是**两种**状态。
//
// 修复前：`detailUnavailable = isError && message.includes("404")`，而 `fetchAgents` 把 404 折成
// `null` 返回（不进 `isError`）⇒ 那段永远为假 ⇒ 404 被显示成"暂无在线 agent"，把"未知"说成"零"。

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AgentInfo } from "../api/types";

const mocks = vi.hoisted(() => ({ fetchAgents: vi.fn() }));

// `fetchAgents` 的契约：404 → `null`（`api/client.ts:112`）。这里只替掉网络层，保留页面逻辑。
vi.mock("../api/client", () => ({ fetchAgents: mocks.fetchAgents }));

vi.mock("../hooks/useMetricsHistory", () => ({
  useMetricsHistory: () => ({
    latest: null,
    history: [],
    raw: null,
    error: null,
    reachable: true,
  }),
}));

import Agents from "./Agents";

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <Agents />
    </QueryClientProvider>,
  );
}

const oneAgent: AgentInfo = {
  agent_id: "agent-1",
  models: ["mock-llm"],
  max_concurrency: 4,
  inflight: 1,
  last_seen_secs_ago: 2,
  healthy: true,
};

describe("Agents 页的明细降级（P3-18①）", () => {
  beforeEach(() => {
    localStorage.setItem("hlmg.admin.token", "t");
    mocks.fetchAgents.mockReset();
  });

  it("404（fetchAgents 返回 null）显示『返回 404』而不是『暂无在线 agent』", async () => {
    mocks.fetchAgents.mockResolvedValue(null);
    renderPage();

    expect(await screen.findByText(/返回 404/)).toBeDefined();
    expect(screen.queryByText("暂无在线 agent")).toBeNull();
    // 顶栏副标题也要说"未取到明细"，而不是假装有数据
    expect(screen.getByText(/未取到 \/admin\/agents 明细/)).toBeDefined();
  });

  it("明细为空数组（真的零个 agent）才显示『暂无在线 agent』", async () => {
    mocks.fetchAgents.mockResolvedValue([]);
    renderPage();

    expect(await screen.findByText("暂无在线 agent")).toBeDefined();
    expect(screen.queryByText(/返回 404/)).toBeNull();
    expect(screen.getByText(/来自 \/admin\/agents/)).toBeDefined();
  });

  it("拿到明细时渲染表格（防止降级分支把正常路径吃掉）", async () => {
    mocks.fetchAgents.mockResolvedValue([oneAgent]);
    renderPage();

    expect(await screen.findByText("agent-1")).toBeDefined();
    expect(screen.getByText("mock-llm")).toBeDefined();
    expect(screen.queryByText(/返回 404/)).toBeNull();

    // **渲染级**守卫（复扫 G5）：`//` 注释写到 JSX 子节点位置时会**原样渲染**成文本，而
    // `tsc` / `vite build` 都不报错。原先只有 Overview 的测试有这条断言，而产物守卫只认
    // `P<n>-<n>` 审计标记 ⇒ 不带编号的 `//` 泄漏在别的页面上没人拦。
    const text = document.body.textContent ?? "";
    expect(text).not.toContain("//");
  });
});

describe("Agents 页的状态判定来自网关（复扫 G1）", () => {
  beforeEach(() => {
    localStorage.setItem("hlmg.admin.token", "t");
    mocks.fetchAgents.mockReset();
  });

  it("网关说 healthy 就是在线 —— 哪怕 last_seen 看起来很旧", async () => {
    // 复扫 G1：原先前端拿写死的 15s 去比 `last_seen_secs_ago`，于是把网关按更大的
    // `agent_stale_secs`（比如 60s）判为健康的 agent 显示成"失联"，与同一页顶部的在线数矛盾。
    mocks.fetchAgents.mockResolvedValue([{ ...oneAgent, last_seen_secs_ago: 20, healthy: true }]);
    renderPage();

    expect(await screen.findByText("agent-1")).toBeDefined();
    expect(screen.getByText("在线")).toBeDefined();
    expect(screen.queryByText("失联")).toBeNull();
  });

  it("网关说 not healthy 就是失联 —— 哪怕 last_seen 只有几秒", async () => {
    mocks.fetchAgents.mockResolvedValue([{ ...oneAgent, last_seen_secs_ago: 2, healthy: false }]);
    renderPage();

    expect(await screen.findByText("agent-1")).toBeDefined();
    expect(screen.getByText("失联")).toBeDefined();
    expect(screen.queryByText("在线")).toBeNull();
  });
});
