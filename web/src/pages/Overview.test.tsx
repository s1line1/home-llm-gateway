import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { MetricsSnapshot } from "../api/types";
import Overview from "./Overview";

// 把轮询 hook 换成固定快照：本文件只关心**渲染出来的文字**。
const snapshot: MetricsSnapshot = {
  fetched_at: 0,
  requests_by_status: { 200: 5 },
  active_requests: 2,
  agents: 3,
  agents_healthy: 1,
  bytes_out: 1024,
  request_duration_ms: 10,
  request_count: 5,
};

vi.mock("../hooks/useMetricsHistory", () => ({
  useMetricsHistory: () => ({
    latest: snapshot,
    history: [snapshot],
    raw: null,
    error: null,
    reachable: true,
  }),
}));

describe("总览页", () => {
  it("把『可路由』那个数当在线数用（P3-19），且不把源码文字漏到页面上", () => {
    render(<Overview />);

    expect(screen.getByText("在线 Agents")).toBeDefined();
    // `hlmg_agents=3`（含心跳过期）与 `hlmg_agents_healthy=1`（可路由）刻意取不同值：
    // 页面上该出现的是后者。
    expect(screen.getByText("1")).toBeDefined();
    expect(screen.getByText(/已注册 3/)).toBeDefined();

    // **渲染级**守卫：源码里的审计标记（`P3-19` 这类）或 `//` 注释一旦被当成文本渲染出来
    // （JSX 子节点位置的 `//` 就是这种情况），这里会红 —— 而 `tsc`/`vite build` 都不会报错。
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/(SL-)?P\d+-\d+/);
    expect(text).not.toContain("//");
    // 正文快照：任何**新增的**渲染文字（无论是不是泄漏）都会让这条红，需要人眼确认一次。
    expect(text).toMatchSnapshot();
  });
});
