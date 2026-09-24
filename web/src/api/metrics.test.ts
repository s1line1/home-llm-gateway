import { describe, expect, it } from "vitest";

import { parseMetrics } from "./metrics";

describe("parseMetrics", () => {
  it("分开解析『已注册』与『可路由』两个 agent 数（P3-19）", () => {
    // `hlmg_agents` 的 HELP 明说含心跳过期者，`hlmg_agents_healthy` 才是可路由数 ——
    // 界面上一度把前者当"在线"，这条把两个字段钉住。
    const snap = parseMetrics(
      ["hlmg_agents 3", "hlmg_agents_healthy 1", "hlmg_active_requests 2"].join("\n"),
    );
    expect(snap.agents).toBe(3);
    expect(snap.agents_healthy).toBe(1);
    expect(snap.active_requests).toBe(2);
  });

  it("缺字段回退 0，并按状态码聚合请求数", () => {
    const snap = parseMetrics(
      ['hlmg_requests_total{status="200"} 7', 'hlmg_requests_total{status="429"} 2'].join("\n"),
    );
    expect(snap.requests_by_status[200]).toBe(7);
    expect(snap.requests_by_status[429]).toBe(2);
    expect(snap.agents_healthy).toBe(0);
  });
});
