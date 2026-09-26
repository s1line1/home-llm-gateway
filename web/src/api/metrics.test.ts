import { describe, expect, it } from "vitest";

import { looksLikePrometheus, parseMetrics } from "./metrics";

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

describe("looksLikePrometheus（复扫 G3）", () => {
  it("有一行样本就算指标文本", () => {
    expect(looksLikePrometheus("hlmg_agents 3")).toBe(true);
    expect(looksLikePrometheus("# HELP x y\nhlmg_agents 0")).toBe(true);
  });

  it("HTML / 空文本 / 只有注释 —— 都不是", () => {
    expect(looksLikePrometheus('<!doctype html><div id="root">ui</div>')).toBe(false);
    expect(looksLikePrometheus("")).toBe(false);
    expect(looksLikePrometheus("# 只有注释\n# TYPE hlmg_agents gauge")).toBe(false);
    expect(looksLikePrometheus("not metrics at all")).toBe(false);
  });
});
