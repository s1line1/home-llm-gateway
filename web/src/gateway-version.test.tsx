// P3-20① 的两半：构建时注入的版本号必须来自 `Cargo.toml` 的 `[workspace.package].version`
// （唯一来源），而 `Layout` 必须**渲染那个注入值**、不许再写死。
//
// 修复前：`Layout.tsx` 里写死 "网关版本 0.1.0"，而网关早已 0.1.1 —— 构建/类型检查都不会报错。

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import viteConfig from "../vite.config";
import Layout from "./components/Layout";

vi.mock("./hooks/useMetricsHistory", () => ({
  useMetricsHistory: () => ({
    latest: null,
    history: [],
    raw: null,
    error: null,
    reachable: false,
  }),
}));

/**
 * 独立解析（**不复用** `vite.config.ts` 的正则）：按行找 `[workspace.package]` 段里的 `version`。
 * 两处实现不同 ⇒ 这条能抓出"正则匹配到了别的 `version =`"这类错误。
 */
function workspaceVersionFromCargoToml(): string {
  // vitest 的 root 是 `web/`（配置所在目录），所以工作区 Cargo.toml 在上一级。
  const toml = readFileSync(resolve(process.cwd(), "..", "Cargo.toml"), "utf8");
  const lines = toml.split(/\r?\n/);
  const start = lines.findIndex((line) => line.trim() === "[workspace.package]");
  if (start < 0) throw new Error("Cargo.toml 里找不到 [workspace.package] 段");
  for (const line of lines.slice(start + 1)) {
    if (line.startsWith("[")) break; // 段结束
    const matched = /^version\s*=\s*"([^"]+)"/.exec(line.trim());
    if (matched) return matched[1];
  }
  throw new Error("[workspace.package] 段里没有 version");
}

describe("网关版本号的单一来源（P3-20①）", () => {
  it("vite 注入的 __GATEWAY_VERSION__ 就是 Cargo.toml 的 workspace 版本", () => {
    const injected = JSON.parse(String(viteConfig.define!.__GATEWAY_VERSION__));
    const expected = workspaceVersionFromCargoToml();

    expect(expected).toMatch(/^\d+\.\d+\.\d+/); // 解析器本身要对
    expect(injected).toBe(expected);
    // 测试环境用的是 `vitest.config.ts` 里另一个常量；别把那个当成真版本
    expect(injected).not.toBe("0.0.0-test");
  });

  it("Layout 渲染的是注入值，不是写死的字面量", () => {
    render(
      <MemoryRouter>
        <Layout />
      </MemoryRouter>,
    );

    // `vitest.config.ts` 把 __GATEWAY_VERSION__ 定义成 "0.0.0-test"：写死任何别的版本号都会红
    expect(screen.getByText(/网关版本 0\.0\.0-test/)).toBeDefined();
  });
});
