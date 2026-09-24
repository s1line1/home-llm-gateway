// Keys 页渲染测试：钉住 P3-18② —— 吊销失败必须**说出来**，并且说清"这条 Key 仍然有效"。
//
// 修复前：`deleteMutation` 只有成功回调，失败时 UI 上什么都没有——用户以为已经吊销，
// 而 key 其实还在用（P1-4 的网关侧语义就是"落库失败 ⇒ key 仍有效"）。

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ApiKey } from "../api/types";

const mocks = vi.hoisted(() => ({
  listKeys: vi.fn(),
  createKey: vi.fn(),
  deleteKey: vi.fn(),
}));

vi.mock("../api/client", () => ({
  listKeys: mocks.listKeys,
  createKey: mocks.createKey,
  deleteKey: mocks.deleteKey,
}));

import Keys from "./Keys";

const key: ApiKey = {
  id: "k1",
  name: "dsh-client",
  created_at: 0,
  enabled: true,
  prefix: "sk-abc",
  usage: {
    prompt_tokens: 0,
    completion_tokens: 0,
    total_tokens: 0,
    requests: 0,
    estimated_requests: 0,
    last_used_at: 0,
  },
};

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <Keys />
    </QueryClientProvider>,
  );
}

describe("Keys 页的吊销失败提示（P3-18②）", () => {
  beforeEach(() => {
    localStorage.setItem("hlmg.admin.token", "t");
    mocks.listKeys.mockReset();
    mocks.deleteKey.mockReset();
    mocks.createKey.mockReset();
    mocks.listKeys.mockResolvedValue([key]);
    // 吊销前有 `confirm` 二次确认（`Keys.tsx:175`）：jsdom 没实现它，不换掉的话它返回 undefined ⇒ 不吊销
    vi.spyOn(window, "confirm").mockReturnValue(true);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("deleteKey 失败时显示『吊销失败：…（这条 Key 仍然有效）』", async () => {
    mocks.deleteKey.mockRejectedValue(new Error("SQLite 错误: forced rollback"));
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: "吊销" }));

    expect(
      await screen.findByText(/吊销失败：SQLite 错误: forced rollback（这条 Key 仍然有效）/),
    ).toBeDefined();
    // mutate 的 mutationFn 是异步派发的：上面那条 findByText 已经等到了结果，这里再确认参数
    expect(mocks.deleteKey).toHaveBeenCalledWith("t", "k1");
  });

  it("deleteKey 成功时不显示失败提示", async () => {
    mocks.deleteKey.mockResolvedValue(undefined);
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: "吊销" }));

    // 等一次列表重取（invalidate）落地，确认这段时间没有冒失败文案
    await waitFor(() => expect(mocks.listKeys.mock.calls.length).toBeGreaterThan(1));
    expect(mocks.deleteKey).toHaveBeenCalledWith("t", "k1");
    expect(screen.queryByText(/吊销失败/)).toBeNull();
  });
});
