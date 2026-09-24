// P3-18③ 的接线测试：401 ⇒ 清 admin token ⇒ `RequireAuth` 把用户送回登录页。
//
// 修复前：`RequireAuth` 只看"token 存不存在"，token 失效后用户卡在"已登录但每个页面都加载失败"。
// 这里不测 `handleUnauthorized` 自己（那是纯函数），而是**真的**跑一遍 query/mutation 的
// react-query 缓存回调 + 真实路由守卫，把"接线"钉住。

import { QueryClientProvider, useMutation, useQuery } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";

import RequireAuth from "../components/RequireAuth";
import { ApiError } from "./client";
import { createQueryClient } from "./queryClient";

const TOKEN_KEY = "hlmg.admin.token";

function FailingQuery({ status }: { status: number }) {
  const query = useQuery({
    queryKey: ["probe", status],
    queryFn: async () => {
      throw new ApiError(status, `HTTP ${status}`);
    },
    retry: false,
  });
  return <div>{query.isError ? "加载失败" : "加载中"}</div>;
}

function FailingMutation({ status }: { status: number }) {
  const mutation = useMutation({
    mutationFn: async () => {
      throw new ApiError(status, `HTTP ${status}`);
    },
  });
  return <button onClick={() => mutation.mutate()}>写一次</button>;
}

/** 真实的 `RequireAuth` + 真实的 QueryClient，只把"哪个组件发请求"换掉。 */
function renderWithGuard(node: ReactNode) {
  return render(
    <QueryClientProvider client={createQueryClient()}>
      <MemoryRouter initialEntries={["/"]}>
        <Routes>
          <Route path="/login" element={<div>登录页</div>} />
          <Route element={<RequireAuth />}>
            <Route index element={node} />
          </Route>
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("401 的全局处理（P3-18③）", () => {
  afterEach(() => localStorage.clear());

  it("query 拿到 401 ⇒ token 被清掉并跳到登录页", async () => {
    localStorage.setItem(TOKEN_KEY, "stale");
    renderWithGuard(<FailingQuery status={401} />);

    expect(await screen.findByText("登录页")).toBeDefined();
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });

  it("mutation 拿到 401 也一样（两条缓存回调都要接）", async () => {
    localStorage.setItem(TOKEN_KEY, "stale");
    renderWithGuard(<FailingMutation status={401} />);

    fireEvent.click(await screen.findByRole("button", { name: "写一次" }));

    expect(await screen.findByText("登录页")).toBeDefined();
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });

  it("500 不该把人踢下线（否则一次网关抖动就丢登录态）", async () => {
    localStorage.setItem(TOKEN_KEY, "keep-me");
    renderWithGuard(<FailingQuery status={500} />);

    expect(await screen.findByText("加载失败")).toBeDefined();
    expect(localStorage.getItem(TOKEN_KEY)).toBe("keep-me");
    expect(screen.queryByText("登录页")).toBeNull();
  });
});
