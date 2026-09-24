// react-query 全局配置：把所有 `/admin/*` 的 401 统一收成"登录态失效"。
//
// 单独成模块（而不是留在 `main.tsx`）是为了可测：`main.tsx` 在模块顶层就 `createRoot(...).render(...)`，
// 测试没法只导入那个函数而不把整个应用挂起来。这里只导出配置工厂，401 的接线因此能被真实渲染测试钉住
// （`queryClient.test.tsx`）。

import { MutationCache, QueryCache, QueryClient } from "@tanstack/react-query";

import { ApiError } from "./client";
import { clearAdminToken } from "../hooks/useAdminToken";

/**
 * 任何请求拿到 401 ⇒ 手上的 admin token 已失效（轮换/吊销/写错）。清掉它，`RequireAuth`
 * 会把用户送回登录页；没有这一步，用户会看到一屏"加载失败"却仍然停留在已登录状态（P3-18）。
 *
 * 只认 `ApiError` 且 `status === 401`：网络错误、5xx、形状校验失败都不该把人踢下线。
 */
export function handleUnauthorized(error: unknown): void {
  if (error instanceof ApiError && error.status === 401) {
    clearAdminToken();
  }
}

/** 应用用的 QueryClient：query 与 mutation 两条路径共用同一个 401 处理。 */
export function createQueryClient(): QueryClient {
  return new QueryClient({
    queryCache: new QueryCache({ onError: handleUnauthorized }),
    mutationCache: new MutationCache({ onError: handleUnauthorized }),
    defaultOptions: {
      queries: {
        staleTime: 5000,
        retry: 1,
        refetchOnWindowFocus: false,
      },
    },
  });
}
