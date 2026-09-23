import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";

import { ApiError } from "./api/client";
import Layout from "./components/Layout";
import RequireAuth from "./components/RequireAuth";
import Agents from "./pages/Agents";
import Keys from "./pages/Keys";
import Login from "./pages/Login";
import MetricsPage from "./pages/MetricsPage";
import Overview from "./pages/Overview";
import { clearAdminToken } from "./hooks/useAdminToken";
import "./index.css";

/**
 * 任何请求拿到 401 ⇒ 手上的 admin token 已失效（轮换/吊销/写错）。清掉它，`RequireAuth`
 * 会把用户送回登录页；没有这一步，用户会看到一屏"加载失败"却仍然停留在已登录状态（P3-18）。
 */
function handleUnauthorized(error: unknown) {
  if (error instanceof ApiError && error.status === 401) {
    clearAdminToken();
  }
}

const queryClient = new QueryClient({
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

createRoot(document.getElementById("root")!).render(
  <QueryClientProvider client={queryClient}>
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<RequireAuth />}>
          <Route element={<Layout />}>
            <Route index element={<Overview />} />
            <Route path="/keys" element={<Keys />} />
            <Route path="/agents" element={<Agents />} />
            <Route path="/metrics" element={<MetricsPage />} />
          </Route>
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  </QueryClientProvider>,
);
