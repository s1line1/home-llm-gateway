import { QueryClientProvider } from "@tanstack/react-query";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";

import { createQueryClient } from "./api/queryClient";
import Layout from "./components/Layout";
import RequireAuth from "./components/RequireAuth";
import { MetricsHistoryProvider } from "./hooks/useMetricsHistory";
import Agents from "./pages/Agents";
import Keys from "./pages/Keys";
import Login from "./pages/Login";
import MetricsPage from "./pages/MetricsPage";
import Overview from "./pages/Overview";
import "./index.css";

// 401 处理与默认选项在 `api/queryClient.ts`（那里可被测试直接构造）。
const queryClient = createQueryClient();

createRoot(document.getElementById("root")!).render(
  <QueryClientProvider client={queryClient}>
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<RequireAuth />}>
          {/*
            已登录的壳上挂**唯一**的 `/metrics` 轮询（复扫 G4）：侧边栏（`Layout`）与当前页面
            （Overview / MetricsPage / Agents）共享同一份历史，不再各自开一条、各采各的
            （采样时刻不同步时两处数字会对不上）。放在 `RequireAuth` 里面，所以登录页不拉。
          */}
          <Route
            element={
              <MetricsHistoryProvider>
                <Layout />
              </MetricsHistoryProvider>
            }
          >
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
