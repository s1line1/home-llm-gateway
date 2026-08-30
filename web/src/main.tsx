import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";

import Layout from "./components/Layout";
import RequireAuth from "./components/RequireAuth";
import Agents from "./pages/Agents";
import Keys from "./pages/Keys";
import Login from "./pages/Login";
import MetricsPage from "./pages/MetricsPage";
import Overview from "./pages/Overview";
import "./index.css";

const queryClient = new QueryClient({
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
