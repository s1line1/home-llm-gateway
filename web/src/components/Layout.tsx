// 应用布局：左侧导航 + 顶栏（网关健康状态）+ 内容区。

import { NavLink, Outlet, useNavigate } from "react-router-dom";

import { useAdminToken, useSetAdminToken } from "../hooks/useAdminToken";
import { useMetricsHistory } from "../hooks/useMetricsHistory";
import { StatusPill } from "./ui";

const NAV = [
  { to: "/", label: "总览", end: true },
  { to: "/keys", label: "API Keys" },
  { to: "/agents", label: "Agents" },
  { to: "/metrics", label: "指标" },
];

function navClass({ isActive }: { isActive: boolean }): string {
  return [
    "block rounded-lg px-3 py-2 text-sm font-medium transition-colors",
    isActive ? "bg-slate-800 text-white" : "text-slate-300 hover:bg-slate-800/50 hover:text-white",
  ].join(" ");
}

export default function Layout() {
  const { latest, reachable, error } = useMetricsHistory();
  const token = useAdminToken();
  const clearToken = useSetAdminToken();
  const navigate = useNavigate();

  const logout = () => {
    clearToken("");
    navigate("/login", { replace: true });
  };

  return (
    <div className="flex min-h-screen">
      <aside className="flex w-52 shrink-0 flex-col bg-slate-900">
        <div className="px-4 py-5">
          <h1 className="text-base font-semibold text-white">Edge LLM Gateway</h1>
          <p className="mt-0.5 text-xs text-slate-400">Edge LLM 网关</p>
        </div>
        <nav className="flex-1 space-y-1 px-2">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end} className={navClass}>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="space-y-1 px-4 py-4">
          <div className="text-[11px] leading-relaxed text-slate-500">
            网关版本 0.1.0 · QUIC 隧道 + mTLS
          </div>
          {token && (
            <button
              onClick={logout}
              className="block w-full rounded-lg px-3 py-1.5 text-left text-xs font-medium text-slate-400 transition-colors hover:bg-slate-800 hover:text-white"
            >
              退出登录
            </button>
          )}
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-slate-200 bg-white px-6 py-3">
          <div className="text-sm text-slate-500">
            公网入口{" "}
            <span className="font-mono text-slate-700">/v1/*（OpenAI 兼容）</span>
          </div>
          <div className="flex items-center gap-3">
            {error && <span className="text-xs text-amber-600" title={error}>数据拉取异常</span>}
            <StatusPill
              ok={reachable && latest !== null}
              label={reachable && latest !== null ? `网关在线 · ${latest.agents} agents` : "网关不可达"}
            />
          </div>
        </header>
        <main className="min-w-0 flex-1 overflow-x-hidden p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
