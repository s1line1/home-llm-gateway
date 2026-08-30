// 登录页：输入 admin_token，调用 /admin/keys 校验有效性，通过后进入 Dashboard。

import { useState } from "react";
import type { FormEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import { listKeys } from "../api/client";
import { useSetAdminToken } from "../hooks/useAdminToken";

export default function Login() {
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const saveToken = useSetAdminToken();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from ?? "/";

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const trimmed = token.trim();
    if (!trimmed) return;
    setLoading(true);
    setError(null);
    try {
      // 用管理接口校验 token：200 = 有效，401 = 无效
      await listKeys(trimmed);
      saveToken(trimmed);
      navigate(from, { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "登录失败，请检查 admin_token");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-100 px-4">
      <div className="w-full max-w-sm rounded-2xl border border-slate-200 bg-white p-8 shadow-sm">
        <div className="mb-6">
          <h1 className="text-lg font-semibold text-slate-900">Home LLM Gateway</h1>
          <p className="mt-1 text-sm text-slate-500">管理面板 · 管理员登录</p>
        </div>

        <form onSubmit={submit} className="space-y-4">
          <div>
            <label htmlFor="admin-token" className="mb-1 block text-sm font-medium text-slate-700">
              Admin Token
            </label>
            <input
              id="admin-token"
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="启动网关时配置的 admin_token"
              autoComplete="current-password"
              autoFocus
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-slate-500 focus:outline-none"
            />
          </div>

          {error && (
            <p className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-xs text-rose-700">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={!token.trim() || loading}
            className="w-full rounded-lg bg-slate-900 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? "验证中…" : "登录"}
          </button>
        </form>

        <p className="mt-6 text-xs leading-relaxed text-slate-400">
          token 保存在本浏览器（localStorage），仅用于调用 /admin/* 管理接口；
          部署时在 gateway-config.yml 中配置，可用 <code className="rounded bg-slate-100 px-1">openssl rand -hex 32</code> 生成。
        </p>
      </div>
    </div>
  );
}
