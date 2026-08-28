// API Keys 管理页：admin token 登录 → 创建 / 列表 / 吊销 / 复制明文。

import { useCallback, useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { createKey, deleteKey, listKeys } from "../api/client";
import type { CreatedKey } from "../api/types";
import { useAdminToken, useSetAdminToken } from "../hooks/useAdminToken";
import { Button, Card, EmptyState } from "../components/ui";

const TOKEN_INPUT_ID = "admin-token-input";

function TokenGate({ onAuthed }: { onAuthed: () => void }) {
  const token = useAdminToken();
  const setToken = useSetAdminToken();
  const [draft, setDraft] = useState(token);

  useEffect(() => {
    if (token) onAuthed();
  }, [token, onAuthed]);

  return (
    <Card title="管理员登录" subtitle="输入启动网关时配置的 admin_token（保存在本浏览器 localStorage）">
      <div className="flex max-w-md gap-2">
        <input
          id={TOKEN_INPUT_ID}
          type="password"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="Admin Token"
          className="flex-1 rounded-lg border border-slate-300 px-3 py-1.5 text-sm focus:border-slate-500 focus:outline-none"
          autoComplete="current-password"
        />
        <Button onClick={() => setToken(draft)} disabled={!draft.trim()}>
          保存并加载
        </Button>
      </div>
      <p className="mt-3 text-xs text-slate-500">
        令牌仅用于调用 <code className="rounded bg-slate-100 px-1">/admin/*</code> 接口；可随时在左下角清除。
      </p>
    </Card>
  );
}

export default function Keys() {
  const token = useAdminToken();
  const setToken = useSetAdminToken();
  const queryClient = useQueryClient();

  const [authed, setAuthed] = useState(!!token);
  const [name, setName] = useState("");
  const [created, setCreated] = useState<CreatedKey | null>(null);

  const keysQuery = useQuery({
    queryKey: ["admin", "keys"],
    queryFn: () => listKeys(token),
    enabled: authed && !!token,
    refetchInterval: 10_000,
  });

  const createMutation = useMutation({
    mutationFn: (keyName: string) => createKey(token, keyName),
    onSuccess: (rec) => {
      setCreated(rec);
      setName("");
      void queryClient.invalidateQueries({ queryKey: ["admin", "keys"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteKey(token, id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["admin", "keys"] }),
  });

  const onAuthed = useCallback(() => setAuthed(true), []);

  const copy = useCallback(async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // 明文 HTTP 部署下 clipboard API 不可用 → 降级提示手动复制
      window.prompt("复制 API Key（剪贴板不可用，请手动复制）：", text);
    }
  }, []);

  if (!authed || !token) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-lg font-semibold">API Keys 管理</h2>
          <p className="text-sm text-slate-500">运行时签发 / 吊销访问 <code>/v1/*</code> 的 API Key</p>
        </div>
        <TokenGate onAuthed={onAuthed} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">API Keys 管理</h2>
          <p className="text-sm text-slate-500">
            所有 Key 持久化在网关 SQLite，仅存 argon2 哈希；明文只在创建时返回一次
          </p>
        </div>
        <Button variant="ghost" onClick={() => { setToken(""); setAuthed(false); }}>
          清除登录
        </Button>
      </div>

      <Card title="创建新 Key" subtitle="为每个客户端（DSH / Codex / 脚本）单独创建">
        <form
          className="flex max-w-md gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (name.trim()) createMutation.mutate(name.trim());
          }}
        >
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={64}
            placeholder="用途，如 dsh-client"
            className="flex-1 rounded-lg border border-slate-300 px-3 py-1.5 text-sm focus:border-slate-500 focus:outline-none"
          />
          <Button type="submit" disabled={!name.trim() || createMutation.isPending}>
            {createMutation.isPending ? "创建中…" : "创建 Key"}
          </Button>
        </form>
        {createMutation.isError && (
          <p className="mt-2 text-xs text-rose-600">{createMutation.error.message}</p>
        )}
        {created && (
          <div className="mt-3 rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm">
            <p className="font-medium text-emerald-800">创建成功——明文仅显示这一次：</p>
            <div className="mt-1.5 flex items-center gap-2">
              <code className="flex-1 break-all rounded bg-white px-2 py-1 font-mono text-xs">{created.key}</code>
              <Button variant="secondary" onClick={() => void copy(created.key)}>
                复制
              </Button>
            </div>
          </div>
        )}
      </Card>

      <Card title="已有 Keys" subtitle="吊销立即生效，不可恢复">
        {keysQuery.isPending ? (
          <EmptyState text="加载中…" />
        ) : keysQuery.isError ? (
          <EmptyState text={`加载失败：${keysQuery.error.message}`} />
        ) : keysQuery.data.length === 0 ? (
          <EmptyState text="暂无动态 Key，先在上方创建一个" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-100 text-xs text-slate-500">
                  <th className="pb-2 pr-4 font-medium">名称</th>
                  <th className="pb-2 pr-4 font-medium">ID</th>
                  <th className="pb-2 pr-4 font-medium">前缀</th>
                  <th className="pb-2 pr-4 font-medium">创建时间</th>
                  <th className="pb-2 pr-4 font-medium">状态</th>
                  <th className="pb-2 font-medium" />
                </tr>
              </thead>
              <tbody>
                {keysQuery.data.map((k) => (
                  <tr key={k.id} className="border-b border-slate-50 last:border-0">
                    <td className="py-2.5 pr-4 font-medium text-slate-800">{k.name}</td>
                    <td className="py-2.5 pr-4 font-mono text-xs text-slate-500">{k.id}</td>
                    <td className="py-2.5 pr-4 font-mono text-xs text-slate-500">{k.prefix}</td>
                    <td className="py-2.5 pr-4 text-slate-600">
                      {new Date(k.created_at * 1000).toLocaleString()}
                    </td>
                    <td className="py-2.5 pr-4">
                      <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${k.enabled ? "bg-emerald-50 text-emerald-700" : "bg-slate-100 text-slate-500"}`}>
                        {k.enabled ? "启用" : "禁用"}
                      </span>
                    </td>
                    <td className="py-2.5 text-right">
                      <Button
                        variant="danger"
                        disabled={deleteMutation.isPending}
                        onClick={() => {
                          if (confirm(`吊销 Key「${k.name}」（${k.id}）？立即生效，不可恢复。`)) {
                            deleteMutation.mutate(k.id);
                          }
                        }}
                      >
                        吊销
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
