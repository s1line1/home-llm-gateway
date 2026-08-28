// Admin token 管理：保存在 localStorage，供 /admin/* 调用使用。

import { useCallback, useSyncExternalStore } from "react";

const STORAGE_KEY = "hlmg.admin.token";

function readToken(): string {
  try {
    return localStorage.getItem(STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

function subscribe(cb: () => void): () => void {
  window.addEventListener("storage", cb);
  return () => window.removeEventListener("storage", cb);
}

/** 当前 admin token（跨标签页同步）。 */
export function useAdminToken(): string {
  return useSyncExternalStore(subscribe, readToken, readToken);
}

/** 保存/清除 admin token。 */
export function useSetAdminToken(): (token: string) => void {
  return useCallback((token: string) => {
    const trimmed = token.trim();
    try {
      if (trimmed) localStorage.setItem(STORAGE_KEY, trimmed);
      else localStorage.removeItem(STORAGE_KEY);
    } catch {
      // localStorage 不可用时仅内存态，静默降级
    }
    // 同页手动派发事件，useSyncExternalStore 会重新读取
    window.dispatchEvent(new Event("storage"));
  }, []);
}
