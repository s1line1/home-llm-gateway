// Admin token 管理：保存在 localStorage，供 /admin/* 调用使用。

import { useCallback, useSyncExternalStore } from "react";

const STORAGE_KEY = "hlmg.admin.token";

/**
 * 清除 admin token（非 hook 版）。给 react-query 的全局 401 处理用：任何 `/admin/*` 拿到 401
 * 都说明 token 已失效（被轮换/吊销/写错），必须清掉并让 `RequireAuth` 把用户送回登录页，
 * 否则用户会卡在"已登录但每个页面都加载失败"（P3-18）。
 */
export function clearAdminToken(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // localStorage 不可用：本来也没存住
  }
  // 同页手动派发：`useSyncExternalStore` 靠它重新读取（storage 事件本身只在跨标签页时触发）
  window.dispatchEvent(new Event("storage"));
}

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
