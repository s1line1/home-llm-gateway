// Admin token 管理：保存在 localStorage，供 /admin/* 调用使用。

import { useCallback, useSyncExternalStore } from "react";

const STORAGE_KEY = "hlmg.admin.token";

/**
 * localStorage **写失败**时的内存兜底（复扫 G6）。`null` = "本页没有覆盖值，以 localStorage 为准"。
 *
 * 修好前两处 `catch` 里写的是"仅内存态，静默降级"，但**根本不存在内存态**：token 只往
 * localStorage 里写，而 `readToken` 在异常时返回 `""`。于是 localStorage 不可用时（Safari 无痕、
 * 禁用站点数据、配额满）Login 校验通过 → `navigate` → `RequireAuth` 立刻读到 `""` 判未登录 →
 * 弹回登录页，**用户看不到任何错误**，也不知道是浏览器不让存。
 */
let memoryToken: string | null = null;

function readToken(): string {
  // 本页写过、而那次没写进 localStorage ⇒ 内存态就是真相（存储里可能是旧值或空）
  if (memoryToken !== null) return memoryToken;
  try {
    return localStorage.getItem(STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

/** 把 token 写进（或从）localStorage；返回 `false` 表示这个环境用不了它。 */
function writeStored(token: string): boolean {
  try {
    if (token) localStorage.setItem(STORAGE_KEY, token);
    else localStorage.removeItem(STORAGE_KEY);
    return true;
  } catch {
    return false;
  }
}

/**
 * 清除 admin token（非 hook 版）。给 react-query 的全局 401 处理用：任何 `/admin/*` 拿到 401
 * 都说明 token 已失效（被轮换/吊销/写错），必须清掉并让 `RequireAuth` 把用户送回登录页，
 * 否则用户会卡在"已登录但每个页面都加载失败"（P3-18）。
 */
export function clearAdminToken(): void {
  writeStored("");
  // 内存态一律交还给 localStorage：存储不可用时 `readToken` 本来就会落到 `""`（= 已登出），
  // 而留一个空串覆盖值会让本页**再也跟不上**别的标签页的登录（storage 事件被它挡住）。
  memoryToken = null;
  // 同页手动派发：`useSyncExternalStore` 靠它重新读取（storage 事件本身只在跨标签页时触发）
  window.dispatchEvent(new Event("storage"));
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
    // 写失败时**内存态接手**——这就是注释里那句"静默降级"的实现（复扫 G6）
    memoryToken = writeStored(trimmed) ? null : trimmed;
    // 同页手动派发事件，useSyncExternalStore 会重新读取
    window.dispatchEvent(new Event("storage"));
  }, []);
}
