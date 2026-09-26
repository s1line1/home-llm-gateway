import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { clearAdminToken, useAdminToken, useSetAdminToken } from "./useAdminToken";

/**
 * 与 hook 内部同一个键。它是**浏览器存储的契约**（跨标签页同步、用户手动排查都靠它），
 * 所以这里写死一份并钉住：改名等于让所有已登录用户的 token 失效一次。
 */
const STORAGE_KEY = "hlmg.admin.token";

afterEach(() => {
  vi.restoreAllMocks();
  window.localStorage.clear();
});

/** 让 localStorage 全部抛错：Safari 无痕 / 禁用站点数据 / 配额满都是这个形态。 */
function breakLocalStorage(): void {
  for (const method of ["getItem", "setItem", "removeItem"] as const) {
    vi.spyOn(Storage.prototype, method).mockImplementation(() => {
      throw new Error("localStorage is not available");
    });
  }
}

/**
 * 复扫 G6：localStorage 不可用时**必须真的降级到内存态**。
 *
 * 修好前 `catch` 里那句"仅内存态，静默降级"是假的：token 只写 localStorage，写失败就被丢掉，
 * 而 `readToken` 异常时返回 `""` ⇒ Login 校验通过、`navigate` 之后 `RequireAuth` 立刻判未登录
 * 弹回登录页，用户看不到任何错误。下面第一条就是这条端到端性质的判据（hook 层的"登录后仍是
 * 未登录"）。
 */
describe("useAdminToken：localStorage 不可用时的内存降级（复扫 G6）", () => {
  it("写不进 localStorage 时 token 仍留在内存里（登录后不会被弹回登录页）", () => {
    breakLocalStorage();
    const { result } = renderHook(() => ({
      token: useAdminToken(),
      save: useSetAdminToken(),
    }));
    expect(result.current.token).toBe("");

    act(() => {
      result.current.save("  sk-admin  ");
    });
    expect(result.current.token).toBe("sk-admin");

    // 登出同样要生效（否则用户点"退出"也退不掉）
    act(() => {
      clearAdminToken();
    });
    expect(result.current.token).toBe("");
  });

  it("localStorage 可用时以它为准，随别的标签页登录一起变", () => {
    const { result } = renderHook(() => useAdminToken());
    expect(result.current).toBe("");

    act(() => {
      window.localStorage.setItem(STORAGE_KEY, "from-another-tab");
      window.dispatchEvent(new Event("storage"));
    });
    expect(result.current).toBe("from-another-tab");

    act(() => {
      window.localStorage.removeItem(STORAGE_KEY);
      window.dispatchEvent(new Event("storage"));
    });
    expect(result.current).toBe("");
  });

  it("写存储失败后以内存态为准，不被存储里的旧值盖回去", () => {
    window.localStorage.setItem(STORAGE_KEY, "stale");
    const { result } = renderHook(() => ({
      token: useAdminToken(),
      save: useSetAdminToken(),
    }));
    expect(result.current.token).toBe("stale");

    // 之后配额满：只有写会抛（读仍然可用，返回的是旧值）
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("quota exceeded");
    });
    act(() => {
      result.current.save("fresh");
    });
    expect(result.current.token).toBe("fresh");
  });
});
