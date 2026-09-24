import { defineConfig } from "vitest/config";

// 测试配置独立成文件（而不是并进 `vite.config.ts`）：那份配置会在导入时读 `../Cargo.toml`
// 拿版本号，测试不需要那个副作用。这里显式给一个版本常量，免得 `Layout.tsx` 之类的组件在
// 测试环境下因为 `__GATEWAY_VERSION__` 未定义而炸。
export default defineConfig({
  define: { __GATEWAY_VERSION__: JSON.stringify("0.0.0-test") },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    globals: true,
  },
});
