import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// 版本只有一个来源：工作区 `Cargo.toml` 的 `[workspace.package].version`。以前界面把
// "网关版本 0.1.0" 写死在 `Layout.tsx` 里，而网关早已 0.1.1 —— 这种漂移只能靠"只留一个来源"
// 根治（P3-20）。构建时注入，运行时零成本。
const here = dirname(fileURLToPath(import.meta.url));
const workspaceVersion = (() => {
  const toml = readFileSync(resolve(here, "../Cargo.toml"), "utf8");
  const version = /\[workspace\.package\][\s\S]*?\nversion = "([^"]+)"/.exec(toml)?.[1];
  if (!version) {
    throw new Error("cannot read [workspace.package].version from ../Cargo.toml");
  }
  return version;
})();

// 开发环境代理目标：本地网关（cloud-gateway）。可用环境变量覆盖：
//   GATEWAY_PROXY=http://<服务器>:8080 pnpm dev
// 生产构建产物为纯静态文件，通过网关静态托管或任意静态服务器访问。
const gatewayTarget = process.env.GATEWAY_PROXY ?? "http://127.0.0.1:8080";

export default defineConfig({
  define: { __GATEWAY_VERSION__: JSON.stringify(workspaceVersion) },
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      // 网关公开端点全部代理到 cloud-gateway
      "/healthz": gatewayTarget,
      "/metrics": gatewayTarget,
      "/admin": gatewayTarget,
      "/v1": gatewayTarget,
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
