import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// 开发环境代理目标：本地网关（cloud-gateway）。可用环境变量覆盖：
//   GATEWAY_PROXY=http://<服务器>:8080 pnpm dev
// 生产构建产物为纯静态文件，通过网关静态托管或任意静态服务器访问。
const gatewayTarget = process.env.GATEWAY_PROXY ?? "http://127.0.0.1:8080";

export default defineConfig({
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
