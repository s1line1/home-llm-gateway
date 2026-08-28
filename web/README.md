# home-llm-gateway Web UI

cloud-gateway 的 React 管理界面（TypeScript + React 19 + Vite + Tailwind CSS v4），
覆盖 API Key 管理、agent 在线状态、Prometheus 指标可视化。

## 功能

- **总览**：网关健康、在线 agent 数、在途请求、累计请求/转发字节、状态码分布、趋势图
- **API Keys**：admin token 登录（localStorage）→ 创建（明文仅一次展示）/ 列表 / 吊销 / 复制
- **Agents**：在线 agent 明细（`/admin/agents`，契约预留；当前网关未实现时降级为仅显示总数）
- **指标**：每 5 秒轮询 `/metrics`，最近 60 个采样点的趋势图 + 状态码分布 + 原始文本查看

## 开发

```bash
pnpm install
pnpm dev          # http://localhost:5173，/admin、/metrics、/healthz、/v1 代理到 127.0.0.1:8080
```

网关不在本机时用环境变量覆盖代理目标：

```bash
GATEWAY_PROXY=http://<网关地址>:8080 pnpm dev
```

## 构建

```bash
pnpm build        # 产物在 dist/
pnpm preview      # 本地预览构建产物
```

## 部署：网关托管（推荐）

gateway 从 0.1.0 起内置静态托管：配置 `ui_dir`（默认 `web/dist`，相对工作目录）
指向构建产物目录后，**启动 gateway 即自带 Dashboard**——浏览器打开网关地址 `/`
就是本 UI，前端路由（`/keys` 等）自动 fallback，单进程、单端口：

```bash
# 1. 构建前端
cd web && pnpm install && pnpm build

# 2. 启动网关（项目根目录，默认 ui_dir=web/dist 自动生效）
cd .. && gateway --config gateway-config.yml

# 或显式配置（gateway_config.example.yml）
# ui_dir: web/dist
```

`ui_dir` 目录不存在时 `/` 显示构建提示页（网关不再内嵌管理页）。
改了前端后只需重新 `pnpm build`（不必重编译 Rust）；也可以开发时直接用 `pnpm dev`
+Vite 代理，两者可并行。

## 与网关的 API 契约

| 端点 | 用途 | 状态 |
|---|---|---|
| `GET /healthz` | 存活探针 | ✅ 已实现 |
| `GET /metrics` | Prometheus 指标（前端解析 `hlmg_*` 系列） | ✅ 已实现 |
| `POST /admin/keys` | 创建 key（返回明文一次） | ✅ 已实现 |
| `GET /admin/keys` | 列出 key（脱敏） | ✅ 已实现 |
| `DELETE /admin/keys/{id}` | 吊销 key | ✅ 已实现 |
| `GET /admin/agents` | agent 明细（`agent_id/models/max_concurrency/inflight/last_seen_secs_ago`） | ⏳ 契约预留，网关侧待实现 |

`GET /admin/agents` 实现后，Agents 页自动从"仅显示总数"切换为明细表格，
无需改动前端（可加在 `crates/gateway/src/admin.rs`，数据在 `registry.rs` 中已有）。
