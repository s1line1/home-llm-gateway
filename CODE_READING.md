# home-llm-gateway 代码阅读指南

> 面向新接手者/回顾者的阅读路线。核心原则：**先懂"一条请求的全过程"，
> 再补"治理逻辑"，最后看"验证与部署"**。每层配了验证式学习法（动手确认认知）。

---

## 整体架构速览

```
客户端（任何地方）
   │  HTTPS + OpenAI 兼容 API（含 SSE 流式）
   ▼
cloud-gateway（公网）    axum 入口：认证 → 限流 → 路由 → 隧道帧
   │  QUIC（UDP，mTLS，一条连接多路复用）
   ▼
edge-agent（LLM 所在机器）  主动拨号 + 心跳 + 断线重连
   │  HTTP
   ▼
本地 LLM（Ollama / vLLM / llama.cpp / mock-llm）
```

**三个关键心智模型**（贯穿所有代码）：

1. **一条 QUIC 连接 + 每请求一条流**：连接常驻（agent 拨号），流 = 一次请求，用完即关
2. **request_id 贯穿两端**：gateway 与 agent 日志靠它对齐，排查链路问题
3. **Cancel 传播防白算 token**：客户端断开/超时 → Cancel 帧 → agent 取消上游

---

## 阅读路线

### 第 0 步：文档建立全局（30 分钟）

| 顺序 | 读什么 | 要得到的认知 |
|---|---|---|
| 1 | `README.md` | 项目定位、特性、快速开始、配置命名约定（gateway-config.yml / agent-config.yml） |
| 2 | `DESIGN.md` | 架构图、为什么 QUIC、8 种帧、安全模型、演进路线（多租户/水平扩展） |
| 3 | `OPTIMIZATION.md` | 模块划分现状（哪些已拆、哪些暂缓，如 C3 零拷贝） |

### 第 1 步：协议层（一切的基础，30 分钟）

```
crates/proto/src/frame.rs    8 种帧类型（Register/Heartbeat/ProxyRequest/Head/Body/End/Cancel/Error）
crates/proto/src/io.rs       帧读写：长度前缀 [u32 大端] + postcard 序列化
crates/proto/src/pem.rs      证书加载（gateway/agent 共享）
crates/proto/src/headers.rs  逐跳头过滤（gateway/agent 共享）
```

> 验证：`cargo bench -p proto` 看帧编解码性能基线。

### 第 2 步：请求主链路（核心中的核心，1-2 小时）

**跟着一条 SSE 请求走完全程**，按此顺序：

```
① gateway/src/main.rs → lib.rs
   配置加载（config.rs）→ Gateway::start 组装（HTTP + QUIC + keystore + registry + 优雅关闭）
② gateway/src/http.rs
   路由、中间件、SPA fallback（/v1/* 怎么进到 proxy）
③ gateway/src/http_proxy.rs            ★ 最重要
   认证 → 限流 → 最少负载选 agent → open_bi 开流 → 发 ProxyRequest → 流式回写
④ gateway/src/quic.rs
   服务端：accept_loop、Register / Heartbeat 控制流
⑤ agent/src/main.rs → lib.rs          ★ 另一端
   拨号 → 注册 → accept_bi → handle_stream（转发上游 + Cancel 传播）
```

**关键问题自测**：
- 一条 SSE 流，`request_id` 怎么贯穿两端？
- 客户端断开后，Cancel 帧怎么传播？谁负责取消上游请求（不白算 token）？
- agent 的 `select!` 竞速（上游响应 vs Cancel）为什么是必要的？

### 第 3 步：支撑模块（治理逻辑，1 小时）

```
gateway/src/registry.rs    agent 注册表 + SlotGuard 并发占位（admission control）
gateway/src/keystore/       SQLite 存储 + argon2 哈希 + sha256 lookup 快速索引
gateway/src/admin.rs        Admin API（key 管理 + agents 列表）
gateway/src/ratelimit.rs    令牌桶
gateway/src/metrics.rs      Prometheus 指标（HTTP 层 + 隧道层）
gateway/src/tls.rs          mTLS 配置（动态信任根方向见 TODO P1 多 CA 方案）
```

### 第 4 步：测试与验证（1 小时）

```
crates/gateway/tests/e2e/   13 个 e2e 场景（common.rs 怎么起全栈；chain.rs 全链路；
                            agents.rs 并发正确性；admin.rs 管理 API；metrics.rs 指标）
crates/gateway/benches/     Criterion 微基准（帧编解码 + keystore argon2）
scripts/bench-k6/           k6 宏观压测模板（SSE 长流 + QPS，含 429 分类断言）
```

> 验证：`make check`（fmt + clippy + test + web build）全绿。

### 第 5 步：部署与运维（30 分钟）

```
Makefile                 dev/stop/check 一键流程 + 证书检查（certs-required）
DEPLOY.md                生产部署：证书签发、systemd、安全组（UDP 4433 易漏）
deploy/*.service         优雅关闭怎么生效（systemctl stop → SIGTERM → shutdown）
rust-toolchain.toml      工具链锁定（stable + rustfmt/clippy）
```

### 第 6 步：前端（可选，30 分钟）

```
web/src/api/          ← 先看契约（client.ts + types.ts + metrics.ts）
web/src/pages/        ← 四个页面（数据从哪来：/metrics 轮询、/admin/*）
web/src/components/   ← 布局/图表/UI（无依赖 SVG 图表）
```

---

## 锚点文件（最值得精读的几个）

| 文件 | 为什么先读它 |
|---|---|
| `crates/gateway/src/http_proxy.rs` | 全链路的心脏（认证 → 路由 → 隧道） |
| `crates/gateway/src/registry.rs` 的 `try_acquire` | 并发控制精髓（SlotGuard RAII 自动归还） |
| `crates/agent/src/lib.rs` 的 `handle_stream` | 转发 + Cancel 的 `select!` 竞速 |
| `crates/proto/src/frame.rs` | 两端通信的契约 |
| `crates/gateway/tests/e2e/common.rs` | 怎么在单进程内拉起完整测试栈 |

---

## 验证式学习法（每层读完动手确认）

1. **读完链路** → `make dev` + curl 发请求，看 **gateway 和 agent 双端日志**
   （`request_id` 对齐：received → responded → done）
2. **读完 registry** → `cargo test -p gateway --lib registry` 看并发占位测试
3. **读完 keystore** → Admin API 创建/吊销 key，`sqlite3 keys.db` 确认只存 argon2 哈希
4. **压测一次** → `make bench-k6 KEY=sk-xxx`（或 oha），观察 admission control 的 429
5. **读完优雅关闭** → 起 gateway，`kill -TERM`，看 `received SIGTERM → graceful shutdown` 日志

---

## 常用命令速查

```bash
make dev          # 一键起全栈（mock-llm + gateway + agent，日志在 .tmp/logs/）
make stop         # 停全栈
make check        # fmt + clippy + test + web build（CI 同等门槛）
make bench        # Criterion 微基准
make bench-k6     # k6 宏观压测（KEY=sk-xxx 必传）
cargo llvm-cov --workspace --summary-only   # 覆盖率（当前 95.87%）
```

## 排查链路问题的标准动作

1. 看两端日志：`tail -f .tmp/logs/gateway.log .tmp/logs/agent.log`（或 journalctl）
2. 按 `request_id` 对齐两端：gateway "request handled" ↔ agent "received/done"
3. 看指标：`curl :8080/metrics`（hlmg_agents / quic_connections / 状态码分布）
4. 常见区分：**429 = admission 拒绝**（agent max_concurrency 上限，设计行为）；
   **503 = 无健康 agent**；**5xx = 网关/上游真故障**
