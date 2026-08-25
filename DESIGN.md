# 家庭 LLM 远程访问网关 — 架构设计（QUIC 隧道）

> 目标：家里本地部署大模型，云服务器作为公网中转站，用户在任何地点、任何时间通过 OpenAI 兼容 API 访问家庭模型服务。
> 实现语言：Rust。隧道协议：**QUIC**。

---

## 1. 需求与目标

- **家庭侧**：一台常开的机器跑 LLM 推理服务（Ollama / vLLM / llama.cpp，均提供 OpenAI 兼容 `/v1/*` 接口），位于 NAT 之后，无公网 IP 或 IP 动态变化。
- **云端侧**：一台有公网 IP 的服务器，作为唯一对外入口。
- **客户端**：任何地方的笔记本 / 手机 / 其他程序，只认识云端地址。
- **非目标**：不追求多租户计费、模型市场等完整 AI Gateway 能力；核心是"远程访问自家模型"的专用网关。

## 2. 总体架构

```
客户端（任何地方）
   │  HTTPS + OpenAI 兼容 API（含 SSE 流式）
   ▼
┌──────────────────────────┐
│  cloud-gateway（公网）     │  axum 公网入口
│  · API Key 认证 / 限流     │  认证 → 路由 → 编码为隧道帧
│  · Agent 路由 / 健康管理   │
│  · QUIC Server（隧道端）   │
└──────────┬───────────────┘
           │ QUIC（UDP 443，mTLS，一条连接多路复用）
           │ ← 边缘端主动拨出的长连接，云端永不主动连对端
           ▼
┌──────────────────────────┐
│  edge-agent（家里）        │  常驻进程
│  · QUIC Client（拨号/心跳）│  解码帧 → 转发本地 LLM
│  · 本地 LLM 转发/进程管理  │  流式回传 + 取消传播
└──────────┬───────────────┘
           │ HTTP（127.0.0.1，OpenAI 兼容）
           ▼
       本地 LLM 服务
   （Ollama / vLLM / llama.cpp）
```

**核心原则**：家里主动向外拨 QUIC 长连接。云端只通过这条已建立的连接转发请求，因此：
- 无需家里有公网 IP / 端口映射 / DDNS；
- NAT 打洞问题被彻底绕开（连接是出站的，绝大多数 NAT 都允许）；
- 云端可以精确知道家里 agent 的存活状态。

## 3. 为什么用 QUIC（相对 TCP+TLS）

| 能力 | 对本场景的价值 |
|---|---|
| **多路复用、无队头阻塞** | 一条隧道并发承载多个请求流。LLM 的 SSE 响应是"慢流"，TCP 上一个大响应会阻塞后续请求；QUIC 每个流独立 |
| **连接迁移（Connection ID）** | 边缘端 agent 网络切换（WiFi ↔ 蜂窝、IP 变化）时连接不中断，无需重连 |
| **0-RTT / 快速重连** | 断线重连开销小，心跳丢失后恢复快 |
| **内建 TLS 1.3 + mTLS** | 隧道加密和双向认证开箱即用，无需自己拼 TLS-over-TCP 栈 |
| **Rust 生态成熟** | `quinn` 是生产级实现（Tokio 官方维护），API 稳定 |

风险点：QUIC 走 **UDP**。极少数家庭路由器/运营商可能封锁出站 UDP，届时需要 fallback（见 §10）。

## 4. 隧道协议设计

### 4.1 传输层

- `quinn` 建立 QUIC 连接（UDP 443）。
- **双向认证（mTLS）**：云端自建 CA，为每个 edge-agent 签发客户端证书；云端只接受持有有效证书的连接。防止任何人伪装成"边缘端 agent"接走流量。
- 一个 QUIC 连接承载 N 个双向 **stream**；每个隧道帧独占一个 stream 发送（stream 天然有序、流式，天然适配"一个请求一条流"）。

### 4.2 帧协议（自定义轻量二进制帧，bincode/postcard 序列化）

相比直接套 HTTP/3（`h3` crate），自定义帧更简单可控、省去 HTTP 语义开销；若后续想省维护量可切换到 `h3`（见 §10 备选）。

```
帧 = [ frame_type: u8 ][ request_id: u64 ][ payload: ... ]
```

| 帧类型 | 方向 | 用途 |
|---|---|---|
| `Register` | agent → cloud | 上报 agent_id、模型能力列表、并发上限、版本 |
| `Heartbeat` | 双向 | 保活 + 健康状态（存活、当前并发、队列深度、最近延迟） |
| `ProxyRequest` | cloud → agent | `{ request_id, method, path, headers, body }`，对应一个 OpenAI 兼容请求 |
| `ProxyResponseHead` | agent → cloud | `{ request_id, status, headers }`（转发上游响应头，如 `content-type: text/event-stream`） |
| `ProxyResponseBody` | agent → cloud | `{ request_id, chunk }`，body 分块流式传输（SSE chunk 直接透传） |
| `ProxyResponseEnd` | agent → cloud | `{ request_id, ok }`，流结束 |
| `Cancel` | cloud → agent | 客户端断开/超时，通知 agent 取消上游请求（**防止家里白算 token**） |
| `Error` | 双向 | 错误码 + 描述 |

### 4.3 流式转发语义

- 客户端发起 `GET/POST /v1/chat/completions`（SSE）→ 云端编码为 `ProxyRequest` 沿 QUIC stream 发出；
- agent 收到后转发给本地 LLM，把上游响应逐块编码为 `ProxyResponseHead` + 若干 `ProxyResponseBody` 回传；
- 云端收到 body 帧后**原样透传**给客户端（`chunked` / `text/event-stream`），不做 buffering；
- 任一端关闭：客户端断开 → 云端发 `Cancel` → agent 取消上游 reqwest 请求；agent 崩溃 → 云端对客户端返回 502 并清理。

### 4.4 多路复用与并发控制

- 每个活跃请求占一个 QUIC stream，天然并行；
- agent 上报 `并发上限`（由本地 GPU/内存决定），云端按该上限做 admission control，超限直接回 429。

## 5. 云端（cloud-gateway）设计

**技术栈**：`axum` + `hyper` + `tower` + `quinn` + `clap` + `tracing` + `serde`

职责：
1. **公网 HTTP(S) 入口**：监听 443（TLS），暴露 OpenAI 兼容路径 `/v1/models`、`/v1/chat/completions`、`/v1/embeddings` 等，一律透传给隧道内的 agent。
2. **认证**：Bearer API Key（恒定时间比较，防时序侧信道）；可选 IP 白名单。
3. **限流**：token bucket 按 Key 限流；按 agent 并发上限 admission control（429）。
4. **Agent 路由**：维护 agent 注册表（agent_id → 当前 QUIC 连接 + 健康状态）；多 agent 时按"最少并发"或"轮询"选择；无健康 agent 时返回 503。
5. **QUIC Server**：接受边缘端连接，校验 mTLS 证书，处理 Register/Heartbeat，更新注册表，踢掉同一 agent_id 的旧连接（防重复拨号）。
6. **请求转发**：HTTP → `ProxyRequest` 帧 → 等 `ProxyResponse*` 帧流式回写；超时（空闲超时 + 总超时）→ `Cancel`。
7. **可观测性**：`tracing` 结构化日志 + `metrics`（请求数、延迟、token 量、在线 agent 数）。

## 6. 边缘端（edge-agent）设计

**技术栈**：`quinn` + `reqwest` + `tokio` + `clap` + `tracing` + `serde`

职责：
1. **拨号与保活**：启动即连接云端，指数退避 + 抖动重连（0.5s → 1s → … → 上限 60s）；每 N 秒发 `Heartbeat`。
2. **mTLS**：持有云端 CA 签发的客户端证书。
3. **请求处理**：收到 `ProxyRequest` → 映射为对本地 LLM 的 HTTP 请求（如 `http://127.0.0.1:11434/v1/chat/completions`）→ 流式回传；收到 `Cancel` → 取消上游请求（reqwest 的 `AbortHandle`）。
4. **本地 LLM 管理（可选但推荐）**：进程守护——启动、健康检查（`/v1/models`）、崩溃自动重启。
5. **本地直连模式（可选）**：同网段时客户端也可直连 agent（跳过云端），agent 兼开一个小型 HTTP 入口。

## 7. 安全清单

| 面 | 措施 |
|---|---|
| 公网入口 | 强制 TLS 1.3；API Key 认证；限流；请求大小上限；审计日志（来源 IP、Key、路径、耗时、token 估算） |
| 隧道 | QUIC 内建 TLS 1.3 + mTLS（云端 CA 签发 agent 证书）；连接级空闲超时；证书轮换 |
| 数据 | 全链路加密；日志脱敏（不记录 prompt 内容，或可配置） |
| 密钥 | API Key 用 `argon2` 派生后存储校验；agent 私钥只存家里 |

## 8. 部署形态

- **云端**：编译为单二进制，`systemd` 或 Docker 运行；证书由自家 CA 签发脚本管理。
- **家里**：单二进制，支持 Linux / macOS / Windows / WSL2（家里机器可能什么系统都有）。
- **配置**：网关侧 `config.yml`、边缘端 `config.yml`（均 YAML，模板见 `gateway_config.example.yml` 与 `crates/agent/config.example.yml`）。
- **开机自启**：边缘端注册为 systemd/launchd 服务。

## 9. 里程碑

- **M1 最小链路** ✅：cloud-gateway 公网 HTTP + QUIC server；edge-agent 拨号 + mTLS + 心跳；非流式请求转发。
- **M2 流式** ✅：SSE 透传（agent 逐块转发、网关流式回写）+ `Cancel` 传播（客户端断开/超时即取消上游）。
- **M3 加固** ✅：公网 HTTPS（rustls 原生，无需反代）、按 API Key 令牌桶限流、按 agent `max_concurrency` 的 admission control。
- **M4 完善** ✅：多 agent 最少负载路由（在途最少者优先，原子占位）、`/metrics` Prometheus 指标、`--version`、多平台打包脚本（`scripts/build-release.sh`）与 systemd 单元（`deploy/`）。待办：健康上报驱动的更精细路由、Grafana 仪表盘模板。

## 10. 风险与备选方案

1. **UDP 被封锁**：极少数家庭网络封出站 UDP。备选：隧道降级为 TCP+TLS 并复用同一套帧协议（帧层不变，只换传输层），或提示用户放行 UDP 443。
2. **quinn API 学习成本**：备选直接上 HTTP/3（`h3` crate），用标准 HTTP 语义替代自定义帧，代价是少一点控制力、多一层依赖。
3. **帧协议 bug 排查成本**：协议保持最小集（上表 8 种帧），先做对再做优化；用 `postcard` 保证序列化简单可调试。
4. **家里断网/断电**：云端靠心跳超时自动摘除 agent，客户端得到 503 而非悬挂；agent 恢复后自动重连，无需人工干预。
5. **云服务器被攻击面**：公网入口只暴露认证后的转发能力，不暴露任何管理接口；管理走 SSH。

## 11. 演进路线（多用户 / 大团队 / 高并发）

> 目标：从"个人/小团队网关"演进到"多租户、可水平扩展"的服务。核心判断：**代理链路（QUIC 隧道、帧协议、每请求一流、Cancel 传播）设计无需改动**，改造集中在**网关的状态管理**与**外围服务**。
>
> 注意：LLM 网关的"高并发"不是传统 QPS，而是**并发长连接流 + 慢响应 + 内存占用**；优化重点在连接/流/状态，不在请求吞吐。

### 11.1 现状瓶颈

| 现状 | 限制 |
|---|---|
| agent 注册表在进程内存 | 多实例无法共享在线状态 |
| 令牌桶限流在内存 | 多实例各自计数，限流失效 |
| 单进程承载 HTTP+QUIC+Admin | 无法水平扩展 |
| SQLite 单文件持久化 | 写锁竞争，高并发 key 管理吃力 |
| key 校验 O(n) 遍历 | key 数万级后变慢 |
| 无租户概念 | 所有 key 权限相同，无法隔离/配额/计量 |

### 11.2 阶段 1：单实例优化（小团队，几十并发）

- key 校验改为"先哈希定位、再恒定时间比较"，避免全表遍历
- SQLite 写操作（create/revoke）挪到 `spawn_blocking`，不阻塞 async runtime
- QUIC 流上限调优：`max_concurrent_bidi_streams` 默认 100，高并发流场景上调
- 慢上游排队：agent 满时先排队（带超时）而非直接 429
- SSE 流式转发增加内存缓冲上限，防慢客户端拖垮

### 11.3 阶段 2：多租户（大团队核心需求）

- **租户模型**：API key 增加 `tenant_id`、`permissions`（模型白名单）、`expires_at`、`quota`
- **两级限流**：按 key + 按租户（租户级总配额）
- **用量计量**：从上游 `usage` 字段统计 **token 消耗**（当前只统计 bytes），按租户记量
- **审计**：日志/请求带 tenant_id，支持"谁用了多少"查询
- **管理面升级**：现有 Admin API/管理页扩展为租户管理、key 生命周期、用量报表

### 11.4 阶段 3：水平扩展（高并发）

**核心动作 = 网关无状态化**（把进程内存状态外置）：

| 状态 | 从内存移到 |
|---|---|
| agent 注册表（在线/心跳） | Redis（agent 心跳写 Redis，多实例共享） |
| 限流令牌桶 | Redis（Lua 脚本原子操作） |
| key 校验 | 本地缓存 + 失效机制（pub/sub 或短 TTL） |
| 持久化 | SQLite → PostgreSQL（多写者、并发事务） |

- 多实例 + LB：HTTP 入口挂 SLB/nginx；QUIC 侧 agent 支持配置多个网关地址（发现/故障转移）或随机拨入集群
- 审计/用量异步化：事件写 MQ，不阻塞主链路

### 11.5 阶段 4：架构级（产品化）

- **拆分原则**：单体 + 无状态化优先，别一上来微服务；真拆也按 api-gateway / tunnel-manager / auth / admin 四块演进
- **模型路由升级**：模型感知路由（按 model 名选 agent）+ 容量感知（agent 上报负载/延迟）+ 失败重试到其他 agent
- **安全**：TLS 证书自动轮换、Admin 面 SSO/OIDC、key 加密存储（KMS）
- **计费/配额**：token 计量 → 租户配额 → 超额策略

### 11.6 优先级（按投入产出）

```
第 1 步：多租户 + 认证/限流外置 Redis   ← 解决"大团队"最痛的隔离和配额
第 2 步：无状态化 + 多实例 + LB          ← 解决水平扩展
第 3 步：SQLite → PostgreSQL            ← 解决持久化并发
第 4 步：模型路由升级（感知/重试）        ← 提升利用率
第 5 步：服务拆分 + 审计/计费            ← 产品化收尾
```

### 11.7 无需改动的部分

- ✅ 帧协议、QUIC 隧道、每请求一流——设计本来就是对的
- ✅ Cancel/超时传播语义
- ✅ agent 侧转发逻辑——瓶颈在网关状态管理，不在 agent
- ⚠️ 大规模下瓶颈会转移到**上游 LLM 集群**（每实例并发有限）→ 届时需要模型池、排队调度、容量管理，而非网关自身

---

## 附：工作区规划（后续实现）

```
home-llm-gateway/
├── Cargo.toml            # workspace
├── DESIGN.md             # 本文档
├── crates/
│   ├── gateway/          # cloud-gateway 二进制（axum + quinn server）
│   ├── agent/            # edge-agent 二进制（quinn client + reqwest）
│   └── proto/            # 共享 crate：帧类型、序列化、错误码
│       └── tests/        # 帧编解码 roundtrip 测试
└── certs/                # 自建 CA 与签发脚本（脚本而非仓库内私钥）
```
