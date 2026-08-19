<p align="center"><b>中文</b> | <a href="README.en.md">English</a></p>

# home-llm-gateway

**家里本地部署大模型，云服务器做公网中转，在任何地点通过 OpenAI 兼容 API 访问家庭模型服务。**

Rust 实现，零外部依赖组件（不依赖 frp/ngrok/nginx）。隧道协议 **QUIC**，**mTLS 双向认证**，SSE 流式透传，支持多 agent 负载均衡。

```
客户端（任何地方）
   │  HTTPS + OpenAI 兼容 API（含 SSE 流式）
   ▼
cloud-gateway（公网）      axum 入口：API Key 认证 → 限流 → 路由 → 隧道帧
   │  QUIC（UDP，mTLS，一条连接多路复用，无队头阻塞）
   ▼
home-agent（LLM 所在机器）  主动拨号 + 心跳 + 断线重连，转发本地 LLM
   │  HTTP
   ▼
本地 LLM（Ollama / vLLM / llama.cpp / mock-llm）
```

## 特性

- **QUIC 隧道 + mTLS**：家端主动向外拨长连接，天然穿透 NAT / 动态 IP；双向证书认证，未注册 agent 无法接入
- **流式优先**：SSE 逐块透传（打字机效果）；客户端断开/超时自动 `Cancel` 上游，不白算 token；逐帧空闲超时，不误杀长流
- **公网 HTTPS 原生支持**：rustls 直接监听 443，无需 nginx/caddy
- **安全与治理**：API Key 认证（恒定时间比较）、按 Key 令牌桶限流、按 agent 并发上限的 admission control（超限 429）
- **多 agent 最少负载路由**：多台 LLM 机器自动均衡，失联 agent 自动摘除
- **可观测性**：`/metrics` Prometheus 指标、结构化请求日志（`request_id` / 状态码 / 耗时）、`/healthz` 探针
- **多平台部署**：单静态二进制（Linux / macOS），交叉编译脚本 + systemd 单元

## 目录结构

```
crates/
├── proto/      隧道帧协议（Register/Heartbeat/ProxyRequest/Response*/Cancel/Error）
├── gateway/    cloud-gateway 二进制（axum + quinn server）
├── agent/      home-agent 二进制（quinn client + reqwest）
└── mock-llm/   模拟 OpenAI 兼容接口的假 LLM（无真实模型时打通链路用）
certs/          证书生成脚本（开发用）
deploy/         systemd 单元（gateway.service / agent.service）
scripts/        多平台 release 打包脚本
```

## 快速开始（全部本机即可跑通，无需真实 LLM）

### 环境

- Rust stable（建议 1.75+）
- `openssl` 命令行（仅证书脚本需要）

### 1. 生成证书

```bash
certs/gen-dev.sh        # 输出到 certs/out/（CA + 服务端 + 客户端）
```

### 2. 起 mock LLM（模拟家里的大模型服务）

```bash
cargo run -p mock-llm -- --addr 127.0.0.1:11435
```

### 3. 起 home-agent（家里那台机器）

```bash
cargo run -p agent -- \
  --cloud-addr 127.0.0.1:4433 \
  --ca certs/out/ca.crt \
  --cert certs/out/client.crt \
  --key certs/out/client.key \
  --agent-id home-1 \
  --upstream http://127.0.0.1:11435
```

### 4. 起 cloud-gateway（云服务器）

```bash
cargo run -p gateway -- \
  --listen-addr 0.0.0.0:8080 \
  --quic-addr 0.0.0.0:4433 \
  --cert certs/out/server.crt \
  --key certs/out/server.key \
  --ca certs/out/ca.crt \
  --api-keys dev-key
```

### 5. 从"任何地方"访问

```bash
curl -H "Authorization: Bearer dev-key" http://127.0.0.1:8080/v1/models
curl -H "Authorization: Bearer dev-key" \
  http://127.0.0.1:8080/v1/chat/completions \
  -d '{"model":"mock-llm","messages":[{"role":"user","content":"你好"}]}'
```

看到 mock 回显即代表整条链路（HTTP → 认证 → QUIC 隧道 → agent → 上游）已打通。

**SSE 流式**（接真实模型后就是打字机效果）：

```bash
curl -N -H "Authorization: Bearer dev-key" \
  http://127.0.0.1:8080/v1/chat/completions \
  -d '{"model":"mock-llm","stream":true,"messages":[{"role":"user","content":"你好"}]}'
```

### 6. 测试

```bash
cargo test    # proto roundtrip + 端到端集成测试（内存生成证书，无需任何外部服务）
```

## 接入真实 LLM

把 agent 的 `--upstream` 指向真实服务即可，其余不变：

| 本地服务 | 命令 |
|---|---|
| Ollama | `--upstream http://127.0.0.1:11434` |
| vLLM | `--upstream http://127.0.0.1:8000` |
| llama.cpp server | `--upstream http://127.0.0.1:8080` |

## 生产部署（阿里云 / 公网）

1. **中转网关放公网服务器**：安全组/防火墙放行 **UDP 4433**（QUIC 隧道）与 **TCP 8443**（HTTPS API）。网关自带 HTTPS，无需反代——QUIC 隧道是私有帧协议，反代本来也代理不了。日后若需域名 + 证书自动续期可加 caddy（nginx 需 `proxy_buffering off`，否则破坏 SSE 流式）。
2. **agent 放 LLM 所在机器**：`--cloud-addr <公网IP>:4433`，`--server-name` 填证书 SAN 中的域名（推荐域名 + DNS SAN 证书，避免 IP 变更）。
3. **mTLS 是关键安全线**：CA 私钥自己保管，每个 agent 单独签发客户端证书。
4. **UDP 注意**：QUIC 走 UDP，若被封需要放行；极端情况可降级 TCP+TLS（帧协议不变，见 `DESIGN.md` §10）。

### 启用 HTTPS + 限流

```bash
cargo run -p gateway -- \
  --listen-addr 0.0.0.0:8443 \
  --quic-addr 0.0.0.0:4433 \
  --cert certs/out/server.crt --key certs/out/server.key \
  --ca certs/out/ca.crt \
  --api-keys dev-key \
  --tls-cert certs/out/server.crt --tls-key certs/out/server.key \
  --rate-limit-per-min 60        # 每个 API Key 每分钟上限（0 = 不限）
```

客户端改用 `https://` 访问；自签证书可把 `ca.crt` 装进系统信任库（或临时 `curl -k`）。

### agent 并发上限（admission control）

```bash
cargo run -p agent -- ... --max-concurrency 2   # 声明最多 2 个并发请求
```

网关按 agent 声明的上限做并发占位，超限回 429，避免把家里 GPU 打爆。

### 多 agent（多台 LLM 机器）

多个 agent 指向同一个网关即可，网关按**最少负载**（在途请求最少者优先）自动路由：

```bash
# 机器 1（家里）
cargo run -p agent -- ... --agent-id home-1 --upstream http://127.0.0.1:11434 --max-concurrency 2
# 机器 2（另一台 / 云上）
cargo run -p agent -- ... --agent-id home-2 --upstream http://127.0.0.1:8000 --max-concurrency 4
```

- 每个 agent 单独签发客户端证书，`agent_id` 用于区分
- 超过 `--agent-stale-secs`（默认 15s）未心跳的 agent 自动摘除
- 全部占满时返回 429

### 可观测性

- **`GET /metrics`**：Prometheus 文本格式指标（按状态码计数、在途请求、在线 agent 数、转发字节、累计耗时），可直接被 Prometheus/Grafana 抓取
- **结构化日志**：`tracing`，每个请求带 `request_id` / 状态码 / 耗时（`tower-http` TraceLayer）
- **`/healthz`**：存活探针

> 注意：`/metrics` 未加认证，公网部署建议在安全组中仅对监控网段放行。

### 多平台打包与开机自启

```bash
scripts/build-release.sh          # 构建已安装 target 的 release 二进制并打包到 dist/
rustup target add aarch64-unknown-linux-gnu   # 需要交叉目标时先安装
```

产物：`dist/home-llm-gateway-<版本>-<平台>.tar.gz`（gateway / agent / mock-llm 三个二进制）。
macOS 交叉编译到 Linux 的说明见脚本头部注释；推荐 musl 目标得到静态二进制。

systemd 单元：`deploy/gateway.service`（云服务器）、`deploy/agent.service`（LLM 机器），改好参数后 `systemctl enable --now` 即可开机自启。

## 安全模型

| 面 | 措施 |
|---|---|
| 公网入口 | TLS 1.3、API Key 认证（恒定时间比较）、令牌桶限流、请求体大小上限 |
| 隧道 | QUIC 内建 TLS 1.3 + mTLS（云端 CA 签发 agent 证书），未注册 agent 无法接入 |
| 并发 | 按 agent `max_concurrency` 原子占位，超限 429 |
| 密钥 | CA 私钥仅在自己手里；每个 agent 单独签发客户端证书；`certs/out/` 不入库 |

## 设计文档

架构设计、帧协议细节、里程碑见 [`DESIGN.md`](DESIGN.md)。
