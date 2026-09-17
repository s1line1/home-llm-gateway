<p align="center"><b>中文</b> | <a href="README.en.md">English</a></p>

# home-llm-gateway

**Edge LLM 网关：家里/分支/边缘节点本地部署大模型，云服务器做公网中转，在任何地点通过 OpenAI 兼容 API 按模型路由访问边缘模型服务。**（家庭部署是首个实例）

Rust 实现，零外部依赖组件（不依赖 frp/ngrok/nginx）。隧道协议 **QUIC**，**mTLS 双向认证**，SSE 流式透传，支持多 edge 模型感知路由与负载均衡。

```
客户端（任何地方，请求带 model）
   │  HTTPS + OpenAI 兼容 API（含 SSE 流式）
   ▼
cloud-gateway（公网）      axum 入口：API Key 认证 → 限流 → 按 model 路由 → 隧道帧
   │  QUIC（UDP，mTLS，一条连接多路复用，无队头阻塞）
   ▼
edge-agent（LLM 所在机器）  主动拨号 + 心跳 + 断线重连，转发本地 LLM
   │  HTTP
   ▼
本地 LLM（Ollama / vLLM / llama.cpp / mock-llm）
```

## 特性

- **QUIC 隧道 + mTLS**：边缘端主动向外拨长连接，天然穿透 NAT / 动态 IP；双向证书认证，未注册 agent 无法接入
- **流式优先**：SSE 逐块透传（打字机效果）；客户端断开/超时自动 `Cancel` 上游，不白算 token；逐帧空闲超时，不误杀长流
- **公网 HTTPS 原生支持**：rustls 直接监听 443，无需 nginx/caddy
- **安全与治理**：API Key 认证（`sha256(token)` 索引定位 + argon2 校验，明文不落盘）、按 Key 令牌桶限流、按 agent 并发上限的 admission control（超限 429）
- **多 edge 模型感知路由**：按请求 model 路由到能服务它的 edge（精确优先、`*` 兜底），同组最少负载均衡，失联 agent 不再参与路由；`/v1/models` 网关聚合
- **可观测性**：`/metrics` Prometheus 指标、结构化请求日志（`request_id` / 状态码 / 耗时）、`/healthz` 探针
- **多平台部署**：单静态二进制（Linux / macOS），交叉编译脚本 + systemd 单元

## 目录结构

```
crates/
├── proto/      隧道帧协议（Register/Heartbeat/ProxyRequest/Response*/Cancel/Error）
├── gateway/    cloud-gateway 二进制（axum + s2n-quic server）
├── agent/      edge-agent 二进制（s2n-quic client + reqwest）
└── mock-llm/   模拟 OpenAI 兼容接口的假 LLM（无真实模型时打通链路用）
web/            React + TS 管理面板（Dashboard；网关启动即托管，见下）
certs/          证书生成脚本（开发用）
gateway_config.example.yml  网关配置模板（所有参数，YAML）
agent_config.example.yml    edge-agent 配置模板（所有参数，YAML）
deploy/         systemd 单元（gateway.service / agent.service）
scripts/        多平台 release 打包脚本 + git pre-commit hook（cargo deny + fmt）
Dockerfile      多阶段容器构建（gateway / agent / mock-llm 三个二进制，用法见文件头注释）
deny.toml       cargo-deny 策略（依赖许可证 / 公告；CI 与 pre-commit hook 执行）
```

> 配置文件命名：**网关固定 `gateway-config.yml`，agent 固定 `agent-config.yml`**（本地/生产一致；
> 均含密钥类信息，已 gitignore，不提交）。

## Web 管理面板（React + TS）

`web/` 是独立前端工程（Vite + React + Tailwind），提供总览、API Keys、Agents、指标四个页面。
**网关内置静态托管**：构建前端（`cd web && pnpm install && pnpm build`）后，网关配置
`ui_dir`（默认 `web/dist`）指向产物即可，**启动 gateway 浏览器打开 `/` 就是 Dashboard**
（前端路由自动 fallback，单进程单端口，无需 nginx）。`ui_dir` 缺失时 `/` 显示构建提示页
（网关不再内嵌管理页）。开发时也可 `cd web && pnpm dev` 用 Vite 代理联调
（`GATEWAY_PROXY` 可覆盖网关地址）。

## 快速开始（全部本机即可跑通，无需真实 LLM）

> 以下用 `cargo run` 仅为本地开发方便（debug 构建）；**生产部署直接用编译好的 release 二进制**，服务器无需安装 Rust，见 [`DEPLOY.md`](DEPLOY.md)。

> 💡 常用命令已收进 `Makefile`：`make help` 查看全部；`make setup`（证书+前端依赖）、
> `make dev`（一键起 mock-llm+gateway+agent 全栈）、`make dev-ui`（先构建前端再起全栈）、
> `make stop`（停全栈）、`make test` / `make build` / `make release`。

### 环境

- Rust stable（建议 1.75+）
- `openssl` 命令行（仅证书脚本需要）

### 1. 生成证书

```bash
certs/gen-dev.sh        # 输出到 certs/out/（CA + 服务端 + 客户端）
```

### 2. 起 mock LLM（模拟 edge 上的模型服务）

```bash
cargo run -p mock-llm -- --addr 127.0.0.1:11435
```

### 3. 起 edge-agent（LLM 所在机器 / edge 节点）

agent 同样用 YAML 配置（`agent --config agent-config.yml`，参考 `agent_config.example.yml`）：

```bash
cat > agent-config.yml <<'EOF'
cloud_addr: "127.0.0.1:4433"
ca: certs/out/ca.crt
cert: certs/out/client.crt
key: certs/out/client.key
agent_id: edge-1
upstream: "http://127.0.0.1:11435"
EOF
cargo run -p agent -- --config agent-config.yml
```

### 4. 起 cloud-gateway（云服务器）

网关所有参数都在 **YAML 配置文件**里（`gateway --config gateway-config.yml`，参考 `gateway_config.example.yml`）。本地开发写一份最小配置：

```bash
cat > gateway-config.yml <<'EOF'
listen_addr: "0.0.0.0:8080"
quic_addr: "0.0.0.0:4433"
cert: certs/out/server.crt
key: certs/out/server.key
ca: certs/out/ca.crt
admin_token: dev-admin   # 管理口令，用于创建第一个 API key
EOF
cargo run -p gateway -- --config gateway-config.yml
```

网关**没有静态 key**——所有 API key 都通过 Admin API 运行时创建并存入 SQLite。启动后先创建第一个 key：

```bash
curl -X POST http://127.0.0.1:8080/admin/keys \
  -H "Authorization: Bearer dev-admin" -H "Content-Type: application/json" \
  -d '{"name":"dev"}'
# → {"id":"...","key":"sk-...","name":"dev",...}  记下返回的 sk-... 即下文 dev-key
```

### 5. 从"任何地方"访问

> 下文的 `dev-key` 指上一步 Admin API 返回的明文 key。

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

### 7. 基准测试（Criterion）

函数级微基准（`cargo bench`），聚焦**真的可能变慢且有影响的路径**：
协议帧编解码 + keystore 安全热路径（argon2）：

```bash
cargo bench                          # 全部
cargo bench -p proto                 # 帧编解码（roundtrip/序列化吞吐）
cargo bench -p gateway --bench keystore   # argon2 哈希/校验、authorize 命中与 O(1) 未命中
make bench                           # 等价（可带 BENCH="-p proto"）
```

> 注意：keystore 基准里 argon2 默认参数（m=19456/t=2）单次约 10-30ms，跑完耗时较长属预期。
> 限流器与指标渲染为纳秒级无风险路径，不设基准（避免基准噪音）。

### 8. 宏观压测（系统级）

- **快速验证**（一条命令，无需安装脚本）：`oha`（`cargo install oha` / `brew install oha`）
- **可断言 / 进 CI**：`k6` 脚本模板在 `scripts/bench-k6/`（SSE 长流 + 非流式吞吐两个场景，
  内置成功率 / 延迟分位断言），用法见该目录 README：

```bash
make dev                                        # 起全栈
KEY=$(curl -s -X POST http://127.0.0.1:8080/admin/keys \
  -H "Authorization: Bearer dev-admin" -H "Content-Type: application/json" \
  -d '{"name":"k6"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['key'])")

make bench-k6 KEY=$KEY VUS=20 DUR=30s           # k6 SSE 长流压测
oha -z 30s -c 50 -m POST -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"mock-llm","messages":[{"role":"user","content":"hi"}]}' \
  http://127.0.0.1:8080/v1/chat/completions     # oha 快速吞吐
```

> 压测前建议 `cargo build --release` 用 release 二进制（debug 构建性能差一个数量级）；
> 压纯吞吐时调大 `agent-config.yml` 的 `max_concurrency`，否则高并发会被 admission control 返回 429（设计行为）；
> 高事件速率的流式压测还有第二道天花板在 **agent 的 CPU**（见《agent 每事件的 CPU 成本》）。
> ⚠️ 网关侧的内存要看是否开了校验缓存：**关闭时**每个在途请求要吃约 19MiB（argon2 工作内存），
> `max_concurrency ≈ MemoryMax / 20MB`；**默认开启时**内存不再随在途数线性增长（见《并发上限与内存》）。

## 接入真实 LLM

把 agent 配置里的 `upstream` 指向真实服务即可，其余不变：

| 本地服务 | `upstream` 值 |
|---|---|
| Ollama | `http://127.0.0.1:11434` |
| vLLM | `http://127.0.0.1:8000` |
| llama.cpp server | `http://127.0.0.1:8000` |

## 生产部署（阿里云 / 公网）

> 完整 step-by-step 部署清单（证书签发、安全组、systemd、验证、排障）见 [`DEPLOY.md`](DEPLOY.md)。以下为要点。

1. **中转网关放公网服务器**：安全组/防火墙放行 **UDP 4433**（QUIC 隧道）与 **TCP 8443**（HTTPS API）。网关自带 HTTPS，无需反代——QUIC 隧道是私有帧协议，反代本来也代理不了。日后若需域名 + 证书自动续期可加 caddy（nginx 需 `proxy_buffering off`，否则破坏 SSE 流式）。
2. **agent 放 LLM 所在机器**：agent 配置里 `cloud_addr` 填 `<公网IP>:4433`，`server_name` 填证书 SAN 中的域名（推荐域名 + DNS SAN 证书，避免 IP 变更）。
3. **mTLS 是关键安全线**：CA 私钥自己保管，每个 agent 单独签发客户端证书。
4. **UDP 注意**：QUIC 走 UDP，若被封需要放行；极端情况可降级 TCP+TLS（帧协议不变，见 `DESIGN.md` §10）。

### 启用 HTTPS + 限流

在 `gateway-config.yml` 中启用 TLS 与限流：

```yaml
listen_addr: "0.0.0.0:8443"
quic_addr: "0.0.0.0:4433"
cert: certs/out/server.crt
key: certs/out/server.key
ca: certs/out/ca.crt
admin_token: dev-admin
tls_cert: certs/out/server.crt   # 提供后公网入口启用 HTTPS
tls_key: certs/out/server.key
rate_limit_per_min: 60            # 每个 API Key 每分钟上限（0 = 不限）
```

```bash
cargo run -p gateway -- --config gateway-config.yml
```

客户端改用 `https://` 访问；自签证书可把 `ca.crt` 装进系统信任库（或临时 `curl -k`）。

### agent 并发上限（admission control）

agent 配置里 `max_concurrency: 2`（声明最多 2 个并发请求）。

网关按 agent 声明的上限做并发占位，超限回 429，避免把 edge 的 GPU 打爆。

**这个值该给多少**：主要看 edge 的 GPU/模型吞吐（这是它的本职），网关侧内存只在**缓存关闭时**才跟着并发走——那种情况下每个在途请求约 19MiB，`max_concurrency ≈ MemoryMax / 20MB`（见下节《并发上限与内存》）。**默认开启校验缓存后，网关内存不再随 `max_concurrency` 线性增长**，所以这个值可以放心按 GPU 能力给。网关侧的 `max_concurrent_requests` 是同一件事的总闸门，也按同一思路收口。

### 多 agent（多台 LLM 机器，edge 异构模型）

多个 agent 指向同一个网关即可。网关按**请求的 model 路由到能服务它的 edge**：
精确声明该模型的 edge 优先，其次才轮到 `models: ["*"]` 的通配 edge；
同组内按**最少负载**（在途请求最少者优先）自动路由（每台机器各自一份 agent 配置）：

```yaml
# edge 节点 1（家庭，跑 qwen2.5）agent-config.yml
cloud_addr: "<网关>:4433"
ca/cert/key: /etc/home-llm-gateway/*.crt
agent_id: edge-1
upstream: "http://127.0.0.1:11434"
models: [qwen2.5]        # 声明能力：网关据此路由
max_concurrency: 2

# 机器 2（云上 GPU，跑 llama3）agent-config.yml
cloud_addr: "<网关>:4433"
ca/cert/key: /etc/home-llm-gateway/*.crt
agent_id: edge-2
upstream: "http://127.0.0.1:8000"
models: [llama3]         # 声明能力：网关据此路由
max_concurrency: 4
```

- 客户端请求体必须带 `model`（缺失 → 400）；没有 edge 能服务该模型 → 404
- `/v1/models` 由网关**聚合**所有健康 edge 声明的模型（`*` 通配不列入）
- 每个 agent 单独签发客户端证书，`agent_id` 用于区分
- ⚠️ **每台机器的 `agent_id` 必须唯一**：同名 agent 会让网关踢掉旧连接（本意是同一台机器重连接管），两台机器互踢会让**活得比踢连接周期长的请求全部失败**（表象是 `/admin/agents` 恒显示 1 个 agent 在线、只有 `hlmg_agent_connections_total` 在飞涨）——详见 `TODO.md` P1
- 超过 `agent_stale_secs`（网关配置，默认 15s）未心跳的 agent **不再参与路由**（503/404）；注册表条目要等连接真正关闭才摘除，因此 `/metrics hlmg_agents` 与 `/admin/agents` 在失联期间仍会把它算作在线
- 全部占满时返回 429

### 超时与"隧道卡死"排障

三条超时各管一段（详见 `DESIGN.md` §5.6），配置项都在 `gateway-config.yml`：

| 配置 | 默认 | 覆盖范围 | 超时后 |
|---|---|---|---|
| `tunnel_op_secs` | 2s | 打开隧道流 / 发请求帧 / 取消帧 | `502` + 摘除该 agent 条目 |
| `head_timeout_secs` | 15s | 等上游响应头（首字节） | `504` + 摘除条目 |
| `timeout_secs` | 120s | 响应体逐帧空闲（SSE 有帧就不超时） | 发 `Cancel`，结束该流 |

**隧道坏掉时的典型症状**（都踩过）：`/healthz` 正常但**所有 API 请求挂住不返回**、日志停在最后一行的 `agent registered`、内存只涨不落 —— 因为请求卡在"等响应头"上，占着连接、并发槽位与缓冲区，客户端早已断开也发现不了。监控可关注：

- 日志出现 `upstream head timeout; evicting agent` / `tunnel write timed out; evicting agent`；
- `hlmg_agents` 掉到 0，但 agent 侧日志显示"已连接"（说明两侧对连接死活的判断不一致）。

排查顺序：① 看 agent 侧日志（有没有 `agent error` / 重连退避）；② 看网关 `edge connected` / `agent removed` 时间点；③ 连接数对不上时按上表把超时调小以更快失败，而不是靠重启网关。

### 并发上限与内存（实测）

网关的内存有两笔账，**必须分开算**——过去把它们混在一起，才导致"内存随并发爆炸"的误判：

| | 单笔成本 | 何时发生 | 缓存开启后的总量 |
|---|---|---|---|
| **冷启动校验**（argon2 工作内存） | **19MiB**（`m=19456 KiB`，内存硬是它的设计目标） | 每个**首次出现**的凭据（每次缓存 miss） | `同时首用的不同 token 数 × 19MiB` |
| **转发缓冲**（HTTP/TLS + chunk） | **约 0.2MB**（100 字符短流实测；长响应按响应大小加） | 每个在途请求 | `在途请求数 × ~0.2MB` |

**默认配置开着校验缓存**（`verified_cache_max: 1650`），所以稳态下 19MiB 那笔账几乎不发生：云端真实流量 21 516 个 200 请求 → `hits` 22 426 / `misses` **3**，网关 `memory.peak` 仅 7.5MB。

> **同一台机器、同一把 key、同一负载，只改 `verified_cache_max` 的对照实测**（本地全栈 release 网关，100 字符流，每档 15 秒）：
>
> | 在途并发 | 缓存关闭（`0`）峰值 | 缓存开启（`1650`）峰值 |
> |---|---|---|
> | 8 | 172.8MB（+144.0MB，**每请求 ≈19MB** = argon2） | 31.6MB（+2.8MB，**仅一次冷启动**的 argon2） |
> | 64 | **1 236.5MB**（+1 063.6MB，1GB 上限必然 OOM） | 27.1MB（+13.4MB，净增对应 **每请求 ≈0.2MB** 缓冲） |
> | 128 | **1 633.8MB** 且 **45% 请求失败**（被打爆） | 未测（无必要） |
>
> 缓存关闭时计数器保持 0（该路径不算缓存命中/未命中，见《可观测性》）。
>
> 另一组确认测量（缓存关闭口径）：8 并发同 key 请求 → RSS 8.7MB→160.8MB，vmmap 里正好 **8 块 `MALLOC_LARGE` × 19.0MB**；换成**无效 key**（sha256 未命中、根本不跑 argon2）同样压力下**零增长**；固定 8 条连接压 60 秒 / 16829 请求 → 5 秒后锁死不动（**不是泄漏**，是每并发一份工作内存）。缓存开关的长期对照（404 路径）：**关闭 = 峰值 +153.4MB / 2 962 个请求**；**开启 = 峰值 +1.6MB / 24 654 个请求**。

下面这台 2 vCPU / 1.6GB 云机（网关 `MemoryMax=1G`，100 字符 SSE、102 事件、每流约 1.0s 地板、agent `max_concurrency: 32`）的表，跑在缓存**已生效**的状态：

| 并发 | 网关 RSS | 吞吐 | 中位延迟 | p95 |
|---|---|---|---|---|
| 5 | 107MB | 3.9 req/s | 1275ms | 1302ms |
| 16 | 443–450MB | 12.0 req/s | 1288ms | 1418ms |
| 32 | 654MB（峰值 749–786MB） | 16.0 req/s | 1346ms | 3708ms |

> 这组 RSS 远高于上面本地对照的 27MB，差异来自**机器与历史**：它包含缓存生效前（旧版本）留下的分配器高水位与更多在途流，不能当作"每请求成本"来读。要规划内存请用上面那张对照表。

四条结论：

- **吞吐拐点在 16→32 并发之间**：翻倍并发只换来 +33% 吞吐（12.0 → 16.0 req/s），而 p95 从 1.4s 抬到 3.7s——**瓶颈已不在网关**。要继续加并发前，先确认瓶颈在哪一侧（网关 CPU / 出口带宽 / agent 的每事件 CPU，见下节）。
- **`agent-config.yml` 的 `max_concurrency` 只在缓存关闭时才需要按内存倒推**：那种情况下 32 并发配 1G 上限是安全档位（≈ `MemoryMax / 19MiB`，再留余量），设成 `5000` 之类等于关掉 admission control，会把网关推到 OOM（实测 40 并发 620–780MB）。**默认开启缓存后，这个值按 edge 的 GPU/模型吞吐给即可**。
- **`verified_cache_max`（默认 1650）把校验成本从"每请求"降到"每凭据版本"**：已验证身份缓存 + **单飞**（同一 token 的并发请求串行化，只跑一次 argon2）+ **凭据版本核对**（吊销即时生效，不靠 TTL）。峰值随之变成 `同时首用的不同 token 数 × 19MiB`：64 并发从 **1 236.5MB 降到 27.1MB**（上面那张对照表）。设 0 可回到"每请求都校验"的旧行为。

  > 生产实测（云端 2 vCPU / 1.6GB，同一 key）：缓存生效后 **21 516 个 200 + 941 个 429** 的负载下，`hlmg_key_verify_hits_total` = 22 426、`misses` = 3（命中率 99.99%），网关写入期间内存峰值仅 7.5MB、CPU 峰值 15%。
- **内存不随请求数累积，只随在途数**：停负载后回落到几百 MB 就不再降（分配器保留的高水位池），但持续跑几千个短请求不会继续涨。所以 `MemoryMax` 不要设成小值（见 `deploy/gateway.service` 里 `MemoryHigh` 的警告：会被冻死而不是被杀）。
- **`max_concurrent_requests` 是并发总量闸门，与内存脱钩**。它管的是「所有路径的在途 HTTP 请求总数」（只有 `/metrics` 豁免，SSE 长流从开头占到最后一块 body 送完），超限返回 `429 + Retry-After`。缓存关闭时它必须收在 `MemoryMax / 19MiB` 之下，否则那道闸等于没有——**先撞的是 `MemoryMax`（网关被 OOM 杀掉、连接中断），而不是这里优雅地 429**；缓存开启后按业务量给即可：

  ```yaml
  max_concurrent_requests: 32    # 缓存关闭时 ≈ MemoryMax / 20MB；开启后按业务量给
  ```

  三者职责不同、不能互相替代：`rate_limit_per_min` 管**每个 key 的速率**，agent 的 `max_concurrency` 管**每个 edge 的在途数**（保 GPU），这个字段管**整个网关的在途总数**（保网关自己）。

### agent 每事件的 CPU 成本

网关的内存成本由"在途 key 校验"决定（上一节），**agent 的成本则由 SSE 事件速率决定**。给定一个 token 一个 SSE 事件的流，agent 的开销几乎全部是"事件派发"本身：唤醒 → 组帧 → 发包，**与事件里有多少字节无关**。

实测（云端网关 + release agent `max_concurrency: 32` + 本机 mock，16 条并发流、每条流一个事件一个 chunk）：

| 事件/秒 | 字节/事件 | agent CPU | user / sys | csw/s | CPU/事件 |
|---|---|---|---|---|---|
| 154 | 116 | 1.0 核 | 9.5s / 23.4s | 639 | 6 800µs |
| 1 009 | 55 | 3.8 核 | 31.9s / **88.7s** | 3 506 | 3 790µs |
| 1 173 | 153 | 4.4 核 | 36.9s / **102.8s** | 4 067 | 3 780µs |
| 5 121 | 55 | 9.5 核 | 73.4s / 226.9s | 11 913 | 1 861µs |
| 6 003（饱和） | 55 | 11.7 核 | 55.3s / 196.1s | 12 736 | 1 947µs |

三条实测结论：

- **成本跟事件数走，跟字节数无关**：payload 从 1 字节提到 101 字节（事件数、节奏不变），CPU/事件 3 790µs → 3 780µs，纹丝不动；而这些档位的字节速率只有 0.2–0.3 MB/s。收益在"合并事件"而不在"合并字节"——上游一个 chunk 里塞 10 个 token，比 10 个独立 chunk 省近一个数量级的 CPU。
- **内核态是主要开销**：sys 占 73–78%，上下文切换 ≈ 3× 事件/秒。`sample` 采到的热点只有 `__sendmsg`，调用栈完整落在 s2n-quic 的发送队列 → 包编码 → 丢包恢复路径上；其余采样都停在 `__psynch_cvwait` / `kevent`。**所以别往"解析 JSON / 序列化帧更省"的方向优化**，要减少的是事件派发次数与套接字往返。
- **单 agent 的事件速率上限 ≈ 6 000 事件/秒**（约 12 核，几乎全是内核态），到顶后流开始排队：p95 5.6s、max 12.2s。**30 秒级长尾多半出现在这里**，不是网关的问题——用 `top` 看 agent 是否跑满即可区分。

换算到真实流量就不必紧张：真实模型 20–100 token/s，即约 1.9–3.8ms CPU/token，**单条流只吃 0.04–0.4 核**（单核可撑 3–23 条流，8 核机器对应上百条并发流）。6 000 事件/秒相当于 120 条流同时以 50 token/s 输出，所以"每事件 CPU"在生产 token 速率下不是瓶颈；真正先撞到的是密钥校验（见上一节）与网络出口。

> 测量方法：agent 侧 CPU 取自 `proc_pidinfo(PROC_PIDTASKINFO)`，热点用系统自带 `sample`。⚠️ 该结构体字段有坑：`pti_threads_user` / `pti_threads_system` 也是 `u64`，漏掉它们会让 `pti_csw` 读错位（我们一开始把线程数当成了上下文切换数，量级差 400 倍）。

### 网关自身的吞吐上限（实测 ≈190 QPS / 2 vCPU）

**结论：这台 2 vCPU 云机上的单实例网关，真实上限约 180–210 QPS，此时它把自己两个核吃满。**

"gateway 能跑多少 QPS"必须先定义负载——它随**每请求事件数**变化，因为事件成本的大头在 agent 而不在网关（见上一节）：

| 负载口径 | 实测上限 | 当时的瓶颈 |
|---|---|---|
| SSE，100 事件/请求 | 16–17 QPS | **agent** 的 ≈1 700 事件/秒 |
| SSE，1 事件/请求 | ≈180–211 QPS | **gateway** 的 CPU（2 核） |
| 非流式，1 帧/请求 | ≈190–197 QPS | **gateway** 的 CPU（2 核） |

把负载降到"每请求 1 个事件"之后，瓶颈就干净地从 agent 移到了网关。阶梯实测（15s/档，客户端 k6 `VUS`，同时采三侧）：

| 并发 | QPS | p50 | p95 | 失败 | gateway CPU | CPU/请求 | gateway 内存 | UDP 丢包增量 |
|---|---|---|---|---|---|---|---|---|
| 128 | 190.3 | 844ms | 880ms | 0.4% | 1.51 核 | 0.50ms | 58MB | 0 |
| 256 | 189.4 | 1.72s | 1.76s | 0.4% | 1.82 核 | 0.58ms | 59MB | 0 |
| 512 | 197.1 | 3.04s | 3.50s | 4.6% | **2.01 核** | 0.56ms | 61MB | 0 |

（流式 1 事件/请求同口径：512 并发 → **211.3 QPS**、p50 2.78s、gateway 2.14 核。）

四条判读：

- **QPS 不随并发增长（128→512 并发几乎不变），而延迟线性增长**（p50 844ms→3.04s）——这是排队饱和的典型特征，不是"还能加并发"。
- **gateway CPU 停在 2.0–2.3 核**，而云机 `nproc=2`、cgroup `cpu.max=max`（**没有配额限制**）、`nr_throttled=0`（没被节流）→ 就是**算力打满**。2.1 核 ÷ 190 QPS ≈ **每请求 0.55–0.9ms CPU**，与"CPU 跑满得出该 QPS"自洽，约 **95 QPS/核**。
- **这次不是别人拖后腿**（并发采三侧）：agent **1.05 核**、上游 mock 0.31 核（都可忽略）；链路 0.3MB/s 且 **UDP 丢包增量为 0**。
- **实测上限 ≈190 QPS**，不是"理论值"。

**为什么停在这里（已剖析）**：不是算力用尽，而是**每请求一次同步落库把网关串行化了**。本地全栈用 `sample` 剖析网关，热点不在 HTTP/QUIC，而在阻塞线程池里的 `KeyStore::persist_usage`——**13 951 / 13 965 个采样停在 `Mutex::lock()`**（真正执行 SQL 的只有 14 个），调用栈上全是 `sqlite3VdbeExec` / `syncJournal` / `unixSync` / `fsync`。在云机上取线程等待点更直接：

```
线程数 515；卡在 futex(等同一把 db 锁) 的线程 = 514 / 511 / 511 / 514 / 514 / 514
```

即**每请求 `spawn_blocking` 一次用量 UPSERT，全都要抢同一把全局 `db` 互斥锁**；"CPU 吃满 2 核"里很大一部分是 512 个阻塞线程的争抢与上下文切换。三个对照实测（本地同机、同 mock、`oha` 256 并发 × 30s，实验代码已回退）：

| 方案 | QPS | CPU/请求 | 线程数 | 库里的用量 |
|---|---|---|---|---|
| 改造前：每请求 `spawn_blocking` 落库 | 934 | 11.2ms | **521** | 18 555 |
| **改造后：批量落库 + 关闭前落库** | **15 744** | **3.40ms** | **151** | **314 742** |

（同机、同 mock、同客户端 `oha` 256 并发 × 20s。两档延迟不可直接比：改造前压根跑不到这个并发——它被写库串行化摁在 934 QPS，改造后才真正吃满 CPU。库里的用量都是 SIGTERM 之后读出来的。）

**所以顺序是先修落库路径、再谈扩容**——不修的话加核/加实例也会在 190 QPS 附近走平，因为瓶颈是串行化的写路径而不是核数。（上表为本机盘的数字，fsync 仅 0.05ms；云机 fsync ≈3.5ms，修完后的云端上限尚未实测。）

### 用量落库（每请求写库 → 按周期批量写）

用量（token / 请求数）落库在改造前是**每请求一次** `INSERT ... ON CONFLICT`，也就是上面那条把吞吐摁住的路径。现在改成：

- **热路径只做内存累加**（`UsageCollector::finish` → `KeyStore::accumulate_usage`），纳秒级、无 IO；
- **后台任务按周期（1s）批量落库**（`usage_flush::spawn` → `KeyStore::flush_usage_once`），一个事务里把有变化的 key 各写一行；
- **写的是绝对累计值而不是增量**：库里始终收敛到内存的真相，天然幂等、重启不会重复累加，也不存在"增量被取走但落库失败 ⇒ 永久少一段"的窗口；
- **关闭前强制落库**：`main` 收到 SIGTERM/SIGINT 后先 `Gateway::flush_usage_on_shutdown()`（阻塞写一次）再停服务，日志会打 `usage flushed before shutdown keys=N` —— **正常关闭不丢任何用量**；只有"进程被 SIGKILL / 断电"这种非正常退出，才可能丢最后一个 flush 周期（≤1s）的用量。
- 顺带开启 `journal_mode=WAL` + `synchronous=NORMAL`：批量之后提交次数已经很少，这两条让剩余提交不必每次 fsync 主库（云端每次同步提交约 3.5ms）。

`/admin/usage` 读的仍是内存计数，响应返回时立即一致，不受 flush 周期影响。


含义：**单实例约 190 QPS，要更高只有加核（垂直，大致线性）或加实例（水平，`DESIGN.md` §11.4 未实现）**。真实 LLM 场景不受它约束——真实模型下 `QPS ≈ 并发 ÷ 单请求耗时`（几秒级），远低于 190；这个数字只在"把模型换快"或"拿网关转发非 LLM 小请求"时才有意义。

> 测法要点（缺一条数字就失真）：① 上游换**每请求 1 事件**的最小 mock，把 agent 的 1 700 事件/秒墙推开；② 云端放开闸门 `max_concurrent_requests: 5000`、`rate_limit_per_min: 0`（测完记得改回，见上一节的内存口径）；③ 压测客户端用 k6 而非 Python `requests`（后者 32 并发自己就先饱和了）；④ 每档同时读云端 cgroup 的 `cpu.stat`/`memory.current` 与 `nstat` 的 UDP 丢包增量。

### 可观测性

- **`GET /metrics`**：Prometheus 文本格式指标（按状态码计数、在途请求、在线 agent 数、转发字节、累计耗时），可直接被 Prometheus/Grafana 抓取
  - 浏览器直接访问（`Accept: text/html`）时返回 Dashboard 页面而非文本，便于点进指标页；Prometheus 抓取（`Accept: */*`）不受影响
  - `hlmg_quic_accepting`：隧道入口是否仍在接受新 agent（1/0）。UDP 驱动失效时入口会停止接受新连接，而进程与 HTTP 入口照常运行——**建议对该指标为 0 告警**（这是唯一能发现该故障的信号）
  - `hlmg_key_verify_hits_total` / `hlmg_key_verify_misses_total`：key 校验命中已验证缓存 / **真正跑了 argon2**的次数。misses 的**增量**就是内存与 CPU 的风险信号（一次 miss 峰值 +19MiB，见《并发上限与内存》），稳态下应接近 0；突然上涨说明凭据被吊销/新增，或缓存容量 `verified_cache_max` 不够。⚠️ **`verified_cache_max: 0` 时这两个计数器恒为 0**（走的是不走缓存的旧路径，两个数都不加）——看到 0 要先确认缓存是否被关掉，别当成"没有校验"
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

## API Key 管理（Admin API）

网关内置轻量管理接口，可**运行时签发 / 吊销 key，无需重启网关**：

- **网页管理页**：浏览器打开 `http://<网关地址>/` 即进入管理界面——输入 admin token 后可直接**创建 / 吊销 / 列出 key**
- 配置项 `admin_token`（`gateway-config.yml`）：管理口令（与 API Key 相互独立），提供后启用 `/admin/*` 与页面中的管理功能
- 配置项 `keys_file`：动态 key 持久化数据库文件（SQLite，默认 `keys.db`），重启后依然有效；**只存 argon2 哈希，明文仅创建时返回一次**
- 网关没有静态 key——所有 key 都由 Admin API 创建（全部持久化在 SQLite），统一用于调用 `/v1/*`

```bash
# 创建 key（返回明文，仅此一次展示）
curl -X POST http://127.0.0.1:8080/admin/keys \
  -H "Authorization: Bearer <admin-token>" -H "Content-Type: application/json" \
  -d '{"name":"dsh-client"}'
# → {"id":"ab99de40","key":"sk-…","name":"dsh-client","created_at":…,"enabled":true}

# 列出（脱敏；明文不落盘，前缀为固定掩码，不暴露任何凭据信息）
curl http://127.0.0.1:8080/admin/keys -H "Authorization: Bearer <admin-token>"

# 吊销（立即生效）
curl -X DELETE http://127.0.0.1:8080/admin/keys/<id> -H "Authorization: Bearer <admin-token>"
```

> 安全：`admin_token` 务必用强随机值（`openssl rand -hex 32`）；`keys.db`（SQLite）只存 argon2 哈希、不含明文密钥，已加入 `.gitignore`；生产环境建议在安全组中仅对管理网段开放 `/admin/*`。

## 安全模型

| 面 | 措施 |
|---|---|
| 公网入口 | TLS 1.3（配 `tls_cert`/`tls_key` 后启用 HTTPS；未配即明文 HTTP）、API Key 认证（sha256 索引 + argon2 校验）、令牌桶限流、请求体大小上限 |
| 隧道 | QUIC 内建 TLS 1.3 + mTLS（云端 CA 签发 agent 证书），未注册 agent 无法接入 |
| 凭据边界 | 调用方凭据（`Authorization` / `Cookie`）只留在「客户端 ↔ 网关」这一跳，**不**随隧道帧转发给 edge / 上游（上游需要认证时，在 agent 侧配置上游自己的凭据） |
| 并发 | 按 agent `max_concurrency` 原子占位，超限 429 |
| 密钥 | CA 私钥仅在自己手里；每个 agent 单独签发客户端证书；`certs/out/` 不入库 |

## 设计文档

架构设计、帧协议细节、里程碑见 [`DESIGN.md`](DESIGN.md)。
