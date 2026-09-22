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
docker-compose.yml  容器部署示例（网关；agent 模板在文件末尾，路径映射见 DEPLOY.md §11）
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
cargo test             # proto roundtrip + 端到端集成测试（内存生成证书，无需任何外部服务）
cargo nextest run -w   # 同上，但用 nextest（CI 用的就是它，见下）
```

> **CI 用 `cargo nextest`**（`cargo test` 仍然可用，两者都要能过）。换它的原因：nextest
> **每条测试一个进程**，各测试二进制之间可以并行，而且不会像 libtest 那样把 `#[serial]`
> 的**等锁时间**算进"这条测试跑了多久"——CI 上原来那几条 `has been running for over 60
> seconds` 多数只是排在队里等锁。
>
> ⚠️ 但这也意味着 **nextest 下 `#[serial]` 会失效**（`serial_test` 的锁是**进程内**的，
> 进程隔离后各锁各的）。e2e 每条都要起独立 runtime + QUIC + mTLS 栈、且含时序敏感断言，
> 所以它的串行改由 `.config/nextest.toml` 的 **test-group**（`max-threads = 1`）保证；
> `#[serial]` 标记**保留不删**，因为 `cargo test` 仍然依赖它们。
>
> `make test` = `cargo test`，`make nextest` = nextest（未安装时先 `cargo install cargo-nextest --locked`）。
> 另外 nextest **不跑 doctest**：本仓库当前没有 doctest，将来若加了要补 `cargo test --doc`。

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

**这个值该给多少**：主要看 edge 的 GPU/模型吞吐（这是它的本职）。**三个约束（都实测过）**：

- **它只是声明**：agent 端**没有信号量**、不会自己拦，超了由网关按这个数字返回 `429 "agent at capacity"`——所以它是"告诉网关我能吃多少"，而不是自我限流。
- **必须 ≤ 网关的 `max_open_tunnel_streams`**（默认 1024）：声明超过网关每连接的流额度时，多出来的请求会排在 **QUIC 流额度**上（而不是容量上），表现为"隧道随机超时"→ 摘除 → 重连期间全量 503。网关在 agent 注册时会打 WARN 提示。
- **只有缓存关闭时**才需要按网关内存倒推：那种情况下每个在途请求约 19MiB，`max_concurrency ≈ MemoryMax / 20MB`（见《并发上限与内存》）。**默认开启校验缓存后，网关内存不再随 `max_concurrency` 线性增长**，所以这个值按 GPU 能力给即可（网关侧另有 `max_concurrent_requests` 作为总闸门）。

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
| `tunnel_op_secs` | 10s | 打开隧道流 / 发请求帧 / 取消帧 | **先换一个 agent 重试**（见下）；仍失败才 `502`，并计入"连续超时" |
| `head_timeout_secs` | 15s | 等上游响应头（首字节） | `504`（**不重试**）；**只有窗口内没有任何成功响应头时才计入"连续超时"**（被堵住的慢不摘除，见下） |
| `timeout_secs` | 120s | 响应体逐帧空闲（SSE 有帧就不超时） | 发 `Cancel`，结束该流 |

判"连接已死"要**连续 3 次**隧道操作超时（`registry::TUNNEL_TIMEOUTS_BEFORE_EVICT`）：单次超时在高并发下
是排队假象——开流/写帧都要过连接级流管理器。任何一次**收到响应头**都会把计数清零
（开流成功不算，因为卡死的 agent 照样能被开流）。

### 失败处理：重试、摘除与延迟关闭

#### 能重试什么、不能重试什么（`MAX_TUNNEL_ATTEMPTS = 2`）

| 失败点 | 是否重试 | 依据 |
|---|---|---|
| 打开隧道流失败 | **重试**（换另一个 agent） | 还没写过任何字节，请求帧必然**未送达** |
| 写请求帧失败 | **重试**（换另一个 agent） | `write_frame` 是一整块 `write_all`，只有**全部字节被接受**才返回；超时 ⇒ 帧不完整 ⇒ agent 读不到完整帧（`FrameReader` 先读满长度前缀+载荷）⇒ 它不会调用上游 |
| **等响应头超时** | **不重试** | 请求帧已完整送达，**模型可能已经在执行**；重试会重复计费、重复生成（`temperature > 0` 时结果还不一样）。宁可报错，也不做不安全的静默重放 |
| 响应体中途断流/超时 | 不重试 | 已经产出字节，无法重放 |

重试会**排除刚失败的那条连接**（`try_acquire_excluding`），否则"重试"会再次选中同一条坏连接；
没有别的候选时，把**真正的失败原因**报给客户端（`502 ... no other agent available to retry`），
而不是一个会把人引向"注册问题"的 503。

> 想把"响应头超时"也做成可安全重试（不产生第二次模型调用），需要协议级去重：
> 全局唯一 `request_uid` + agent 侧去重表。完整设计、取舍与不解决的问题见
> [`EXACTLY_ONCE.md`](EXACTLY_ONCE.md)（**提案，未实现**）。

#### 摘除与延迟关闭

达到连续超时阈值后，

1. **先移出路由** —— 后续请求不再选中它（这一步与何时关连接无关）；
2. **再决定何时关闭连接**：若这条连接上还有别的在途请求（`inflight > 1`），立刻关就是白扔
   已经在途的工作——它们既可能是**已经把请求送达 agent、模型正在生成**的，也可能是
   **仍在等响应头**的（槽位从取得一直持有到响应结束）。所以等在途归零后再关，
   **最多等 `evict_close_grace_secs`（默认 15s，与 `head_timeout_secs` 相同）**后强制关；
   只剩当前这个失败请求时才立刻关。

延迟关闭既避免打断正常请求，又保证连接最终会关——否则 agent 会退化成
"自认为在线、网关侧不存在"的僵尸（实测这种状态下 503 占 92.6%）。

#### "超时"不等于"已死"：忙与死必须分开处置

**两类超时都适用这套判据，但问的问题不同**：开流超时问"还有额度吗"（`registry::Entry::open_timeout_is_fatal`），响应头超时问"这条隧道最近还干活吗"（`registry::Entry::head_timeout_is_fatal`）。

**开流超时**：

| 成因 | 判据 | 处置 |
|---|---|---|
| **忙**（背压） | 在途请求数已达这条连接的承载上限 `min(agent 声明的 max_concurrency, 每连接流额度)` | **不摘除**：排队等额度是正常背压。记 `hlmg_tunnel_open_timeouts_total{class="busy"}`，换下一条连接重试；都满了返回 **429**（容量不足），而不是 502 |
| **死** | 没到承载上限却开不出流（没有任何排队理由） | 走上面的摘除流程（连续 3 次 + 延迟关闭），记 `class="dead"` |

**响应头超时**（2026-09-18 补第一层，修的是"链路饱和 → 全队 503"那条放大链；2026-09 补第二层，修"均匀慢流量"那格）：

| 成因 | 判据 | 处置 |
|---|---|---|
| **被堵住的慢** | 窗口（`4 × head_timeout`，默认 60s）内**有过成功响应头** | **不摘除、不计连续超时**：只回 504、向上游发 `Cancel`。记 `hlmg_upstream_head_timeouts_total{class="slow"}` |
| **慢，但对端还活着**（第二层） | 窗口已过，但**心跳新鲜**（`agent_stale_after` 内）**且**静默未超过 `head_silent_grace_secs`（默认 120s = 一条请求的寿命） | 同上：不摘除、只回 504，记 `class="slow"` |
| **真的没有了** | 其余：窗口已过且（对端不再说话 **或** 静默已超过上面那条上限）；**以及"从未回过响应头"** | 走原来的摘除流程（连续 3 次 + 延迟关闭），记 `class="silent"` |

**第二层为什么必须有**：那格判据靠"最近有没有成功响应头"来分辨，而它的唯一刷新点就是成功响应头本身。于是只要**所有**请求都慢过 `head_timeout`（大模型首字节慢、上游排队、链路被堵），就没有任何一次成功能刷新它 → 窗口必然走完 → 一条**活得好好的** agent 被摘除，绕回它本来要防的那条链。对端还在发心跳 = 它还在说话；而"数据面被堵住的慢"与"数据面卡死"在网关侧**观察上无法区分**，所以这一层选择"宁可晚摘、不误摘"，并用 `head_silent_grace_secs` 给上界——静默比一条请求活得还久、心跳却还在，那更像卡死。代价是这种卡死连接要等到超过该上限才被摘除，期间它的每个请求白等一次 `head_timeout`。

这套判据的云端验证见《云出口带宽上限》的复测表：同一档压测里 924 次"慢但不摘除"，
而摘除/重连/`registry-empty` 全部为 0（修前同一档是 1 026 次误摘 + 全量 503）。

窗口不单独设配置项，由 `head_timeout` 派生（4 倍）：连续四个响应头超时窗口一次都没回过，就不再是"排队慢"。**注册不算"活着"**——判据要的是"**响应头**最近有没有流动"，所以一条注册后从不回包的坏隧道仍然按原来的连续 3 次规则被摘掉（既有的 `e2e_dead_tunnel_fails_fast_instead_of_hanging` 就钉着这一点）；同理，第二层也不覆盖"从未回过响应头"的连接——没有一次成功响应头就**没有"它能服务"的证据**。代价是"最近刚成功过、随后真死"的 agent 会晚一个窗口（对端也不再说话时）或晚到 `head_silent_grace_secs`（心跳仍在时）才被摘除——不影响路由，因为真死的 agent 心跳会停，`agent_stale_after` 先把它从候选里剔掉；进程直接消失时则由连接关闭走 `remove_if_same` 摘除。

把"忙"当"死"会**把局部过载放大成全站不可用**：摘除 → 连接被关 → agent 重连（退避最长 30s）
→ 期间注册表里一个可路由 agent 都没有 → 所有请求 503。云端实测（2026-09-17，4 agent、768 并发）：
`tunnel open timed out` 9345 次，一次 30s 压测 `hlmg_agent_rejections_total{reason="registry-empty"}`
**+6835**、503 **+6057**。两个 class 分开暴露，是为了让"该扩容"与"该查网络"一眼可分。

#### 每连接流额度必须显式设置（`max_open_tunnel_streams`，默认 1024）

s2n-quic 的 `initial_max_streams_bidi` 默认只有 **100**（`InitialMaxStreamsBidi::RECOMMENDED`），
实际可用额度取 `min(本地额度, 对端额度)`。agent 侧已经给了 1000（`agent::connect_once`），
**但网关自己的本地额度以前从没设过 = 100**：一条 agent 连接最多只能有 100 条在途请求，
第 101 条起就在排队等额度回收，上游一慢（首字节超过 `tunnel_op_secs`）就排队超时。
取值必须 **≥ 每个 agent 声明的 `max_concurrency`**，声明超过本值时网关注册时会打 WARN
（这类配置不一致表现为"隧道随机超时"，比容量不足难查得多）。
回归测试：`e2e_more_concurrent_tunnels_than_the_default_quic_stream_ceiling`
（120 条并发慢流；把额度改回 100 时正好 20/120 失败，且失败的是 503——正是上面那条放大链）。

#### 客户端停滞：为什么入口侧每一处都必须设上限（`client_stall_secs`，默认 60s）

准入票据（`max_concurrent_requests` 那道闸）的释放挂在 Drop 上，但**释放的前提是相关任务/连接
能结束**。以前有五处客户端侧等待**没有任何超时**，任一处都能让连接/任务永久占住资源：

| 位置 | 谁能触发 | 修法 |
|---|---|---|
| 读请求体（曾是 `Bytes` 提取器） | 只发 headers、声明大 `Content-Length` 却不发 body 的客户端 | 改为逐块读 + **停滞**超时（有字节就续期）→ `408` |
| 写响应体通道（`tx.send().await`） | 读完响应头就不再读 socket 的客户端 | 通道满且 `stall` 内无人取 → 记指标 + 取消上游（`Cancel`，别白烧 token）+ 结束响应体 |
| hyper 往 socket 写响应 | 同上（这一半**应用层修不到**：数据已在 hyper/socket 缓冲里） | IO 层包 `io_stall::WriteStall`：连续 `stall` 写不进一个字节 → 断开连接，body 随连接任务 drop，票据归还 |
| TLS 握手（`acceptor.accept`） | 连上却**一个字节都不发**的客户端（半开连接） | `tokio::time::timeout(client_stall, ..)` → 记 WARN 并断开 |
| 读请求头（hyper） | 发了**半个请求头**就不再发的客户端 | `http1::Builder::header_read_timeout(client_stall)` **+ `.timer(TokioTimer::new())`**：不 set timer 时 hyper 只是"记下配置"，超时值不生效——它默认的 30s 就是这样一直没生效的 |

后两处（2026-09-21 补，评估 H8 / `PROJECT_SCAN` P1-1）与前三处有一个关键区别：前三处是
**准入之后**占住槽位，这两处**连闸门都没进**（闸门在"解析出请求"之后才生效），所以它们吃的是
**fd 与连接任务**，此前只受 NOFILE 约束。与之配套的是并发连接数上限
`max_entry_connections`（默认 1024，0 = 不限）：满额时**暂停 accept**，新连接留在内核 backlog
里排队——不是拒绝，所以突发流量只会变慢、不会变成 5xx，fd 也不会被吃光。

实测（2026-09-18 云端）：这类泄漏沉淀过 **8 个永不复位的槽位**——`hlmg_active_requests` 恒定 8，
而 `hlmg_request_count − Σ状态码 = 8` 精确对上（= "被准入但永不结束"）。它只增不减：
当前 `max_concurrent_requests: 5000` 时无害，但按本文件的内存口径生产该是 ~32 量级，
8 个就是 25%，且**只能重启恢复**。

> ⚠️ 判据要**减掉中断**：`僵尸槽位 = hlmg_request_count − Σ状态码 − hlmg_requests_aborted_total`。
> 客户端中途断开时 hyper 会 drop 掉 handler 的 future——准入数已经 +1 而状态码永远写不出来，
> 不减这一项的话每中断一次差值就漂移 +1，真泄漏会被淹没（2026-09-22 修：中断单独计数，
> 由 `metrics_middleware` 的 RAII 守卫补记）。上面那次历史事故里没有中断参与，所以当时直接对得上。

判定的是**停滞**而不是**总时长**：该方向只要还有字节在动就持续续期，所以慢而持续的大 body
上传、弱网下逐块到达的 SSE 都不会被误杀。五个方向共用同一个 `client_stall_secs`。
回归测试：`tests/e2e/stalls.rs`（请求体停滞、响应体停滞各一条；判据是 `max_concurrent_requests: 1`
下**后续请求不得 429**——槽位一泄漏就必然 429）、`tests/e2e/entry_limits.rs`（半开握手、
半个请求头、额度满时排队各一条）与 `io_stall` 的单测（写不动必须 `TimedOut`、持续有进展绝不断开）。
都做过红检。

**e2e 自己也按同一套口径上界**：HTTP 一律用 `common::test_client()`（整条请求含读响应体的
总超时 = `STEP_TIMEOUT`），原始帧/channel 等待用 `common::bounded(step, ..)`——卡住会变成
**带步骤名**的失败，而不是 nextest 的 180s TIMEOUT、或 `make test`（e2e 是 `#[serial]`）下
整个套件无限期挂起。**故意让客户端卡住的用例豁免**（`stalls.rs`、`write_backpressure.rs`、
`https::e2e_proxy_protocol_edge_cases`），理由见 `common.rs` 的 `test_client` 文档。

#### 隧道坏掉时的典型症状（都踩过）

`/healthz` 正常但**所有 API 请求挂住不返回**、日志停在最后一行的 `agent registered`、内存只涨不落 —— 因为请求卡在"等响应头"上，占着连接、并发槽位与缓冲区，客户端早已断开也发现不了。监控可关注：

- 日志出现 `upstream head timeout; evicting agent` / `tunnel write timed out; evicting agent`；
- 日志出现 `tunnel open timed out while agent is at capacity; not evicting` = 容量不足（该扩容或调 `max_concurrency`），不是故障；
- `hlmg_agents` 掉到 0，但 agent 侧日志显示"已连接"（说明两侧对连接死活的判断不一致）。

排查顺序：① 看 agent 侧日志（有没有 `agent error` / 重连退避）；② 看网关 `edge connected` / `agent removed` 时间点；③ 连接数对不上时按上表把超时调小以更快失败，而不是靠重启网关。

### 并发上限与内存（实测）

网关的内存有两笔账，**必须分开算**——过去把它们混在一起，才导致"内存随并发爆炸"的误判：

| | 单笔成本 | 何时发生 | 缓存开启后的总量 |
|---|---|---|---|
| **冷启动校验**（argon2 工作内存） | **19MiB**（`m=19456 KiB`，内存硬是它的设计目标） | 每个**首次出现**的凭据（每次缓存 miss） | `同时首用的不同 token 数 × 19MiB` |
| **转发缓冲**（HTTP/TLS + chunk） | **约 0.2MB**（100 字符短流实测；长响应按响应大小加） | 每个在途请求 | `在途请求数 × ~0.2MB` |

**默认配置开着校验缓存**（`verified_cache_max: 1650`），所以稳态下 19MiB 那笔账几乎不发生：云端真实流量 21 516 个 200 请求 → `hits` 22 426 / `misses` **3**。缓存到底有没有在生效，看这两个计数器就知道：线上实测发 3 个带有效 key 的请求 → `hits=2 / misses=1`（首个 miss 跑 argon2，随后命中）。⚠️ **`misses` 的口径是"真跑了 argon2 的次数"**（与指标 HELP 的措辞一致，2026-09 对齐过一次）：**`verified_cache_max: 0`（缓存关闭）时 `hits` 恒为 0、`misses` 等于校验次数**——旧口径在这一档恒为 0，会让人误以为"没有校验"。错 token 不计入：它的 `sha256` 不同 ⇒ 查不到记录 ⇒ 按设计**不跑 argon2**。

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

**线上读数（云端 2 vCPU / 1.6GB，`MemoryMax=1G`，缓存开着）**：

| 状态 | 读数 |
|---|---|
| 刚启动、几乎无流量 | RSS **5.2MB**、`VmHWM` **10.2MB**、cgroup `memory.peak` **11MB** |
| 数百并发压测期间（2026-09-17 会话记录） | RSS **≈69MB** 量级 |
| 21 516 个 200 请求跑完之后 | cgroup `memory.peak` 仅 **7.5MB**（批量落库版；写路径不再随请求数吃内存） |

**网关侧结论**（agent 侧的在下一节，链路带宽在《云出口带宽上限》，三者别混着读）：

- **`verified_cache_max`（默认 1650）把校验成本从"每请求"降到"每凭据版本"**：已验证身份缓存 + **单飞**（同一 token 的并发请求串行化，只跑一次 argon2）+ **凭据版本核对**（吊销即时生效，不靠 TTL）。峰值随之变成 `同时首用的不同 token 数 × 19MiB`：64 并发从 **1 236.5MB 降到 27.1MB**（上面那张对照表）。设 0 可回到"每请求都校验"的旧行为。

  > 生产实测（云端 2 vCPU / 1.6GB，同一 key）：缓存生效后 **21 516 个 200 + 941 个 429** 的负载下，`hlmg_key_verify_hits_total` = 22 426、`misses` = 3（命中率 99.99%），CPU 峰值 15%。
- **`max_concurrent_requests` 是并发总量闸门，与内存脱钩**。它管的是「所有路径的在途 HTTP 请求总数」（`/metrics` 与 `/healthz` 豁免——探针被 429 会让 LB 摘除实例、把"慢"放大成"全挂"；SSE 长流从开头占到最后一块 body 送完），超限返回 `429 + Retry-After`。缓存关闭时它必须收在 `MemoryMax / 19MiB` 之下，否则那道闸等于没有——**先撞的是 `MemoryMax`（网关被 OOM 杀掉、连接中断），而不是这里优雅地 429**；缓存开启后按业务量给即可：

  ```yaml
  max_concurrent_requests: 32    # 缓存关闭时 ≈ MemoryMax / 20MB；开启后按业务量给
  ```
- **网关的内存只跟"在途"走、不跟"请求数"走**：持续跑几千几万个短请求不会继续涨，停负载后回到十几 MB 量级——分配器保留的高水位只体现在 `memory.peak` 上，不会让 RSS 长期停在几百 MB（依据是上面的线上读数表）。所以 `MemoryMax` 不要设成小值（见 `deploy/gateway.service` 里 `MemoryHigh` 的警告：会被冻死而不是被杀）。

  三者职责不同、不能互相替代：`rate_limit_per_min` 管**每个 key 的速率**，agent 的 `max_concurrency` 管**每个 edge 的在途数**（保 GPU），这个字段管**整个网关的在途总数**（保网关自己）。

> ⚠️ **作废数据**：本节曾引用一组"云端 5/16/32 并发 → RSS 107 / 443–450 / 654MB（峰值 749–786MB）"的读数，**不要再用**。它自相矛盾：32 并发那档 RSS 636MB 与 `32 × 19MiB = 638MB` 几乎精确相等，是**每请求一次 argon2** 的指纹——说明那几次运行里缓存并没有真正生效，与当时写的"缓存已生效"前提冲突；而"差异来自旧版本留下的分配器高水位"是推测，解释不了原始采样里负载开始后 **20 秒内 RSS 从 11MB 涨到 573MB** 的活内存。规划内存请用上面那张受控对照表与线上读数。

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

**agent 侧结论**：

- **成本跟事件数走，跟字节数无关**：payload 从 1 字节提到 101 字节（事件数、节奏不变），CPU/事件 3 790µs → 3 780µs，纹丝不动；而这些档位的字节速率只有 0.2–0.3 MB/s。收益在"合并事件"而不在"合并字节"——上游一个 chunk 里塞 10 个 token，比 10 个独立 chunk 省近一个数量级的 CPU。
- **内核态是主要开销**：sys 占 73–78%，上下文切换 ≈ 3× 事件/秒。`sample` 采到的热点只有 `__sendmsg`，调用栈完整落在 s2n-quic 的发送队列 → 包编码 → 丢包恢复路径上；其余采样都停在 `__psynch_cvwait` / `kevent`。**所以别往"解析 JSON / 序列化帧更省"的方向优化**，要减少的是事件派发次数与套接字往返。
- **单 agent 的事件速率上限 ≈ 6 000 事件/秒**（约 12 核，几乎全是内核态），到顶后流开始排队：p95 5.6s、max 12.2s。**30 秒级长尾多半出现在这里**，不是网关的问题——用 `top` 看 agent 是否跑满即可区分。上限随核数走：较早一次 100 事件/请求的端到端实测在 **≈1 700 事件/秒**处到顶（那台 edge 的核数更少），而 102 事件/请求的负载实测约 **16 req/s**（16 × 102 ≈ **1 630 事件/秒**）——两次读数落在同一个量级，都是 agent 先到顶。
- **所以"加并发换不到吞吐"先查 agent**：判断顺序是 **agent 的事件速率 → 链路带宽 → 网关**。大 payload 时先撞的是**云出口带宽**（≈0.4 MB/s，见《云出口带宽上限》）；网关自己的 CPU 在 500 QPS 时只用 7–8%。

换算到真实流量就不必紧张：真实模型 20–100 token/s，即约 1.9–3.8ms CPU/token，**单条流只吃 0.04–0.4 核**（单核可撑 3–23 条流，8 核机器对应上百条并发流）。6 000 事件/秒相当于 120 条流同时以 50 token/s 输出，所以"每事件 CPU"在生产 token 速率下不是瓶颈；真正先撞到的是密钥校验（见上一节）与网络出口。

> 测量方法：agent 侧 CPU 取自 `proc_pidinfo(PROC_PIDTASKINFO)`，热点用系统自带 `sample`。⚠️ 该结构体字段有坑：`pti_threads_user` / `pti_threads_system` 也是 `u64`，漏掉它们会让 `pti_csw` 读错位（我们一开始把线程数当成了上下文切换数，量级差 400 倍）。

### 网关自身的吞吐上限（实测：改造前 ≈190、改造后 ≈460–500 QPS / 2 vCPU）

> **口径先说清（本节只留可信数字）**：**可信 = 只数 `/metrics` 里 `status="200"` 的增量，
> 并同时记录 200 占比**。任何用压测工具自带的 "Success rate" 得出的绝对 QPS **一律不作为
> 结论**——`oha` 的 Success rate 只统计连接错误，**503 也算成功**，我们因此一度写出过
> 1 400+ 的假数字（见本节末尾的作废说明）。凡口径不合此标准的数字，本文只保留其**结论**，
> 不保留其绝对 QPS。

**结论：改造前约 180–210 QPS；把"每请求一次落库"改成按周期批量之后，可信实测 ≈460–500 QPS（200 占比 100%），此时网关只用 7–8% CPU。这个上限是云服务器出口带宽给的，不是网关算力给的（见下方带宽说明块）。**

"gateway 能跑多少 QPS"必须先定义负载——它随**每请求事件数**变化，因为事件成本的大头在 agent 而不在网关（见上一节）：

| 负载口径 | 实测上限 | 当时的瓶颈 |
|---|---|---|
| SSE，100 事件/请求 | 16–17 QPS | **agent** 的 ≈1 700 事件/秒 |
| SSE，1 事件/请求 | ≈180–211 QPS | **gateway** 的 CPU（2 核） |
| 非流式，1 帧/请求 | ≈190–197 QPS | **gateway** 的 CPU（2 核） |

（上表为改造前的读数，客户端同为 k6、失败率另计；它的用途是**判断瓶颈在 agent 还是在
gateway**，不是给出"网关能跑多少"——那个数字看下面 200-口径的复测表。）

把负载降到"每请求 1 个事件"之后，瓶颈就干净地从 agent 移到了网关。阶梯实测（15s/档，客户端 k6 `VUS`，同时采三侧；QPS 为 k6 统计的**完成请求数**，失败率另列，因此与 200-口径一致）：

| 并发 | QPS | p50 | p95 | 失败 | gateway CPU | CPU/请求 | gateway 内存 | UDP 丢包增量 |
|---|---|---|---|---|---|---|---|---|
| 128 | 190.3 | 844ms | 880ms | 0.4% | 1.51 核 | 0.50ms | 58MB | 0 |
| 256 | 189.4 | 1.72s | 1.76s | 0.4% | 1.82 核 | 0.58ms | 59MB | 0 |
| 512 | 197.1 | 3.04s | 3.50s | 4.6% | **2.01 核** | 0.56ms | 61MB | 0 |

（流式 1 事件/请求同口径：512 并发 → **211.3 QPS**、p50 2.78s、gateway 2.14 核。）

四条判读：

- **QPS 不随并发增长（128→512 并发几乎不变），而延迟线性增长**（p50 844ms→3.04s）——这是排队饱和的典型特征，不是"还能加并发"。
- **（改造前的读数）gateway CPU 停在 2.0–2.3 核**，而云机 `nproc=2`、cgroup `cpu.max=max`（**没有配额限制**）、`nr_throttled=0`（没被节流）。当时看着像"算力打满"，2.1 核 ÷ 190 QPS ≈ **每请求 0.55–0.9ms CPU**；但下一节的剖析证明那不是算力用尽，而是每请求同步落库 + 全局锁争抢：**批量落库实施后，同样 2 vCPU 在 ≈500 QPS（200 占比 100%）时只用 0.149 核、0.30ms/请求**。
- **这次不是别人拖后腿**（并发采三侧）：agent **1.05 核**、上游 mock 0.31 核（都可忽略）；链路 0.3MB/s 且 **UDP 丢包增量为 0**。
- **改造前的实测上限 ≈190 QPS**（k6 口径、失败率列在上表；批量落库后为 ≈460–500 QPS，见下方云端复测）。

**为什么停在这里（已剖析）**：不是算力用尽，而是**每请求一次同步落库把网关串行化了**。本地全栈用 `sample` 剖析网关，热点不在 HTTP/QUIC，而在阻塞线程池里的 `KeyStore::persist_usage`——**13 951 / 13 965 个采样停在 `Mutex::lock()`**（真正执行 SQL 的只有 14 个），调用栈上全是 `sqlite3VdbeExec` / `syncJournal` / `unixSync` / `fsync`。在云机上取线程等待点更直接：

```
线程数 515；卡在 futex(等同一把 db 锁) 的线程 = 514 / 511 / 511 / 514 / 514 / 514
```

即**每请求 `spawn_blocking` 一次用量 UPSERT，全都要抢同一把全局 `db` 互斥锁**；改造前
云机上 515 个线程里有 514 个卡在 futex 等这把锁，"CPU 吃满 2 核"里很大一部分是线程争抢与
上下文切换。

> 这里**不引用**当时那组本机对照的绝对 QPS（934 → 15 744）：它用的是 `oha` 口径，含被算作
> 成功的 503，不可信。可信的对比用同一口径（只数 200）在云端做：
> **每请求 CPU 从 0.55–0.9ms（改造前，2.1 核 ÷ 190 QPS）降到 0.30ms（改造后，0.149 核 ÷ 496 QPS）**，
> 同一台 2 vCPU 机器上的吞吐从 ≈190 升到 ≈496。

**所以顺序是先修落库路径、再谈扩容**——不修的话加核/加实例也会在 190 QPS 附近走平，
因为瓶颈是串行化的写路径而不是核数。（那条写路径的剖析见下：热点全在阻塞线程池里抢同一把
`db` 互斥锁，与 HTTP/QUIC 无关。）

**云端复测（部署批量落库版之后，2 vCPU、每请求 1 事件）**：

> ⚠️ **作废声明**：本节历史上出现过一组 1 400 量级的 QPS，**已作废、不要在别处引用**。
> 原因是 `oha` 的 "Success rate" 只统计连接错误、**503 也算成功**，而那几档的 503 占比高达
> 92–95%——所谓"QPS"里绝大多数是被立即拒绝的请求。口径自此改为只数 `status="200"` 的增量
> 并同时给出 200 占比（即上面的 464 / 496）。

| 并发 | **真实 QPS（只数 200）** | 200 占比 | gateway CPU | CPU/成功请求 |
|---|---|---|---|---|
| 32 | **464** | **100%** | 0.161 核（8%） | 0.346ms |
| 192 | **496** | **100%** | 0.149 核（7.5%） | 0.300ms |
| 768 | 51–73 | 3.6–5.4% | 0.26 核（13%） | —（**修复前**读数：agent 侧心跳超时导致大面积 503，机制与修复见下） |

**结论**：可信的稳定吞吐是 **≈460–500 QPS（200 占比 100%）**，且此时网关只用 7–8% 的
CPU——**这 7–8% 就是关键**：上限不在网关算力，而在云服务器出口带宽（见下方《云出口带宽上限》；
496 × ~1 KB ≈ 4 Mbps ≈ 实测下行上限）。768 并发那一档**当时**不可用，原因也不在网关算力，而在
agent 侧心跳超时→主动断开→重连握手超时（**已修**，见下方《768 并发档》）。

#### 云出口带宽上限（实测 ≈0.40 MB/s）

**这是本节另一条同等重要的上限，与网关算力无关。** 2026-09-18 实测这台 ECS 的**下行**
（= 网关发给客户端的响应方向）被限在 **≈0.40 MB/s（3.2 Mbps）**，而上行是 79 Mbps：

| 测法 | 速率 |
|---|---|
| 云 ECS HTTP 直下 20MB | 0.44 MB/s |
| 云 ECS SSH/TCP 下 20MB（复测两次） | 0.40 MB/s |
| 经隧道 QUIC 大响应（256KB，单流） | 0.42 MB/s |
| 清华镜像 → 同一台 Mac（对照，绕开该 ECS） | 10.1 MB/s |

也就是说上面那个 **≈496 QPS 恰好等于带宽上限**（496 × ~1 KB 响应 ≈ 4 Mbps，与实测下行
3.2–3.6 Mbps 同量级），而不是网关算力的上限——两个数字必须一起看：**网关自己的容量远高于此，
是链路先到顶**。单流大响应实测（256 KB 走 616 ms）与这个上限吻合。

**排障时最容易踩的放大机制**：带宽饱和会被 `head_timeout`(15s) 放大成"隧道坏掉"——
响应头 15s 内到不了 → 摘除 agent → 连接被关 → agent 重连 → 期间注册表为空 → **全量 503**。

**实测 A/B（同参数、只改请求体大小，k6 的 `http_req_failed` 口径）**：

| | 请求体 16 B | 请求体 8 KB |
|---|---|---|
| 失败率 | **0.06%** | **48.97%** |
| 中位延迟 | 54.7 ms | 2.06 s |

8 KB 那档日志里全是 `upstream head timeout; evicting agent`。折算施加速率：每迭代 ≈28 KB
（请求 base64 后 body ≈11 KB + `/v1/echo` 把整包回吐 ≈15 KB + 流式端点 ≈2.5 KB）× 50 iters/s
≈ **1.4 MB/s**——**按载荷折算的估算值，不是直接采 `data_sent`**；对 0.4 MB/s 的上限就是
**超载约 3.5 倍**；16 B 那档 ≈150 KB/s，在上限之内。

同一组跑批里只改**单个** body 大小，得到同一条单调曲线（8 KB 那一档重复跑过两次：
48.16% 与 48.97%，属正常波动）：

| 请求体 | 1 KB | 4 KB | 8 KB | 16 KB | 64 KB |
|---|---|---|---|---|---|
| 失败率 | **0.00%** | 5.35% | **48.16%** | 76.53% | **98.38%** |

**两条触发路径**（决定验收怎么设计）：

1. **聚合超载**：`QPS × (请求字节 + 响应字节) > 0.4 MB/s` → 排队 → 上表那条曲线，**几 KB 就能复现**；
2. **单发超时**：`单请求字节 / 0.4 MB/s > head_timeout(15s)`，即**单请求 ≳ 6 MB** 时，
   哪怕只有 1 个并发也会 504 + 摘除（因为"读完才回"的上游，响应头要等上传完成）。

**所以验收负载必须按字节预算设计**：`QPS × (请求+响应字节) ≤ 0.4 MB/s`，
且单请求 ≲ 6 MB；否则测的是链路，不是网关。

**原因分两层，读的时候必须分开看**：

| 层 | 是什么 | 能不能用代码解决 |
|---|---|---|
| **链路层** | 云 ECS 出口 ≈0.40 MB/s，超出的字节必然来不及时 | ❌ 不能——只能调带宽，或减少字节（别整包回吐、压缩、把大请求拆小） |
| **网关行为层** | 响应头超时曾被**一律当成"隧道已死"**，于是把被链路堵住的 agent 摘掉 | ✅ **已修**（2026-09-18）：判据改成"这台 agent 最近还在正常回响应头吗"，见《"超时"不等于"已死"》。**修完链路饱和表现为若干 504，而不是全队 503** |

**网关那层的代码位置**（这就是"慢"如何变成"全队下线"的）：`proxy/mod.rs:530` 的响应头超时分支
**无条件**调 `registry.evict()`；而摘除计数与开流超时**共用**（`registry.rs:148` 的
`TUNNEL_TIMEOUTS_BEFORE_EVICT = 3`），且**只在收到响应头时清零**（`registry.rs:151` 的
`note_tunnel_op_ok`，唯一调用点 `proxy/mod.rs:507` 的 `HeadOutcome::Head` 分支）。
链路饱和时"一个响应头都收不到" → 计数必然涨到 3 → 摘除 + 关连接 → agent 重连期间注册表为空
→ **全量 503**。

**能修到什么程度**（已实施）：把"被堵住的慢"只回 504、**不计 strike、不摘除**（`registry::Entry::head_timeout_is_fatal`，
窗口 = `4 × head_timeout`）；只有窗口内一次响应头都没回来才算死。回归测试见
`tests/e2e/head_timeout.rs`（两条：慢但不死 → 不摘除；窗口内完全沉默 → 仍摘除）。

**链路那半决定"有多少请求做不完"，网关那半决定"做不完的请求是变成几个 504，还是把整队拖下线
变成全量 503"**——这次只修了后者：**不减字节就不提吞吐**，`QPS × 字节 > 0.4 MB/s` 时的 504 依旧存在。

**云端验证（2026-09-18 21:39，部署 `c7f298e` = PR #82）**：同一档（8 KB body、RATE=50、30 s、4 个 agent）
修前修后对照——

| | 修前 | 修后 |
|---|---|---|
| 失败率 | 48.97% | 41.55%（**全部是 504**） |
| `hlmg_upstream_head_timeouts_total{class="slow"}` | —（当时还没有这个指标） | **+924** |
| `class="silent"` | — | **0** |
| `hlmg_agent_connections_total`（被摘除会重连） | 反复重连 | **+0** |
| `agent_rejections_total{reason="registry-empty"}`（503 的成因） | **+3 753** | **+0** |
| 502 / 503 / 429 | 503 **+6 057** | **全 0** |
| 4 个 agent 各自的重连次数 | 13–15 次 | **全 0** |
| `integrity_mismatch` | 0 | **0** |

云端日志（只统计压测窗口，避免被部署前的历史行污染）：`still answering; not evicting` = 924、
`has been silent; evicting` = 0、`registry-empty` = 0、`agent evicted` = 0。
**同样超载，失败从"整队下线 → 全量 503"变成"924 个请求各自 504"。**

对照组（16 B body、同参数）：3 000 请求、失败 **0.00%**、中位 60.6 ms——字节量落在链路之内时一切正常，
反证 8 KB 那档的 504 是字节预算问题，不是网关行为问题。

#### 768 并发档：心跳零余量与重连风暴（机制已定位，代码已修）

**修复前的机制**（2026-09-17 定位到代码）：`crates/agent/src/lib.rs` 的 `heartbeat_loop` 给心跳回包
只留 **5s**，与 5s 心跳间隔等长、零余量；满负载下开流要抢连接级流管理器而超时 → 心跳任务返回 Err →
`run()` 的 `select!` 把"心跳结束"当致命 → **主动断开** → 重连又撞上 QUIC 默认 **10s 握手限时**
（`s2n-quic-core/src/connection/limits.rs` 的 `MAX_HANDSHAKE_DURATION_DEFAULT`）→ 固定 1s 重试形成
风暴。这期间网关注册表里没有健康 agent，`try_acquire` 全部过滤掉 → 每个请求 `503 "no edge available"`、`ttfb_ms=0`。

**已修的三处**（都可对着代码核）：

| 位置 | 改动 |
|---|---|
| agent 心跳（`agent/src/lib.rs`） | 回包等待改为 **`3 × interval`**（默认 15s，给排队留余量）+ **连续 2 次**失败才断开 |
| agent 握手（同上） | `with_max_handshake_duration(30s)`（原为默认 10s） |
| 网关摘除（`gateway/src/registry.rs`） | 需**连续 3 次**隧道操作超时；摘除时**延迟关闭**（等在途请求收尾，最多 5s） |

> ⚠️ **这一档（768 并发）在修复之后没有留下的可信读数**：本文不写"修好后 768 档是多少"，
> 因为那次复测的原始输出没有归档。表里 768 行的 **51–73 QPS / 3.6–5.4% 是修复前的旧读数**，
> 不能拿来判断今天；要判断就按同一口径（只数 `status="200"` + 记 200 占比）重跑一次。
> 这条缺口登记在 `TODO.md`。

**这两条可观测性就是那次定位的产物**（完整说明见《可观测性》，这里只留由来）：`hlmg_agents`
（注册条目数，含失联未关连接的）与 **`hlmg_agents_healthy`**（心跳未过期、真正可路由的）必须分开
暴露，否则"注册表里有 2 个 agent 但全部 stale"只能靠人肉推断；四种拒绝原因
（`registry-empty` / `all-candidates-stale` / `no-agent-serves-model` / `all-candidates-at-capacity`）
各自打 `warn` 日志，带 `registered` / `healthy` / `oldest_last_seen_secs`。

**今天先撞到的上限不是心跳，也不是网关算力**：依次是 **agent 的事件速率**（见《agent 每事件的 CPU 成本》）、
**云出口带宽**（≈0.4 MB/s，见上）、以及两类已处理掉的失败模式——开流排在 **QUIC 流额度**上
（`max_open_tunnel_streams`）与**客户端停滞占住准入槽位**（见《失败处理》）。心跳这条自此只作为
机制史料保留。

### 用量落库（每请求写库 → 按周期批量写）

用量（token / 请求数）落库在改造前是**每请求一次** `INSERT ... ON CONFLICT`，也就是上面那条把吞吐摁住的路径。现在改成：

- **热路径只做内存累加**（`UsageCollector::finish` → `KeyStore::accumulate_usage`），纳秒级、无 IO；
- **后台任务按周期（1s）批量落库**（`usage_flush::spawn` → `KeyStore::flush_usage_once`），一个事务里把有变化的 key 各写一行；
- **写的是绝对累计值而不是增量**：库里始终收敛到内存的真相，天然幂等、重启不会重复累加，也不存在"增量被取走但落库失败 ⇒ 永久少一段"的窗口；
- **关闭前强制落库**：`main` 收到 SIGTERM/SIGINT 后调用 `Gateway::shutdown()`——它先停 accept 并把在途请求排空（`shutdown_grace_secs`，默认 15s），**最后**把用量强制落库一次（有界阻塞写）再 abort 所有任务；日志会打 `usage flushed before shutdown keys=N`；
- 顺带开启 `journal_mode=WAL` + `synchronous=NORMAL`。

**触发条件是"时间"，不是"攒够多少条"**（`usage_flush.rs`）：

```rust
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);   // 每 1 秒 tick 一次
if !store.usage_has_pending() { continue; }                // 无变化 → 整轮跳过，连库锁都不拿
// 只写有变化的 key：
.filter(|(_, r)| force || !r.ever_flushed || r.current != r.flushed)
```

所以**不存在"流量太小、一直攒着不写"的状态**——阈值只决定"一轮写几个 key"，不决定"多久开始写"。三种边界：

| 情形 | 行为 |
|---|---|
| 零星流量 | 最迟 1 秒内落库 |
| 完全无流量 | `usage_has_pending()` 为 false，整轮跳过，**静默期零 IO** |
| 落库失败（磁盘满 / 锁冲突） | 事务未提交 ⇒ **不更新 `flushed` 标记** ⇒ 下一轮自动重试，不会丢 |

**内存语义**（两点要分清）：

- **不会积压增量**：内存里存的是"绝对累计值 + 已落库镜像"，不是待写队列。flush 之后 `current` 仍在（`/admin/usage` 直接读它，响应返回即一致），但库里已经是同一个值。
- **map 只增不减**：每个**用过的 key** 一个条目（约 150 字节），不做淘汰。线上 17 个 key ≈ 3KB，可忽略；但若频繁轮换 key（例如每请求一把新 key），它会随**累计用过的 key 数**线性增长（1 万 key ≈ 2MB）。这是有界但单调的增长，尚未做淘汰。

**崩溃窗口**（代价说清楚）：

| 事件 | 会丢多少用量 |
|---|---|
| 正常关闭（SIGTERM/SIGINT、systemd stop、Ctrl+C） | **已结算的用量 0 丢失**：先停 accept 并把在途排空（默认 15s 宽限），**最后**才强制 flush 再 abort；仍可能丢的只有"强制 flush 之后、进程退出之前"那一瞬 |
| `kill -9`（SIGKILL） | 最多 **1 秒** |
| 断电 / 宿主机崩溃 | 最多 1 秒，**且**可能丢最后一次提交（`synchronous=NORMAL` 抗进程崩溃、不抗断电） |

要"断电也不丢"就得改回 `synchronous=FULL`（每次提交 fsync 主库，云端实测 ≈3.5ms/次）。批量之后提交只有约 1 次/秒，这个代价不大——**需要更硬的持久性就把它调回去**。

`/admin/usage` 读的仍是内存计数，响应返回时立即一致，不受 flush 周期影响。

含义：**改造后单实例可信实测 ≈460–500 QPS，而网关只用 7–8% CPU——这个数字是云服务器出口带宽的上限，不是网关的上限**。网关自身容量更高的证据：本机起同一份代码的完整栈（loopback、无广域网瓶颈）时，8 个并发连接就能跑 **1 841 请求/秒**（16 B 响应体）与 **1 419 请求/秒**（8 KB 响应体），64 KB 响应单流只要 13.7ms。要探云端真实上限，先解决出口带宽与 agent 心跳/重连两件事。

真实 LLM 场景完全不受这个上限约束：`QPS ≈ 并发 ÷ 单请求耗时`，几秒级的单请求耗时会把
QPS 压到一两个数量级以下。上面这些数字只在"把模型换快"或"拿网关转发非 LLM 小请求"时才
有意义。

> 测法要点（缺一条数字就失真）：① 上游换**每请求 1 事件**的最小 mock，把 agent 的 1 700 事件/秒墙推开；② 云端放开闸门 `max_concurrent_requests: 5000`、`rate_limit_per_min: 0`（测完记得改回，见上一节的内存口径）；③ 压测客户端用 k6 而非 Python `requests`（后者 32 并发自己就先饱和了）；④ 每档同时读云端 cgroup 的 `cpu.stat`/`memory.current` 与 `nstat` 的 UDP 丢包增量。

### 可观测性

- **`GET /metrics`**：Prometheus 文本格式指标（按状态码计数、在途请求、在线 agent 数、转发字节、累计耗时），可直接被 Prometheus/Grafana 抓取
  - 浏览器直接访问（`Accept: text/html`）时返回 Dashboard 页面而非文本，便于点进指标页；Prometheus 抓取（`Accept: */*`）不受影响
  - `hlmg_quic_accepting`：隧道入口是否仍在接受新 agent（1/0）。UDP 驱动失效时入口会停止接受新连接，而进程与 HTTP 入口照常运行——**建议对该指标为 0 告警**（这是唯一能发现该故障的信号）
  - `hlmg_http_accept_errors_total`：公网入口 `accept()` 失败的累计次数（`EMFILE`/`ECONNABORTED` 一类**暂时性**错误）。入口现在**退避重试、不会退出**（退避 50ms 起翻倍、封顶 1s），所以这个数**持续增长**才是信号：说明 fd 长期不够用（先看下面《文件描述符上限》一节），而不是"入口挂了"。⚠️ 修复之前，**一次**这样的错误就会让入口永久停摆（进程、systemd、`/healthz` 全都正常，端口却不再接受连接）
  - **`hlmg_agents` 与 `hlmg_agents_healthy`**：前者是**注册条目数**（含心跳已过期、连接还没关的），
    后者是**心跳未过期、真正可路由**的数量。排查"所有请求 503"时只有后者能说明问题——
    `hlmg_agents=2` 而 `hlmg_agents_healthy=0` 意味着"有人注册，但全部不健康"，与"没人注册"完全不同
  - `hlmg_agent_rejections_total{reason=...}`：因挑不出可路由 agent 而拒绝的请求数，按原因分：
    `registry-empty`（没人注册）/ `all-candidates-stale`（有人但心跳全过期）/
    `no-agent-serves-model` / `all-candidates-at-capacity`。**503 的成因看这个，不要靠状态码猜**
  - `hlmg_tunnel_retries_total{outcome=...}`：因隧道建立失败而换 agent 重试的次数——
    `ok`（重试成功的**自愈**次数）/ `failed`（换了仍失败）/ `no-alternative`（没有别的 agent 可换）
  - `hlmg_client_stalls_total{phase="request-body"|"response-body"}`：因客户端**停滞**而主动放弃的
    请求数（读不动请求体 / 不消费响应体）。**它是准入槽位泄漏的直接告警**：修好之前这类停滞
    不留任何痕迹，只表现为 `hlmg_active_requests` 只增不减
  - `hlmg_upstream_head_timeouts_total{class="slow"|"silent"}`：响应头超过 `head_timeout_secs` 的次数，
    `slow` = 窗口内有过成功响应头（被堵住的慢，**回 504 但不摘除**）、`silent` = 窗口内一次都没回来
    （计入连续超时，够 3 次就摘除）。**它回答的是"该扩容还是该查网络"**：`slow` 陡增通常是链路/上游慢
  - `hlmg_tunnel_open_timeouts_total{class=...}`：开流超过 `tunnel_op_secs` 的次数，按判定分——
    `busy`（在途已顶到承载上限，**背压**，不摘除，改换 agent 或 429）/ `dead`（没到上限却开不出流，
    坏连接，摘除）。**`busy` 陡增 = 该扩容或调 agent 的 `max_concurrency`；`dead` 陡增才是隧道/网络故障**
  - `hlmg_key_verify_hits_total` / `hlmg_key_verify_misses_total`：key 校验命中已验证缓存 / **真正跑了 argon2**的次数。misses 的**增量**就是内存与 CPU 的风险信号（一次 miss 峰值 +19MiB，见《并发上限与内存》），稳态下应接近 0；突然上涨说明凭据被吊销/新增，或缓存容量 `verified_cache_max` 不够。⚠️ **`verified_cache_max: 0` 时这两个计数器恒为 0**（走的是不走缓存的旧路径，两个数都不加）——看到 0 要先确认缓存是否被关掉，别当成"没有校验"
- **结构化日志**：`tracing`，每个请求带 `request_id` / 状态码 / 耗时（`tower-http` TraceLayer）
- **`/healthz`**：存活探针（⚠️ 仍恒返 `ok`，不做深度检查；但**豁免并发闸门**——闸门打满时探针也 200，否则 LB 摘除会把"慢"放大成"全挂"。见 `REBUILD.md` §5.3）

> 注意：`/metrics` 未加认证，公网部署建议在安全组中仅对监控网段放行。

### 多平台打包与开机自启

```bash
scripts/build-release.sh          # 构建已安装 target 的 release 二进制并打包到 dist/
rustup target add aarch64-unknown-linux-gnu   # 需要交叉目标时先安装
```

产物：`dist/home-llm-gateway-<版本>-<平台>.tar.gz`（gateway / agent / mock-llm 三个二进制）。
macOS 交叉编译到 Linux 的说明见脚本头部注释；推荐 musl 目标得到静态二进制。

systemd 单元：`deploy/gateway.service`（云服务器）、`deploy/agent.service`（LLM 机器），改好参数后 `systemctl enable --now` 即可开机自启。

### 文件描述符上限（为什么网关要自己抬）

**现象**：并发一高，客户端开始零星 `connection reset by peer`，而网关 `/healthz` 正常、
CPU/内存都不高；网关日志里是 `accept error: Too many open files (os error 24)`。
实测（2026-09-17，云端 2 vCPU）日志里这种错误有 296 次，全部落在压测窗口内。

> 注：那 296 次错误发生在**明文入口还在用 `axum::serve`** 的时期——它记一行日志后继续接受连接，
> 所以网关没有真的停摆。2026-09-18 `55c56f1`（为写超时把明文入口也换成自研循环）之后那点容错丢了，
> HTTPS 入口则从最初就是 `listener.accept().await?`：**一次** `EMFILE` 就会结束整个 accept 循环
> （进程活着、systemd active、日志一行 warn，端口再不通）。现在两条入口合并成同一个循环并带退避重试，
> 见 `hlmg_http_accept_errors_total` 与 `crates/gateway/src/http/entry.rs`。

**成因**：进程的 `RLIMIT_NOFILE` 有 soft（运行时实际强制执行，用满即 `EMFILE`）与 hard
（soft 允许抬到的天花板）两个值。`gateway.service` 没设 `LimitNOFILE`，于是吃 systemd 的
全局默认 —— `/proc/<pid>/limits` 显示 `Max open files 1024 524288`。1024 不是内核限制
（`fs.nr_open` 是 1048576，同机 `cron` 也是 1024，`sshd` 则自己抬到了 1048576），
而实测 768 个并发客户端连接时网关 fd 峰值就有 **785**，默认值在生产水位上是贴脸的。

**处理**：网关启动时（绑任何 socket 之前）自己把 soft 抬到 `min(hard, 16384)`
（`gateway/src/nofile.rs`）。任何进程都能在 hard 以内抬自己的 soft，不需要特权；
失败只记 WARN 不阻止启动。另有一道**业务级**的水位：公网入口的并发连接数上限
`max_entry_connections`（默认 1024，0 = 不限）——它把"半开连接能吃多少 fd"从一个进程级天花板
收成一个明确的数字，满额时暂停 accept、新连接在内核 backlog 排队（见《客户端停滞》）。
启动日志会留一行，便于事后核对：

```
INFO gateway::nofile: raised NOFILE soft limit from=1024 to=16384 hard=524288 target=16384 limited_by_hard=false
```

**为什么不抬到 hard（云端是 524288）**：上限给到几十万，等于把"fd 泄漏"的引爆点从**本进程的
`EMFILE`**（止损范围一个进程、日志直接可见）推到**整机的 `fs.file-max`/内存**（拖垮同机其他
服务、现场更难还原）。16384 已是实测水位的约 20 倍，够用且代价不外溢。

**unit 里还要不要写 `LimitNOFILE`**：可选。两者分工是"unit 定 hard（真正天花板），代码抬 soft"。
如果想让天花板更高（例如要跑 2000+ 并发连接），在 unit 里加 `LimitNOFILE=65536` 即可——
**不写也不会再撞那个 1024**。反过来若 unit 把 hard 压到 1024 以下，代码也只能抬到 hard，
日志里 `limited_by_hard=true` 就是在提示这件事。

## API Key 管理（Admin API）

网关内置轻量管理接口，可**运行时签发 / 吊销 key，无需重启网关**：

- **网页管理页**：浏览器打开 `http://<网关地址>/` 即进入管理界面——输入 admin token 后可直接**创建 / 吊销 / 列出 key**
- 配置项 `admin_token`（`gateway-config.yml`）：管理口令（与 API Key 相互独立），提供后启用 `/admin/*` 与页面中的管理功能
- 配置项 `keys_file`：动态 key 持久化数据库文件（SQLite，默认 `keys.db`），重启后依然有效；**只存 argon2 哈希，明文仅创建时返回一次**；文件权限由网关在打开时收紧为 `0600`
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

- [`DESIGN.md`](DESIGN.md)：架构设计、帧协议细节、里程碑
- [`EXACTLY_ONCE.md`](EXACTLY_ONCE.md)：**提案**——让"响应头超时"也能安全重试所需的协议级去重
  （全局唯一 `request_uid` + agent 侧去重表），含取舍、内存边界与不解决的问题
