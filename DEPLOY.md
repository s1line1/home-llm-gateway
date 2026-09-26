# 阿里云 / 公网部署清单（Step-by-Step）

> 目标：把 Edge LLM 网关（cloud-gateway + edge-agent）跑在公网上——中转网关放阿里云 ECS，agent 放 LLM 所在机器（edge 节点：家里 / 分支 / 云主机），任何地点通过 HTTPS 按 model 访问边缘模型服务。
>
> 阅读前提：已按 `README.md` 在本地跑通全链路（mock 或真实模型）。

## 架构回顾

```
客户端（任何地方）
   │  https://<公网IP>:8443/v1/...   （API Key）
   ▼
阿里云 ECS（中转网关）  gateway：HTTPS 8443 + QUIC UDP 4433
   │  QUIC（UDP 4433，mTLS）← agent 主动拨出
   ▼
edge 节点（家里 / 分支 / 云主机）  agent → 本地 Ollama / vLLM / llama.cpp
```

## 0. 准备

| 项 | 说明 |
|---|---|
| 阿里云 ECS（中转网关） | 规格 **2C4G** 起步（纯转发，内存占用几十 MB）；系统 Ubuntu 22.04 / Debian 12 / Alibaba Cloud Linux |
| LLM 机器（edge 节点） | 家里机器（NAT 后也可以，agent 是出站连接）；或分支/云主机；若多 edge 异构模型，网关按 model 路由 |
| 域名（可选但推荐） | 有域名则证书 SAN 用 `DNS:`，IP 变更不影响；没有就用 `IP:` SAN 的自签证书 |
| 本地 | 仓库已 clone（或 `dist/` 里有现成二进制） |

## 1. 生成生产证书（最关键的一步）

开发脚本 `certs/gen-dev.sh` 的 server 证书 SAN 只有 `localhost/127.0.0.1`，**生产必须换成你的公网 IP 或域名**。在自己电脑上执行：

```bash
mkdir -p prod-certs && cd prod-certs

# 1) CA（只生成一次；ca.key 永远留在自己手里，绝不上服务器）
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout ca.key -out ca.crt -days 3650 -subj "/CN=HomeLLM CA"

# 2) 网关服务端证书（SAN 填你的公网 IP 或域名，二者可都填）
openssl req -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr -subj "/CN=gw"
cat > server.ext <<EOF
subjectAltName=DNS:llm.example.com,IP:1.2.3.4
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 -extfile server.ext

# 3) 每台 LLM 机器单独签发一个客户端证书（mTLS）
openssl req -newkey rsa:2048 -nodes \
  -keyout client-edge1.key -out client-edge1.csr -subj "/CN=edge-agent-1"
cat > client.ext <<EOF
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -in client-edge1.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client-edge1.crt -days 825 -extfile client.ext
# 有第二台就再签一份 client-edge2（CN 同名无害，agent_id 才是身份标识）
```

分发：`ca.crt` 给两端；`server.crt/server.key` 给中转服务器；`client-edge1.crt/client-edge1.key` 给对应 agent 机器。

> **证书轮换**：825 天有效期，到期前重签替换即可（重签后重启服务）。
> 不建议用 Let's Encrypt：90 天自动续期需要给 rustls 热重载证书，个人项目自签更省事。

## 2. 安全组 + 防火墙

阿里云控制台 → ECS 实例 → 安全组 → 入方向规则：

| 协议/端口 | 用途 | 来源 |
|---|---|---|
| TCP 22 | SSH | 你的 IP |
| **UDP 4433** | QUIC 隧道（agent 拨入） | 0.0.0.0/0 |
| **TCP 8443** | HTTPS API 入口 | 0.0.0.0/0 |

ECS 上的系统防火墙（`ufw` / `firewalld`）也需放行，或直接用安全组并关闭系统防火墙：

```bash
sudo ufw allow 8443/tcp && sudo ufw allow 4433/udp && sudo ufw enable
```

## 3. 编译二进制

### 方案 A：云上直接构建（最省事，推荐）

```bash
# 中转服务器上
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
# 国内网络建议配 crates 镜像（rsproxy.cn / tuna），加快下载
git clone git@github.com:s1line1/home-llm-gateway.git
cd home-llm-gateway
cargo build --release            # 产出 target/release/{gateway,agent,mock-llm}
```

### 方案 B：本机交叉编译后上传

```bash
./scripts/build-release.sh       # 已安装的 target 会构建；未安装的按提示 rustup target add
# macOS → Linux 需要交叉链接器，见脚本头部注释；推荐 musl 目标出静态二进制
# 产物：dist/home-llm-gateway-<版本>-<平台>.tar.gz
```

## 4. 目录规划（中转服务器）

```bash
sudo mkdir -p /etc/home-llm-gateway
# 二进制（方案 A 构建后在 home-llm-gateway/target/release/ 下，方案 B 解包 dist/）
sudo cp target/release/gateway /usr/local/bin/gateway
# 证书：**直接放配置目录**——`gateway_config.example.yml` 里的 cert/key/ca 就是
# /etc/home-llm-gateway/{server.crt,server.key,ca.crt}（没有 certs/ 子目录，别自建一层，
# 否则示例配置"零改动"启动时读不到证书）
sudo cp server.crt server.key ca.crt /etc/home-llm-gateway/
sudo chmod 600 /etc/home-llm-gateway/server.key
# Web UI（可选）：本机构建后把产物整个上传（含 index.html + assets/）。
# ⚠️ **层次要和配置里的 ui_dir 对齐**：下面保持 `web/dist/` 这一层，对应 ui_dir: web/dist
#   cd web && pnpm install && pnpm build
#   ssh <服务器> 'sudo mkdir -p /etc/home-llm-gateway/web/dist'
#   scp -r web/dist/* <服务器>:/etc/home-llm-gateway/web/dist/
# （另一种常见写法是 `scp -r web/dist <服务器>:/etc/home-llm-gateway/web` —— scp 会把目录**改名**
#   成 `web`，产物落在 `…/web/` 下少一层，那时 `ui_dir` 要写 `web` 而不是 `web/dist`。
#   两种都由你定，但**配置必须和实际层次一致**，否则 `/` 只显示"UI 未构建"的占位页。）
```

## 5. 部署网关（中转服务器）

```bash
# 1) 生成强随机 Admin Token（网关没有静态 API Key，key 一律由 Admin API 运行时创建）
openssl rand -hex 32        # Admin Token（记下来，登录管理页 / 调 /admin/* 用）

# 2) 基于模板生成网关配置（所有参数都在这里）
sudo cp gateway_config.example.yml /etc/home-llm-gateway/gateway-config.yml
sudo vi /etc/home-llm-gateway/gateway-config.yml

# 3) 安装并启动（systemd 单元只负责 --config 指向配置文件）
sudo mkdir -p /var/log/home-llm-gateway
sudo cp deploy/gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gateway

# 4) 看日志（deploy/gateway.service 的 StandardOutput/StandardError 把应用日志**落盘**，
#    所以 journalctl -u gateway 里只有 systemd 自己的启停消息，没有网关日志）
sudo tail -f /var/log/home-llm-gateway/gateway.log
```

`gateway-config.yml` 关键参数（按需修改，完整示例见 `gateway_config.example.yml`）：

```yaml
listen_addr: "0.0.0.0:8443"        # HTTPS API 入口
quic_addr: "0.0.0.0:4433"          # QUIC 隧道（UDP）
tls_cert / tls_key                 # 公网 HTTPS 证书（server.crt/server.key）
cert / key / ca                    # QUIC 隧道证书（同 server 证书 + ca.crt）
admin_token: <强随机串>             # Admin API 口令（必配；用它创建第一个 API key）
keys_file: /etc/home-llm-gateway/keys.db   # 动态 key 持久化数据库（SQLite，默认 keys.db）
rate_limit_per_min: 60             # 每个 Key 每分钟上限
ui_dir: web/dist                   # Web UI 目录（§4 上传的产物；相对 WorkingDirectory，
                                   # 所以要带 `web/dist` 这一层——层次必须与实际目录一致）
                                   # ⚠️ 原生部署**必须显式写**：不写时的默认值是**镜像内**的
                                   # /usr/local/share/home-llm-gateway/web（给容器用的绝对路径）。
                                   # 目录里没有可用产物时 `/` 显示构建提示页，API 不受影响
```

> 网关**没有静态 key**——所有 API key 都通过 Admin API 运行时创建并存入 SQLite（首次启动先用 `admin_token` 创建第一个 key）。

> **关闭信号**：`SIGTERM` / `SIGINT` / **`SIGHUP`** 走**同一条**优雅关闭路径（停接入 → 排空在途 → 有界强制落库），日志会先打一行 `shutdown signals armed (SIGINT/SIGTERM/SIGHUP)`。`SIGHUP` **不是**"重载配置"：本单元没有 `ExecReload`，配置热重载也不在范围内（`OPTIMIZATION.md` A4），`systemctl reload gateway` 会直接报不支持——想换配置就 `restart`。

**运行时签发 API Key**（不用重启网关）：

```bash
curl -X POST http://127.0.0.1:8443/admin/keys \
  -H "Authorization: Bearer <admin-token>" -H "Content-Type: application/json" \
  -d '{"name":"dsh-client"}'
# 返回 {"id":...,"key":"sk-...","name":...}，key 只显示这一次，记下来
curl http://127.0.0.1:8443/admin/keys -H "Authorization: Bearer <admin-token>"   # 列出（脱敏）
curl -X DELETE http://127.0.0.1:8443/admin/keys/<id> -H "Authorization: Bearer <admin-token>"  # 吊销
```

**本机自检**：

```bash
curl -k https://127.0.0.1:8443/healthz            # → {"status":"ok","tunnel_entry":"accepting","agents":{...}}
                                                  #   隧道入口停摆时是 503 + status=degraded（处置：重启网关）
curl -k https://127.0.0.1:8443/v1/models           # → 401（还没 agent，但说明认证生效）
```

## 6. 部署 agent + LLM（LLM 机器）

先装好 LLM 服务并本地验证（以 Ollama 为例）：

```bash
curl -s http://127.0.0.1:11434/v1/models          # 本机确认 OpenAI 兼容接口正常
```

安装 agent（同样放二进制 + 证书，注意用**该机器自己那份** client 证书）：

```bash
sudo mkdir -p /etc/home-llm-gateway
# 二进制（agent.service 的 ExecStart 是 /usr/local/bin/agent）
sudo cp target/release/agent /usr/local/bin/agent
# 证书：与 agent_config.example.yml 的路径一致（/etc/home-llm-gateway/{ca.crt,client.crt,client.key}）
sudo cp ca.crt /etc/home-llm-gateway/ca.crt
sudo cp client-edge1.crt /etc/home-llm-gateway/client.crt
sudo cp client-edge1.key /etc/home-llm-gateway/client.key
sudo chmod 600 /etc/home-llm-gateway/client.key

# 基于 agent_config.example.yml 生成 agent 配置：
#   cloud_addr: <公网IP>:4433
#   server_name: <与网关 server 证书 SAN 一致的域名或 IP>   ← 关键！不一致会 TLS 握手失败
#   agent_id: <每台机器唯一！>                              ← 关键！同名会让两台机器互踢（见下方警告）
#   upstream: http://127.0.0.1:11434
sudo cp agent_config.example.yml /etc/home-llm-gateway/agent-config.yml
sudo vi /etc/home-llm-gateway/agent-config.yml
```

> ⚠️ **`agent_id` 必须每台机器唯一**：`agent_config.example.yml` 与 `Makefile` 生成的默认值都是
> `edge-1`，**多台机器直接照抄就会撞车**。同名时网关会关掉旧连接（本意是同一台机器重连接管），
> 两台机器于是轮流接管——**凡活得比接管周期长的请求都可能失败（502）**，而两侧进程都健康、
> `/admin/agents` 恒显示"1 个 agent 在线"，信号只有 `hlmg_agent_connections_total` 在飞涨。
> **2026-09-22 起 agent 侧那半边已修**：退避不再被"连上就被踢"重置回 500ms（改看会话存活时长，
> 短命会话继续指数退避 + ±20% 抖动），所以不再退化成"每 ~500ms 互踢、永不收敛"的风暴；
> 但网关侧"同名接管"仍是当前语义，**多台机器依然要各用各的 `agent_id`**。详见 `TODO.md` 与
> `docs/PROJECT_SCAN.md` 的 P2-1。

```bash
# deploy/agent.service 只负责 --config 指向配置文件
sudo mkdir -p /var/log/home-llm-gateway
sudo cp deploy/agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now agent

# 看到 connected to cloud gateway / registered with cloud gateway 即成功
sudo tail -f /var/log/home-llm-gateway/agent.log
```

> agent 侧的关闭信号与网关同款：`SIGTERM` / `SIGINT` / `SIGHUP` 都走 `agent.shutdown()`。

## 7. 端到端验证（从任意地点）

```bash
# 模型列表（应返回真实模型）
curl -k -H "Authorization: Bearer <你的key>" https://<公网IP>:8443/v1/models

# 流式对话
curl -N -k -H "Authorization: Bearer <你的key>" \
  https://<公网IP>:8443/v1/chat/completions \
  -d '{"model":"<模型名>","stream":true,"messages":[{"role":"user","content":"你好"}]}'

# Web 管理面板（§4 已上传 web/dist 时）：浏览器打开 https://<公网IP>:8443/
# 用 admin_token 登录后即可创建 / 吊销 API Key、查看 agent 状态与指标
```

想要免 `-k`：把 `ca.crt` 装进客户端系统信任库（macOS 钥匙串 / 浏览器 / `SSL_CERT_FILE` 环境变量）。

## 8. 常见问题排查

| 现象 | 排查 |
|---|---|
| agent 日志：连接失败 / 一直重试 | ① 安全组 UDP 4433 是否放行；② edge 侧网络是否封出站 UDP（少见）；③ `nc -u -vz <IP> 4433` 测连通 |
| agent：TLS 握手失败 | 配置项 `server_name` 与网关 server 证书 SAN 不匹配；确认填的是 SAN 里的域名或公网 IP |
| 网关日志：agent connected 但很快消失 | agent 心跳被断（网络不稳）；检查 UDP 丢包；`agent_stale_secs`（网关配置）适当调大 |
| **请求大面积 502/超时，`/admin/agents` 恒显示 1 个 agent，`hlmg_agent_connections_total` 飞涨** | **两台机器 `agent_id` 撞车**（见 §6 警告）：改配置里任一方的 `agent_id` 为唯一值后重启该 agent |
| curl 返回 401 | API Key 不对或没带 `Authorization: Bearer` |
| curl 返回 503 | 网关没注册到健康 agent（看网关/agent 日志） |
| curl 返回 429 | 限流超了（等下一分钟）或 agent 并发占满 |
| **大请求体（≥1 MB）或大响应吞吐上不去、成片 504** | **云服务器的出口带宽上限**：实测该 ECS 出口 ≈0.40 MB/s（3.2 Mbps），`QPS × (请求字节+响应字节)` 超了就排队；并发大请求还会按 `1/N` 摊薄每条可用速率，于是 15 s 的 `head_timeout` 先到 ⇒ 504（日志是 `… still answering; not evicting`）。**这不是网关缺陷**：先按字节预算设计负载，或把带宽调上去；判据与实测表见 `README.md`《云出口带宽上限》《请求体阶梯复测》 |
| 浏览器打开 8443 显示"尚未构建"提示页 | **systemd/原生部署**：`ui_dir` 指向的目录里没有可用产物——没构建、没上传（§4）、只上传了源码目录，或者**根本没写 `ui_dir`**（此时默认值是镜像内路径 `/usr/local/share/home-llm-gateway/web`，宿主上不存在 ⇒ 原生部署必须显式写）；**容器部署**：镜像自带产物、默认就能用，出现本页说明产物不在镜像里，或配置把 `ui_dir` 覆盖成了宿主路径（§11.5）。两种情况都是**非致命降级**，API 不受影响，改完重启即可（容器 `docker compose up -d`） |
| edge 侧 IP 变了连不上 | 用域名 SAN 证书 + `server_name` 填域名，配 DDNS 指向新 IP |

## 9. 部署后安全清单（必做）

- [ ] `ca.key` 只在本地，未上传到任何服务器
- [ ] 第一个 API Key 由 Admin API 创建（明文只显示一次），未使用可猜测的名字/弱口令
- [ ] `admin_token` 用独立强随机串（配置文件 `admin_token`）；`/admin/*` 在安全组中仅对管理网段开放
- [ ] 每台 LLM 机器的 `agent_id` 唯一（见 §6 警告）
- [ ] 安全组仅放行所需端口（22 限制来源 IP）
- [ ] `/metrics` 未加认证：安全组中仅对监控网段放行，或后续给 metrics 加鉴权
- [ ] server.key / client.key 权限 `chmod 600`（`keys.db` 由网关启动时自动收紧为 0600，可用 `stat -c %a keys.db` 复核）
- [ ] 证书到期前重签轮换（825 天），记录到期时间

## 10. 升级说明（旧版 keys.db 自动迁移）

**适用场景**：个人 / 小团队 / key 数量小（个位到几十个），且不介意极端情况下重新签发 key 的部署。
从早期版本（argon2 哈希改造 `6691b5d` 之前，API key 以**明文**存在 SQLite）升级时，
网关启动会自动把旧库迁移到 argon2 哈希存储，**无需手工操作**：

1. 启动时检测到表缺 `lookup` 列（旧 schema）即触发迁移
2. 读取旧明文 key → 重新计算 `lookup`（sha256）+ `key_hash`（argon2）
3. 事务内重建新 schema 表 → 删除旧表 → `VACUUM` 重写文件，清除磁盘上旧明文残留
4. 迁移成功日志：`migrated legacy plaintext keys to argon2 hashes count=N`；
   旧 key 迁移后**继续可用，无需重新签发**；已是新 schema 的库零开销跳过

**边界与风险（重要）**：

- 迁移是**同步执行**的，耗时与 key 数量成正比（每个 key 的 argon2 约 10-30ms）——海量 key 会阻塞网关启动
- 迁移一次性读入全部旧记录，并使用单一大事务——数据量极大时内存峰值高、失败整体回滚
- 因此**该自动迁移仅适合小数据量 / 个人 / 小团队、不介意极端情况下重新发 key 的场景**；
  大规模生产升级请先备份 `keys.db`，改用离线迁移工具（演进方案见 `TODO.md` P1「keys.db 迁移规模化」），
  不要依赖启动时的自动迁移
- 无论量级，升级前都建议 `cp keys.db keys.db.bak` 备份；迁移是幂等的，失败后可安全重试

**上面是"明文 → argon2"的大迁移。另有一次轻量迁移**（已验证身份缓存引入时新增 `api_keys.cred_version` 列）：
启动时检查该列是否存在，缺则 `ALTER TABLE ... ADD COLUMN cred_version INTEGER NOT NULL DEFAULT 1`，
**只加列、不重建表、不重算哈希，旧 key 全部继续可用**。升级后建议确认一下：

```bash
sqlite3 /etc/home-llm-gateway/keys.db "PRAGMA table_info(api_keys);"   # 应含 cred_version
curl -s localhost:8080/metrics | grep -E 'hlmg_key_verify_(hits|misses)_total'
# 稳态下 hits 快速累积、misses 几乎不动（每个不同 token 只付一次 argon2）
```

## 11. Docker 部署（可选）

§4–§6 的 systemd 路径是默认方案；本节只讲**容器化时路径与端口怎么映射**，以及三个会让人卡住的坑。
部署用的镜像是 **`crates/gateway/Dockerfile`**（多阶段：Rust 阶段只产出 gateway，前端阶段把
Dashboard 编进镜像），**上下文必须是仓库根**：

```bash
docker build -f crates/gateway/Dockerfile -t home-llm-gateway .
# 或者在 crate 目录里（等价，上下文仍然是仓库根）：
#   cd crates/gateway && docker build -f Dockerfile -t home-llm-gateway ../..
# 或直接 compose（仓库里只有这一份 compose）：
#   docker compose -f crates/gateway/docker-compose.yml build
```

镜像里**只有 gateway + Dashboard**（没有 agent / mock-llm）。agent 按 §6 用 systemd +
`deploy/agent.service` 部署；要容器化 agent 得另写一份 Dockerfile（本仓库不再提供 agent 镜像）。

### 11.1 一条硬规则：配置里的路径按「进程 CWD」解析

`gateway/src/config.rs` 的 `from_path` 只把 YAML 读进来交给 `from_file`，**不会**把里面的路径
重写成"相对配置文件所在目录"。所以 `cert` / `key` / `ca` / `keys_file` / `ui_dir` 全部由操作系统
按**进程的工作目录**解析。

- systemd 那份之所以能用相对路径（`ui_dir: web/dist`、`keys_file: keys.db`），靠的是单元里的
  `WorkingDirectory=/etc/home-llm-gateway`；
- 镜像里已补 `WORKDIR /etc/home-llm-gateway`，语义与之一致。

### 11.2 挂载点必须与配置里的路径对齐（二选一）

`gateway_config.example.yml` 和 `agent_config.example.yml` 用的都是绝对路径
`/etc/home-llm-gateway/...`，所以：

| 方案 | 挂载 | 配置文件 |
|---|---|---|
| **A. 同路径挂载**（推荐） | `-v /etc/home-llm-gateway:/etc/home-llm-gateway` | **零改动**，示例配置原样可用（`ui_dir` 是唯一例外，见 §11.5） |
| **B. 挂到 `/config`** | `-v /etc/home-llm-gateway:/config` | 必须把 cert/key/ca 改成 `/config/...`、`keys_file` 改成 `/config/keys.db` |

⚠️ 两者混用是最常见的启动失败：容器内会报读不到证书/密钥（`cert/key/ca paths are required`
之后是文件读取失败）。**挂载点了，配置里的路径就得跟着走**，反之亦然。

### 11.3 三个必须知道的坑

1. **命令行里不要再写 `gateway` / `agent`**：镜像的 ENTRYPOINT 已经是 gateway 二进制，而 CLI
   只接受 `--config`（没有子命令、没有位置参数）。多写那一个词会被 clap 判成
   `unexpected argument 'gateway' found` 并以**退出码 2** 立刻退出，配 `restart` 就是崩溃重启循环。
2. **部署镜像里没有 agent**：`crates/gateway/Dockerfile` 只 `--bin gateway`，所以
   `entrypoint: ["/usr/local/bin/agent"]` 会直接 "no such file or directory"。agent 按 §6 用
   systemd + `deploy/agent.service` 部署；确实要容器化就另写一份 Dockerfile（照该文件的结构，
   多一个 `--bin agent` 与一次 COPY）——本仓库不再提供 agent 镜像。
3. **`keys.db` 是 SQLite WAL 模式**：会额外生成 `keys.db-wal` / `keys.db-shm`，所以必须挂
   **目录**（不能只挂那个文件），而且**目录**要可写；SELinux 主机上可能还要加 `:z` / `:Z`。
   三个文件的权限由网关启动时收紧为 `0600`：主库与**已经存在**的 `-wal`/`-shm` 都会被显式
   `chmod`（侧车平时是 0600 只是继承主库的 mode，所以拷贝/迁移来的旧库要专门收一遍；本次
   复扫 C2-1 正是漏在这里）。

### 11.4 端口与安全组

| 端口 | 协议 | 用途 |
|---|---|---|
| 8443 | TCP | HTTP/HTTPS 入口（`listen_addr`），客户端与 Web UI 走这里 |
| 4433 | **UDP** | QUIC 隧道（`quic_addr`），agent 拨号走这里 |

- 写成 `-p 4433:4433`（漏掉 `/udp`）会映射成 TCP，**agent 永远连不上**；
- 云安全组要放行 **UDP 4433**（只放 TCP 是常见错误），见 §2；
- 网关不需要 `--network host`，发布端口即可；agent 那一侧常配 host 网络（它要连本机 LLM）。

### 11.5 容器化的两个注意点（其一的缺口已补）

- **配置不支持环境变量展开**（`config.rs` 里没有任何 env 取值），所以 `admin_token` 只能写在
  `gateway-config.yml` 里。该文件因此属于密钥：`chmod 600`、不要 `COPY` 进镜像、用只读挂载。
- ~~镜像里没有 `web/dist`~~ **2026-09-24 已补**：Dashboard 由 `crates/gateway/Dockerfile` 的
  `web-builder` 阶段
  **在镜像内构建**（`pnpm install --frozen-lockfile` + `pnpm build`，末尾照样跑
  `scripts/check-bundle.mjs` 那道产物泄漏守卫——它红了整次构建就失败），产物在
  `/usr/local/share/home-llm-gateway/web`；运行镜像里**不带 Node**，只多一份静态产物。

  **容器部署什么都不用配**：`ui_dir` 不写时的默认值就是上面那个镜像内路径
  （`config.rs` 的 `default_ui_dir()`）——不构建、不挂载、不加配置项，起来就有 Dashboard。
  有配置就用配置（例如你想换成自己挂进去的一套产物，照常写 `ui_dir:` 覆盖）。

  **从老部署升级**：`docker compose -f crates/gateway/docker-compose.yml build && docker compose
  -f crates/gateway/docker-compose.yml up -d`（`-f` 不能省，仓库根已经没有 compose 文件了：裸
  `docker compose build` 会报 `no configuration file provided`；见 §11.6），然后**删掉配置里的
  `ui_dir` 那一行**（如果它指向宿主上那份 `web/dist` —— 现在镜像自带、且更省事），
  再把宿主上的 `web/` 目录删掉。不删配置也能跑，只是还在用你挂的那份。

  为什么默认值必须是**绝对路径**、而且不能放在 `/etc/home-llm-gateway/web`：容器里 `ui_dir`
  的相对路径按**进程 CWD**（`/etc/home-llm-gateway`，见 §11.1）解析，而那是配置/证书/`keys.db`
  的挂载点 —— 镜像里放那儿的东西会被宿主目录**遮住**，`/` 照样是"UI 未构建"（`ui.rs` 的启动期
  判定会打 warn，浏览器看到占位页）。所以产物放挂载点之外，默认值也指向那里；代价是**原生部署
  必须显式写 `ui_dir`**（默认值是给镜像用的）。

### 11.6 用 docker compose

```bash
# compose 文件在 crates/gateway/ 下 ⇒ 用 -f 指它（或先 cd 进去，两条等价）
docker compose -f crates/gateway/docker-compose.yml build   # 先编 Rust（release）再编前端，然后打包运行镜像
docker compose -f crates/gateway/docker-compose.yml config -q   # 只校验配置，不起容器
docker compose -f crates/gateway/docker-compose.yml up -d gateway
# 日志：compose 的 command 把 stdout 重定向到了 /var/log/home-llm-gateway/gateway.log，
# 所以 `docker compose logs -f gateway` 是**空的**（容器 stdout 没有内容）——直接看那个文件：
sudo tail -f /var/log/home-llm-gateway/gateway.log
```

前端阶段的可调 build-arg（都有默认值，见 `crates/gateway/Dockerfile`）：`NPM_MIRROR`（默认
npmmirror，`--build-arg NPM_MIRROR=` 则用官方源）、`PNPM_VERSION`（默认 `10`，与 CI 的
`pnpm/action-setup` 同一主版本——`--frozen-lockfile` 要求 pnpm 原样接受这份锁文件，跟随 CI
就等于跟着一个有持续验证的组合）。基础镜像是 `node:22-bookworm-slim`（同样对齐 CI 的
`setup-node node-version: 22`）。
