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
sudo mkdir -p /etc/home-llm-gateway/certs
# 二进制（方案 A 构建后在 home-llm-gateway/target/release/ 下，方案 B 解包 dist/）
sudo cp target/release/gateway /usr/local/bin/gateway
# 证书
sudo cp server.crt server.key ca.crt /etc/home-llm-gateway/certs/
sudo chmod 600 /etc/home-llm-gateway/certs/server.key
# Web UI（可选）：本机构建后把产物整个上传（含 index.html + assets/）
#   cd web && pnpm install && pnpm build
#   scp -r web/dist <服务器>:/etc/home-llm-gateway/web
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

# 4) 看日志（日志落盘到文件，见 deploy/gateway.service 的 StandardOutput；
#    也可 journalctl -u gateway -f 看 systemd 侧）
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
ui_dir: web                        # Web UI 目录（§4 上传的 web/dist；相对 WorkingDirectory，
                                   # 省略 = `/` 显示构建提示页，API 不受影响）
```

> 网关**没有静态 key**——所有 API key 都通过 Admin API 运行时创建并存入 SQLite（首次启动先用 `admin_token` 创建第一个 key）。

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
curl -k https://127.0.0.1:8443/healthz            # → ok
curl -k https://127.0.0.1:8443/v1/models           # → 401（还没 agent，但说明认证生效）
```

## 6. 部署 agent + LLM（LLM 机器）

先装好 LLM 服务并本地验证（以 Ollama 为例）：

```bash
curl -s http://127.0.0.1:11434/v1/models          # 本机确认 OpenAI 兼容接口正常
```

安装 agent（同样放二进制 + 证书，注意用**该机器自己那份** client 证书）：

```bash
sudo mkdir -p /opt/home-llm-gateway/certs
sudo cp agent ca.crt client-edge1.crt client-edge1.key /opt/home-llm-gateway/certs/
# 目录里只有 agent 二进制 + 证书

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
> agent 把"被踢"当干净断开、把退避重置回 500ms，于是两台机器每 ~500ms 互踢一次、永不收敛——
> **凡活得比踢连接周期长的请求全部失败（502）**，而两侧进程都健康、`/admin/agents` 恒显示
> "1 个 agent 在线"，只有 `hlmg_agent_connections_total` 在飞涨。详见 `TODO.md` P1。

```bash
# deploy/agent.service 只负责 --config 指向配置文件
sudo mkdir -p /var/log/home-llm-gateway
sudo cp deploy/agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now agent

# 看到 connected to cloud gateway / registered with cloud gateway 即成功
sudo tail -f /var/log/home-llm-gateway/agent.log
```

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
| 浏览器打开 8443 显示"尚未构建"提示页 | 未上传 web/dist（§4）或 gateway-config.yml 未配 `ui_dir`；API 不受影响，可后补 UI 再 `systemctl restart gateway` |
| edge 侧 IP 变了连不上 | 用域名 SAN 证书 + `server_name` 填域名，配 DDNS 指向新 IP |

## 9. 部署后安全清单（必做）

- [ ] `ca.key` 只在本地，未上传到任何服务器
- [ ] 第一个 API Key 由 Admin API 创建（明文只显示一次），未使用可猜测的名字/弱口令
- [ ] `admin_token` 用独立强随机串（配置文件 `admin_token`）；`/admin/*` 在安全组中仅对管理网段开放
- [ ] 每台 LLM 机器的 `agent_id` 唯一（见 §6 警告）
- [ ] 安全组仅放行所需端口（22 限制来源 IP）
- [ ] `/metrics` 未加认证：安全组中仅对监控网段放行，或后续给 metrics 加鉴权
- [ ] server.key / client.key / keys.db 权限 `chmod 600`
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
仓库里已有 `Dockerfile`（多阶段，产出 gateway / agent / mock-llm 三个二进制）和
`docker-compose.yml`（网关；agent 的模板注释在文件末尾）。

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
| **A. 同路径挂载**（推荐） | `-v /etc/home-llm-gateway:/etc/home-llm-gateway` | **零改动**，示例配置原样可用 |
| **B. 挂到 `/config`** | `-v /etc/home-llm-gateway:/config` | 必须把 cert/key/ca 改成 `/config/...`、`keys_file` 改成 `/config/keys.db` |

⚠️ 两者混用是最常见的启动失败：容器内会报读不到证书/密钥（`cert/key/ca paths are required`
之后是文件读取失败）。**挂载点了，配置里的路径就得跟着走**，反之亦然。

### 11.3 三个必须知道的坑

1. **命令行里不要再写 `gateway` / `agent`**：镜像的 ENTRYPOINT 已经是 gateway 二进制，而 CLI
   只接受 `--config`（没有子命令、没有位置参数）。多写那一个词会被 clap 判成
   `unexpected argument 'gateway' found` 并以**退出码 2** 立刻退出，配 `restart` 就是崩溃重启循环。
2. **同一个镜像跑 agent 必须切 entrypoint**：加 `--entrypoint /usr/local/bin/agent`
   （mock-llm 同理），否则跑起来的仍然是网关。
3. **`keys.db` 是 SQLite WAL 模式**：会额外生成 `keys.db-wal` / `keys.db-shm`，所以必须挂
   **目录**（不能只挂那个文件），而且**目录**要可写；SELinux 主机上可能还要加 `:z` / `:Z`。

### 11.4 端口与安全组

| 端口 | 协议 | 用途 |
|---|---|---|
| 8443 | TCP | HTTP/HTTPS 入口（`listen_addr`），客户端与 Web UI 走这里 |
| 4433 | **UDP** | QUIC 隧道（`quic_addr`），agent 拨号走这里 |

- 写成 `-p 4433:4433`（漏掉 `/udp`）会映射成 TCP，**agent 永远连不上**；
- 云安全组要放行 **UDP 4433**（只放 TCP 是常见错误），见 §2；
- 网关不需要 `--network host`，发布端口即可；agent 那一侧常配 host 网络（它要连本机 LLM）。

### 11.5 容器化的两个能力缺口

- **配置不支持环境变量展开**（`config.rs` 里没有任何 env 取值），所以 `admin_token` 只能写在
  `gateway-config.yml` 里。该文件因此属于密钥：`chmod 600`、不要 `COPY` 进镜像、用只读挂载。
- **镜像里没有 `web/dist`**：容器内访问 `/` 只会看到"UI 未构建"的提示页。要用管理面板，就在构建
  镜像时把前端一并打进去，或在 compose 里把 `web/dist` 挂进去并调整 `ui_dir`。已登记在 `TODO.md`。

### 11.6 用 docker compose

```bash
docker compose config -q          # 只校验配置，不起容器
docker compose up -d gateway
docker compose logs -f gateway    # 日志走 stdout（没有日志文件配置项）
```
