# 阿里云 / 公网部署清单（Step-by-Step）

> 目标：把 `home-llm-gateway` 跑在公网上——中转网关放阿里云 ECS，agent 放 LLM 所在机器（家里或另一台云主机），任何地点通过 HTTPS 访问家里的模型服务。
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
LLM 机器（家里 / 另一台云主机）  agent → 本地 Ollama / vLLM / llama.cpp
```

## 0. 准备

| 项 | 说明 |
|---|---|
| 阿里云 ECS（中转网关） | 规格 **2C4G** 起步（纯转发，内存占用几十 MB）；系统 Ubuntu 22.04 / Debian 12 / Alibaba Cloud Linux |
| LLM 机器 | 家里机器（NAT 后也可以，agent 是出站连接）；若 LLM 也放云上，按模型选 GPU/高配机型 |
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
  -keyout client-home1.key -out client-home1.csr -subj "/CN=home-agent-1"
cat > client.ext <<EOF
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -in client-home1.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client-home1.crt -days 825 -extfile client.ext
# 有第二台就再签一份 client-home2
```

分发：`ca.crt` 给两端；`server.crt/server.key` 给中转服务器；`client-home1.crt/client-home1.key` 给对应 agent 机器。

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
sudo mkdir -p /opt/home-llm-gateway/certs
# 二进制（方案 A 构建后在 home-llm-gateway/target/release/ 下，方案 B 解包 dist/）
sudo cp target/release/gateway /opt/home-llm-gateway/
# 证书
sudo cp server.crt server.key ca.crt /opt/home-llm-gateway/certs/
sudo chmod 600 /opt/home-llm-gateway/certs/server.key
```

## 5. 部署网关（中转服务器）

```bash
# 1) 生成强随机 API Key 与 Admin Token
openssl rand -hex 32        # API Key（记下来，客户端要用）
openssl rand -hex 32        # Admin Token

# 2) 基于模板生成网关配置（所有参数都在这里）
sudo cp gateway_config.example.yml /etc/home-llm-gateway/config.yml
sudo vi /etc/home-llm-gateway/config.yml

# 3) 安装并启动（systemd 单元只负责 --config 指向配置文件）
sudo cp deploy/gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gateway

# 4) 看日志
sudo journalctl -u gateway -f
```

`config.yml` 关键参数（按需修改，完整示例见 `gateway_config.example.yml`）：

```yaml
listen_addr: "0.0.0.0:8443"        # HTTPS API 入口
quic_addr: "0.0.0.0:4433"          # QUIC 隧道（UDP）
tls_cert / tls_key                 # 公网 HTTPS 证书（server.crt/server.key）
cert / key / ca                    # QUIC 隧道证书（同 server 证书 + ca.crt）
admin_token: <强随机串>             # Admin API 口令（必配；用它创建第一个 API key）
keys_file: /etc/home-llm-gateway/keys.db   # 动态 key 持久化数据库（SQLite，默认 keys.db）
rate_limit_per_min: 60             # 每个 Key 每分钟上限
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
sudo cp agent ca.crt client-home1.crt client-home1.key /opt/home-llm-gateway/certs/
# 目录里只有 agent 二进制 + 证书

# 编辑 deploy/agent.service：
#   --cloud-addr  <公网IP>:4433
#   --server-name <与网关 server 证书 SAN 一致的域名或 IP>   ← 关键！不一致会 TLS 握手失败
#   --upstream    http://127.0.0.1:11434
sudo cp deploy/agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now agent

# 看到 connected to cloud gateway 即成功
sudo journalctl -u agent -f
```

## 7. 端到端验证（从任意地点）

```bash
# 模型列表（应返回真实模型）
curl -k -H "Authorization: Bearer <你的key>" https://<公网IP>:8443/v1/models

# 流式对话
curl -N -k -H "Authorization: Bearer <你的key>" \
  https://<公网IP>:8443/v1/chat/completions \
  -d '{"model":"<模型名>","stream":true,"messages":[{"role":"user","content":"你好"}]}'
```

想要免 `-k`：把 `ca.crt` 装进客户端系统信任库（macOS 钥匙串 / 浏览器 / `SSL_CERT_FILE` 环境变量）。

## 8. 常见问题排查

| 现象 | 排查 |
|---|---|
| agent 日志：连接失败 / 一直重试 | ① 安全组 UDP 4433 是否放行；② 家里路由器是否封出站 UDP（少见）；③ `nc -u -vz <IP> 4433` 测连通 |
| agent：TLS 握手失败 | `--server-name` 与网关 server 证书 SAN 不匹配；确认填的是 SAN 里的域名或公网 IP |
| 网关日志：agent connected 但很快消失 | agent 心跳被断（网络不稳）；检查 UDP 丢包；`--agent-stale-secs` 适当调大 |
| curl 返回 401 | API Key 不对或没带 `Authorization: Bearer` |
| curl 返回 503 | 网关没注册到健康 agent（看网关/agent 日志） |
| curl 返回 429 | 限流超了（等下一分钟）或 agent 并发占满 |
| 家里 IP 变了连不上 | 用域名 SAN 证书 + `--server-name` 填域名，配 DDNS 指向新 IP |

## 9. 部署后安全清单（必做）

- [ ] `ca.key` 只在本地，未上传到任何服务器
- [ ] API Key 用 `openssl rand -hex 32` 生成，未用弱密码
- [ ] `--admin-token` 用独立强随机串；`/admin/*` 在安全组中仅对管理网段开放
- [ ] 安全组仅放行所需端口（22 限制来源 IP）
- [ ] `/metrics` 未加认证：安全组中仅对监控网段放行，或后续给 metrics 加鉴权
- [ ] server.key / client.key / keys.db 权限 `chmod 600`
- [ ] 证书到期前重签轮换（825 天），记录到期时间
