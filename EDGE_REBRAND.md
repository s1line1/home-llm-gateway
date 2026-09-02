# home-llm-gateway — Edge 定位术语统一方案（2026-09 定稿）

> 项目定位已从"家庭网关"升级为 **Edge LLM 网关**（家庭是首个实例，见 MODEL_ROUTING.md）。
> 代码与文档中仍残留"家庭 / 家里 / 家端 / home-*"术语，本方案统一为 edge 语义。
> 状态：**方案定稿，实施完成（2026-09）**。

---

## 1. 原则

- **只改表述，不改行为**：协议、路由、指标、配置结构零变更。
- **标识符保持稳定**：仓库名、目录名、二进制名、metrics 前缀、systemd 目录、既有 agent_id
  是部署/观测锚点，改了会造成破坏（Prometheus 断档、云端迁移），**不改**。
- 用户可见文案（`--help`、日志、API 错误、Web UI）优先改——那是定位的直接表达。

## 2. 改动清单（按层分级）

### 第一层：运行时代码文案（用户可见，需重新编译）

| 文件 | 现状 | 改为 |
|---|---|---|
| `crates/gateway/src/main.rs:13` | `cloud-gateway: 家庭 LLM 远程访问网关（公网入口 + QUIC 隧道服务端）` | `cloud-gateway: Edge LLM 网关（公网入口 + QUIC 隧道服务端）` |
| `crates/gateway/src/http_proxy.rs:91` | API 错误 `no home agent available` | `no edge available`（客户端可见） |
| `crates/gateway/src/quic.rs:31` | 日志 `home agent connected` | `edge connected` |
| `crates/agent/src/main.rs:13` | `home-agent: 常驻 LLM 所在机器，通过 QUIC 隧道接入云端网关` | `edge-agent: 常驻 LLM 所在机器（edge），通过 QUIC 隧道接入云端网关` |
| `crates/agent/src/lib.rs:1` | 模块注释 `home-agent：常驻家里...` | edge-agent 表述 |

### 第二层：代码注释（内部，随手统一）

| 文件 | 位置 |
|---|---|
| `crates/proto/src/frame.rs:1` | "网关与家端 agent 之间" → "网关与 edge-agent 之间" |
| `crates/gateway/src/registry.rs:1` | "家端 agent 注册表" → "edge-agent 注册表" |
| `crates/gateway/src/quic.rs:1` | "接受家端 agent 连接" → "接受 edge-agent 连接" |
| `crates/gateway/src/tls.rs:15` | "校验家端 agent 的客户端证书" → "校验 edge-agent" |
| `crates/gateway/src/keystore/mod.rs:14` | "家庭网关低 QPS 下" → "edge 网关低 QPS 下" |
| `crates/agent/src/config.rs:52` | `default_agent_id()` 返回 `home-agent-1` → `edge-1`（**仅默认值**；已有配置不受影响） |

### 第三层：Web UI 文案（需重建 web/dist）

| 文件 | 现状 | 改为 |
|---|---|---|
| `web/index.html:6` | `<title>Home LLM Gateway</title>` | `<title>Edge LLM Gateway</title>` |
| `web/src/components/Layout.tsx:39` | "家庭 LLM 远程访问网关" | "Edge LLM 网关" |
| `web/src/pages/Agents.tsx:77` | "家端 edge-agent 在线状态与并发负载" | "edge-agent 在线状态与并发负载" |

### 第四层：文档（README/DESIGN/DEPLOY/TODO 等）

| 文件 | 处数 | 说明 |
|---|---|---|
| `DEPLOY.md` | ~21 | 部署心智"家庭"→"edge 节点（家庭是其一）"；路径 `/etc/home-llm-gateway/` 保留不改 |
| `DESIGN.md` | ~14 | 与 §1 已改的定位呼应，正文举例统一 |
| `README.md` | ~11 | 已改过头部，正文/多 agent 段残留补完 |
| `README.en.md` | ~6 | 同步英文 |
| `CODE_READING.md` | 1 | 顺手 |
| `OPTIMIZATION.md` | 1 | 顺手 |
| `MODEL_ROUTING.md` | 3 | 内部引用，保留仓库名即可 |
| `TODO.md` | 1 | 顺手 |
| `certs/gen-dev.sh` / `scripts/build-release.sh` / `deploy/*.service` / `*.example.yml` | 少量注释 | 注释统一；**产物名/路径/配置键不改** |

## 3. 明确不改（部署/观测锚点，防破坏）

- git remote 与 GitHub 仓库名 `home-llm-gateway`
- 本地工作目录名
- `dist/` 打包产物名 `home-llm-gateway-*.tar.gz`（0.2.0 发布时可一并评估）
- metrics 前缀 `hlmg_*`（Prometheus 断档）
- `/etc/home-llm-gateway/` systemd 部署目录
- 用户真实配置 `agent_id: home-2`（标识符）

## 4. 影响与验证

- **零逻辑变更**：不涉及协议帧、路由、配置结构、指标名；无新测试。
- 回归：现有 85 测试应全绿（cargo test --workspace）+ fmt/clippy。
- Web：改 3 处文案后重建 `web/dist`，CI web job 通过即可。

## 5. 实施顺序

1. 第一层（代码文案）+ 第二层（注释）——一个 commit
2. 第三层（Web UI）+ 重建 dist —— 并入同一 commit 或独立
3. 第四层（文档）——并入或独立 commit，随你定粒度
