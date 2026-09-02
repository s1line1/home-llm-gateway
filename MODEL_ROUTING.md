# home-llm-gateway — Edge 定位与模型路由方案（2026-09 定稿）

> 项目定位从"家庭网关"升级为 **Edge LLM 网关**：统一公网入口接入多台边缘节点（edge），
> 每台 edge 声明异构模型能力，网关按请求 model 做调度。家庭部署是第一个实例（单 edge）。
> 状态：**方案定稿；模型路由已按三阶段实施完成（2026-09）**。

---

## 1. 定位重述

- **项目 = Edge LLM 网关**：客户端（任何地方）→ 公网入口 → 路由到能服务目标模型的 edge → 本地 LLM。
- 现有命名保留（cloud-gateway / edge-agent），仅升级语义与文档表述。
- 此定位下**按模型路由是核心调度能力**，不是可选增强。

## 2. 现状盘点（代码事实）

| 环节 | 现状 | 实施后 |
|---|---|---|
| agent 模型声明 | `AgentConfig.models`（默认 `["*"]`）→ Register 帧 → `registry.Entry.models`——全链路已有 | 同左 |
| 路由消费模型 | **无**：`try_acquire` 只看健康 + inflight 最少，模型完全不参与 | ✅ 按 model 过滤候选 + 精确优先 |
| `/v1/models` | 无特殊路由 → 透传给某台 agent → 返回单台上游的模型列表（异构多 edge 时语义错误） | ✅ 网关聚合健康 edge 声明（认证+限流同代理层） |
| 模型不匹配 | 请求发错 edge → 上游 404/报错，网关无感知 | ✅ 无 edge 可服务 → 404 `model not found` |

## 3. 目标设计（实施后语义）

### 3.1 请求侧：解析 model

`http_proxy::proxy` 认证后、选 agent 前，从 body 提取顶层 `model` 字段
（`serde_json::from_slice` 全量解析；请求体通常几 KB，相对隧道/网络开销可忽略）：

- body 无 `model` → **400** `model is required`（OpenAI 语义；所有主流客户端必带）✅
- model 非字符串 → 400 ✅

### 3.2 路由侧：按模型过滤候选

`try_acquire(stale_after, model)`（registry.rs）：

```
候选 = 健康 agent 且 (models 含 "*" 或 models 含 model)
排序 = 精确声明该模型者优先 → 同组内 inflight 最少 → 心跳最新
```

- **通配语义（决策点 1，已定）**：`models: ["*"]` = 全匹配/兜底。✅ 精确声明优先于通配，
  精确 edge 容量打满后才回落到通配 edge（通配不抢单）。
- **无 model（决策点 2，已定）**：body 无 `model` → 严格 **400**。✅
- 无健康 agent → `NoAgent` → 503；有健康 agent 但均不能服务 → `NoModel` → **404**。✅

### 3.3 `/v1/models`：网关聚合（不再透传）

遍历健康 edge 的 `Entry.models` 去重并集，返回 OpenAI 格式（带与代理入口同级的
Bearer 认证 + 限流）；`["*"]` 不贡献条目。✅

### 3.4 模型 id 对齐（三档，本轮只做档 1）

| 档 | 机制 | 状态 |
|---|---|---|
| 1（本轮） | **直配**：客户端 model 填 edge 声明的真实模型名 | ✅ 已实施 |
| 2（后续） | **重写映射**：网关维护 `client_alias → edge_model`（OpenRouter 风格，如 `gpt-5-codex` → `qwen2.5`） | 未做 |
| 3（不做） | 纯透传（现状） | — |

## 4. 改动清单（已完成）

| # | 文件 | 改动 |
|---|---|---|
| 1 | `crates/gateway/src/registry.rs` | `try_acquire(stale_after, model)`；模型过滤候选；精确优先排序；`AcquireError::NoModel`；`healthy_models()` 聚合辅助 |
| 2 | `crates/gateway/src/http_proxy.rs` | `extract_model`；`auth_and_rate_limit` 公共认证限流；proxy 用 model 调 try_acquire；NoModel→404 |
| 3 | `crates/gateway/src/http.rs` | `/v1/models` 静态路由（优先于 `/v1/{*rest}`）；`models_route` 聚合 + 认证限流 |
| 4 | `crates/agent/src/config.rs` + `agent_config.example.yml` | `models` 字段语义注释更新（edge 能力声明、`*` 兜底） |
| 5 | 测试 | 单测：模型匹配/精确优先/通配兜底/回落/无 model 400/healthy_models；e2e：双 edge 异构模型路由 + 聚合 + 通配兜底 + 400 |

**不需要改**：proto 帧协议、agent 转发逻辑、Register/Heartbeat（model 在请求 body 里透传）。

## 5. 实施分步（已完成）

1. **阶段 1（路由核心）**：registry + http_proxy 改动 + 单测 ✅
2. **阶段 2（/v1/models 聚合）**：http.rs 路由 + handler + 单测 ✅
3. **阶段 3（回归 + 文档）**：e2e 双 edge 异构场景 + README/DESIGN/TODO 更新 ✅

## 6. 明确本轮不做（防蔓延）

- 客户端 model → edge model **重写映射**（档 2）
- edge 模型**热插拔增量上报**（模型变更需 agent 重连重新 Register；heartbeat 不刷新 models）
- 多租户 / quota / 地域 / 成本调度
- 大 body 流式 model 提取微优化
