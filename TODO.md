# home-llm-gateway TODO

> 基于实际代码审查与需求梳理（2026-08），按优先级排列。状态：未实现，仅规划。

## P0 — 工具接入（DSH / Codex / Claude Code 直连）

背景：cloud-gateway 需作为 DeepSeek Harness、Codex CLI、Claude Code 等工具的 LLM 后端。
当前已实现：OpenAI chat-completions 形态（`/v1/chat/completions`、`/v1/models`、SSE、Bearer 认证）、
客户端断开/超时 → Cancel 上游（不白算 token）。缺口如下。

- [ ] **实机验证链路**：本地起 gateway + mock-llm，用 curl 模拟 DSH/Codex 打全流程
      （`/v1/models`、流式 chat、中途断开触发 Cancel），确认工具可直接连；
      顺带确认 `/v1/models` 返回的上游模型名与工具端 `--model` 配置的对应关系
- [ ] **`/v1/responses`（OpenAI Responses API，Codex 新版）**：
      方案 A：网关内把 Responses 请求翻译为上游 chat/completions（含流式事件格式转换）；
      方案 B：确认上游（vLLM 等）原生支持后仅文档化。当前为纯透传，上游不支持即 404
- [ ] **`/v1/messages`（Anthropic Messages API，Claude Code）**：
      方案 A：网关内 OpenAI↔Anthropic 双向格式翻译（含 SSE 事件转换，中等工作量）；
      方案 B：文档化前置 claude-code-router / LiteLLM 翻译层的部署方式
- [ ] **接入文档**：README/DEPLOY 增加 DSH（`DEEPSEEK_BASE_URL`）、Codex（`OPENAI_BASE_URL`）、
      Claude Code（`ANTHROPIC_BASE_URL` 或 router）的配置示例与模型名约定

## P1 — 运维与健壮性

- [ ] **进程级优雅关闭**：gateway/agent 注册 SIGTERM/SIGINT（`tokio::signal`），收到后打 INFO 日志
      → 调用 `Gateway::shutdown()` / `Agent::shutdown()` 干净退出；
      覆盖 systemd stop、Ctrl+C、harness job_kill 场景。当前 `pending().await` 永久挂起，信号直接杀进程
- [ ] **UDP 被封时的 TCP+TLS fallback**（DESIGN.md §10）：帧协议不变，仅替换 QUIC 传输层
- [ ] **健康上报驱动的更精细路由**（DESIGN.md §9 M4 待办）：当前按在途请求数最少路由，
      后续可结合 agent 心跳上报的延迟/队列深度
- [ ] **Grafana 仪表盘模板**（DESIGN.md §9 M4 待办）：消费 `/metrics` 指标
- [ ] **keys.db 迁移规模化**：当前自动迁移（`keystore.rs::migrate_legacy_keys`）同步执行、
      全量读入内存 + 单一大事务——仅适合小数据量 / 个人 / 小团队（适用边界见 DEPLOY.md §10）。
      改进：① **分批流式**：cursor 每批 ~500 条、小事务提交、内存有界（低成本，建议先做）；
      ② **独立离线迁移命令** `gateway migrate-keys`：维护窗口运行，运行时零负担，天然支持分批；
      ③ 大数据量场景启动时只提示"建议离线迁移"，不做自动同步迁移。

## P2 — 测试与质量

- [ ] **覆盖率 96.9% → 99%**：剩余 ~62 行主要是 serve_https 监听失败、axum::serve 停止等
      防御性错误路径（可注入故障测试）
- [ ] **keys.json 保护**：部署时文件权限 600、定期备份/恢复演练（含明文密钥安全说明）
- [ ] **/admin/* 暴露面收敛**：安全组只放行管理网段（README 已提示，可补部署脚本/检查项）
