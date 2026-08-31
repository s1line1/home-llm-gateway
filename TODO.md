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
- [ ] **多 CA 信任根 + 动态增删（每 agent 独立 CA，gateway 不停机）**：
      目标：每个 agent 用独立 CA 签发证书，gateway 维护全部 CA 的信任根集合；
      运行时热添加/移除单个 CA——移除即吊销该 CA 下所有 agent（新连接被拒，
      已建立连接不受影响，其他 agent 零影响）；重启后动态配置不丢。
      **设计要点（已定稿）**：
      1. 新模块 `ca_store.rs`：`TrustStore { cas: RwLock<HashMap<指纹, TrustedCa>>, roots: RwLock<RootCertStore> }`，
         指纹 = sha256(cert DER) 十六进制（标识/防重/吊销定位）；add/remove 同步更新 roots
      2. 自定义 rustls `ClientCertVerifier`（参考官方 dynamic-certs 示例）：verify_client_cert 时
         读 TrustStore 当前信任根验证——每次握手走最新信任根；quinn Endpoint 构建一次，无需重建
      3. Admin API（受 admin_token 保护，与 /admin/keys 同层）：
         `GET /admin/ca` 列表；`POST /admin/ca {pem, name}` 添加（校验 X.509、≤64KB、
         重复指纹 409、非法 400 → 201）；`DELETE /admin/ca/{fp}` 移除（204/404）；
         可选 `POST /admin/ca/{fp}/disable` 禁用不删除
      4. 持久化：SQLite 新表 `trust_cas(fingerprint PK, name, pem, added_at, enabled)`，
         写穿模式（复用 keystore）；启动时加载全部 CA
      5. 兼容性：现有 `ca:` 配置文件 = 初始信任根（行为不变），动态 CA 走 API
      6. 测试：单测（指纹/add/list/remove/409/持久化 roundtrip）；
         e2e：① 双 CA 双 agent 接入 → DELETE 其一 → 该 agent 重连被拒（agent_count 回落）
         另一 agent 不受影响；② POST 新 CA → 新 agent 热接入；③ 重启后动态 CA 仍生效
      7. 分步：TrustStore+verifier → Admin API → SQLite 持久化 → e2e + 文档
         （README/DEPLOY/DESIGN 安全章节更新：每 agent 独立 CA 的管理模型与吊销语义）
- [ ] **UDP 被封时的 TCP+TLS fallback**（DESIGN.md §10）：帧协议不变，仅替换 QUIC 传输层
- [ ] **per-API-key token 用量计量**：
      目标：按 API key 统计 token 消耗（prompt/completion/total + 请求数 + 最后使用时间），
      Admin API 可查询、Keys 页展示；吊销 key 后用量记录仍保留（可审计）。
      **设计要点（已定稿）**：
      1. 数据来源：网关透传层提取上游响应的 `usage` 字段（OpenAI 兼容：非流式 JSON 里有；
         流式在最后一个 chunk 通常带 usage）；上游无 usage 时降级为估算（字符数/4，中文按字符），
         数据标记估算来源
      2. 流式性能：SSE 逐块转发时**先 `contains("usage")` 字符串预过滤**，命中才 JSON 解析，
         避免每块全量解析（99% chunk 零开销）；取消/断流请求按已转发字节估算 completion
      3. 存储：keys.db 新表 `key_usage(key_id PK, prompt_tokens, completion_tokens,
         total_tokens, requests, last_used_at)`；热路径内存
         `RwLock<HashMap<key_id, Mutex<Usage>>>`（AtomicU64 无锁累加），每请求结束写穿 SQLite；
         高并发再优化为 spawn_blocking/批量 flush（见 keys.db 迁移条目）
      4. API/UI：`GET /admin/usage` 每 key 用量汇总；`GET /admin/keys` 响应可选带 usage；
         Keys 页加用量列；`POST /admin/usage/reset` 留后期
      5. 范围：本次只做**计量**（统计+查询+展示）；配额/超限拒绝（key 设 quota 超限 429）
         明确排除，留到多租户阶段（DESIGN.md §11.3 两级限流）
      6. 测试：单测（非流式 JSON usage 提取、流式 usage chunk 提取、无 usage 估算降级、
         并发累加正确性）；e2e（打请求后 /admin/usage 与 mock-llm 返回的 usage 一致、
         吊销后记录仍可查）
      7. 分步：usage 提取模块（透传层挂钩）→ 内存累加 + SQLite 持久化 →
         /admin/usage + Keys 页展示 → e2e + 文档
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

## P3 — 协议层改造（postcard → protobuf）

> 前置判断：**只有动机是"跨语言互操作 / 生态标准化"才值得做**；postcard 在性能和简单性上仍更优
> （小帧更快更小，64KiB body 序列化 ~2 GiB/s 已是 memcpy 级）。若仅为协议演进，
> postcard 加字段本身也向后兼容（serde 忽略未知字段）。

- [ ] **隧道帧协议 postcard → protobuf**：
      目标：`Frame` 枚举 8 种帧改用 protobuf 编解码，获得跨语言互操作与显式 .proto schema。
      **设计要点（已定稿）**：
      1. 选型：**prost**（prost + prost-build + protoc，build.rs 编译期生成）；备选 rust-protobuf（免 protoc）
      2. Schema：`Frame { oneof kind { register=1 ... error=8 } }` + 各 message（字段编号见设计文档）；
         长度前缀 framing 不变（`[u32 大端长度][protobuf 字节]`）
      3. **关键设计：内部 Frame 枚举保留，只换编解码层**——`io.rs` 的 write_frame/read_frame
         签名不变，gateway/agent 调用方几乎零改动；tests 重写
      4. 迁移策略：一次性切换 + **版本校验**（版本号 0.2.0；Register.version 已存在，
         gateway 拒绝 <0.2.0 的 agent，避免双端不同步静默解析失败）；不做双协议共存
      5. 性能门槛：bench 双实现对比（postcard vs protobuf）——若回退超预期（>3x）停下重新评估；
         预期小帧慢 1.5-2x（tag 开销）、大 body 接近持平
      6. 构建影响：+prost 依赖、.proto 文件、protoc（CI/交叉编译需安装，文档化）
      7. 测试：proto roundtrip（8 帧/边界）+ 全量 e2e 回归 + bench 对比报告
      8. 分步：schema+prost 接入 → io.rs 切换+单测 → bench 双实现对比（决策门槛）→
         全量回归 → 版本 0.2.0+校验 → 文档（DESIGN §4.2、部署同版本升级说明）
