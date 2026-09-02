# home-llm-gateway TODO

> 基于实际代码审查与需求梳理（2026-08），按优先级排列。状态：未实现，仅规划。

## P0 — 工具接入（DSH / Codex / Claude Code 直连）

背景：cloud-gateway 需作为 DeepSeek Harness、Codex CLI、Claude Code 等工具的 LLM 后端。
当前已实现：OpenAI chat-completions 形态（`/v1/chat/completions`、`/v1/models`、SSE、Bearer 认证）、
客户端断开/超时 → Cancel 上游（不白算 token）。缺口如下。

- [x] **模型路由（Edge 定位，见 MODEL_ROUTING.md，2026-09 实施）**：
      网关按请求 body 的 model 字段，在**能服务该模型的健康 edge** 中挑最少负载者
      （同模型内均衡）；`models: ["*"]` 全匹配；无 model → 400；模型无人能服务 → 404；
      `/v1/models` 改为网关聚合所有健康 edge 的显式声明模型（不再透传单台上游）。
      双 edge 异构模型 e2e 覆盖（路由正确性、聚合列表、404、400）
- [x] **实机验证链路（生产拓扑，2026-09 实测）**：云端启动 gateway，本地 edge 节点跑
      mock-llm + agent 拨号接入；**DSH/Codex 真实客户端** base_url 指向云端，**流式对话打通**
      （认证 → 模型路由 → 隧道 → 上游 → SSE 回传 [DONE]），确认工具可直接连。
      后续可选补：`/v1/models` 与工具端 `--model` 的对应关系文档化、实机断开触发 Cancel 复核
      （后两者 e2e 已覆盖，属锦上添花）
- [ ] **`/v1/responses`（OpenAI Responses API，Codex 新版）**：
      方案 A：网关内把 Responses 请求翻译为上游 chat/completions（含流式事件格式转换）；
      方案 B：确认上游（vLLM 等）原生支持后仅文档化。当前为纯透传，上游不支持即 404
- [ ] **`/v1/messages`（Anthropic Messages API，Claude Code）**：
      方案 A：网关内 OpenAI↔Anthropic 双向格式翻译（含 SSE 事件转换，中等工作量）；
      方案 B：文档化前置 claude-code-router / LiteLLM 翻译层的部署方式
- [ ] **接入文档**：README/DEPLOY 增加 DSH（`DEEPSEEK_BASE_URL`）、Codex（`OPENAI_BASE_URL`）、
      Claude Code（`ANTHROPIC_BASE_URL` 或 router）的配置示例与模型名约定
- [x] **OpenAI 兼容错误语义标准化（2026-09 实施）**：对照 OpenAI 协议修补三处，
      SDK/工具按 error.type 与 Retry-After 决定重试行为：
      1. **error.type 按状态码映射**（`http_proxy::error_response`）：400→
         `invalid_request_error`、401→`authentication_error`、403→`permission_error`、
         404→`not_found_error`、409→`conflict_error`、429→`rate_limit_error`、
         5xx→`server_error`、其余→`api_error`
      2. **429 响应带 `Retry-After: 60`**（限流/配额拒绝，SDK/脚本退避依赖）
      3. **`x-request-id` 响应头**：metrics_middleware 生成/透传（客户端自带则沿用），
         并写入站 headers 供 proxy 复用为隧道 request_id——HTTP 层/隧道帧/日志
         三方对账一致；proxy 无该头时自增兜底
      （测试：error.type 映射单测 + 429 Retry-After 单测 + x-request-id 中间件单测 +
       e2e `e2e_openai_error_semantics`：401/400/404/429/503 各状态码的 type 与头）

## P1 — 运维与健壮性

- [x] **进程级优雅关闭**：gateway/agent 注册 SIGTERM/SIGINT（`tokio::signal`），收到后打 INFO 日志
      → 调用 `Gateway::shutdown()` / `Agent::shutdown()` 干净退出；
      覆盖 systemd stop、Ctrl+C、harness job_kill 场景（对应 OPTIMIZATION.md A1 ✅）
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
- [x] **per-API-key token 用量计量（2026-09 实施）**：
      按 API key 统计 token 消耗（prompt/completion/total + 请求数 + 最后使用时间），
      Admin API 可查询、Keys 页展示；吊销 key 后用量记录仍保留（可审计）。
      **实现（与定稿设计的差异已标注）**：
      1. 数据来源：`crates/gateway/src/usage.rs` 透传层提取——非流式整包缓冲后解析
         JSON usage；流式逐块 `contains("usage")` 预过滤 + SSE data 行级解析（零开销快路径）；
         上游无 usage / 取消 / 断流 → 估算（prompt 按请求体 messages 字符 /4、
         completion 按已转发字节 /4），`estimated_requests` 计数标记
      2. 存储：keys.db 新表 `key_usage(key_id PK, name, prompt_tokens, completion_tokens,
         requests, estimated_requests, last_used_at)`（**实现加了 name 快照与
         estimated_requests 列**，吊销后名称仍可审计）；热路径内存
         `RwLock<HashMap<key_id, Arc<KeyUsageCell>>>`（AtomicU64 无锁累加），
         每请求结束写穿 SQLite（UPSERT 增量）
      3. API/UI：`GET /admin/usage` 全部 key 汇总（含已吊销）；`GET /admin/keys` 每项内嵌
         `usage`；Keys 页加用量列（total + in/out，估算带 `~` 标记）；
         `POST /admin/usage/reset` 留后期
      4. 范围：只做**计量**（统计+查询+展示）；配额/超限拒绝排除，留多租户阶段
      5. 测试：单测（usage.rs 提取/SSE 行/无 usage 估算 ×6、keystore 累加+持久化+
         吊销保留 ×2）；e2e `e2e_usage_metering`（打 2 次请求 → /admin/usage 与
         mock 返回的 usage 一致、/admin/keys 内嵌一致、吊销后记录仍可查）
- [ ] **计量与治理延伸（待定：暂未决定是否实施）**：usage 计量完成后的候选方向，
      按价值排序与口径待定（含"放哪"的架构判断——现阶段放 gateway 合适，多实例/
      多租户时随 11.4 无状态化外置 Redis）：
      1. **per-key quota**：总量 token 配额 → 超限 429；实现收敛为可替换模块
         （`key_store.check_quota`，将来可整体迁 Redis）；口径待定：token 总量 or
         请求数 or 白名单 or 到期时间；估算请求计不计入；周期（自然月/滚动 N 天）
      2. **用量按 model 归因**：`key_usage` 主键升级 `(key_id, model)` → 已部署
         数据需一次性迁移（暂缓——keys.db 迁移规模化不做，本项连带暂缓）
      3. **用量 reset**（`POST /admin/usage/reset`，TODO 已留口子，不动表结构）
      4. **估算来源强化**（mock/上游补 usage 字段，提高精确占比，不动表）
      5. **用量告警**（quota 80%/100% 打日志/UI 提示，纯读+日志）
      6. **prompt 缓存命中率统计**（vLLM Automatic Prefix Caching：响应 usage 里
         `prompt_tokens_details.cached_tokens` / DeepSeek `prompt_cache_hit_tokens`；
         usage.rs 提取时顺手读 cached_tokens，算命中率 = cached/prompt）——
         仅**代理计费 API**（DeepSeek/OpenAI cache hit 打折）时有省钱价值；
         当前网关连自家 vLLM（无金钱成本），价值有限，暂缓
      注：模型白名单/请求数配额/到期时间等非 token 维度与 token quota 二选一或组合，
      取决于要防的场景（偷用贵模型 → 白名单；刷请求 → 请求数配额；失控并发 → key 并发上限）
- [ ] **健康上报驱动的更精细路由**（DESIGN.md §9 M4 待办）：当前按在途请求数最少路由，
      后续可结合 agent 心跳上报的延迟/队列深度
- [ ] **Grafana 仪表盘模板**（DESIGN.md §9 M4 待办）：消费 `/metrics` 指标
- [ ] **key 禁用/启用 toggle（B 档，可选）**：`KeyRecord.enabled` 字段已存在但 admin API
      只有创建/删除——补 `POST /admin/keys/{id}/disable|enable`（"暂时停用"不吊销），
      10 分钟级改动
- [ ] **HTTP 层总并发 admission（B 档，可选）**：现有限流是 per-key（令牌桶）——
      多个 key 总和仍可压垮单实例。补网关**全局在途上限**（HTTP 入口级，类似 agent 级
      admission）；metrics 的 active_requests 已可观测，实施是加"超限即拒"判断
- [ ] **请求体大小限制可配置（C 档，可选）**：`DefaultBodyLimit::max(16MB)` 硬编码
      （http.rs）——多模态图像/大上下文请求 413 无法调；config 加字段即可
- [ ] **首次部署 bootstrap（B 档，可选）**：第一个 API key 目前必须走 admin API
      （admin_token 配置文件明文）；考虑"首次启动自动建默认 key"或引导提示
- [ ] **usage 数据保留策略（B 档，可选）**：`key_usage` 无限累积（reset 是待定项）——
      长时间运行表会涨；建议与 reset 一并设计保留窗口/归档
- [ ] **Dockerfile / docker-compose（C 档，可选）**：当前部署是 systemd + 手动传文件
      （DEPLOY.md）；容器化需多阶段构建含 web/dist
- [ ] **结构化访问日志 JSONL（C 档，可选）**：tracing 文本日志给人看；如需审计
      "谁何时调了什么"可加 JSON 行落盘
- [ ] **keys.db 迁移规模化**：当前自动迁移（`keystore.rs::migrate_legacy_keys`）同步执行、
      全量读入内存 + 单一大事务——仅适合小数据量 / 个人 / 小团队（适用边界见 DEPLOY.md §10）。
      改进：① **分批流式**：cursor 每批 ~500 条、小事务提交、内存有界（低成本，建议先做）；
      ② **独立离线迁移命令** `gateway migrate-keys`：维护窗口运行，运行时零负担，天然支持分批；
      ③ 大数据量场景启动时只提示"建议离线迁移"，不做自动同步迁移。

## P2 — 测试与质量

- [x] **覆盖率 95.87%（2026-09 实测，stable llvm-cov）**：从 95.77% 提升。
      剩余未覆盖行均为**防御性错误分支 + 进程入口**（main()/pending 后不可达代码），
      stable 工具链无法排除（`#[coverage(off)]` 需 nightly 且当前 nightly 的
      feature(coverage) 缺失 E0635；tarpaulin 0.37 skip 属性不兼容）。
      已完成：补 ui 托管分支 / 非法哈希拒绝 / agent 启动失败 3 个测试；
      清理 ui_fallback 不可达分支；3 个二进制的挂起点抽成 wait_forever/serve_forever。
      目标调整：**不再追求 99% 数字**——新增代码保持"业务路径全覆盖 + 防御分支尽量测"，
      定期复查未覆盖行（`cargo llvm-cov --show-missing-lines`），
      如未来工具链支持行级排除再重新评估。
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
