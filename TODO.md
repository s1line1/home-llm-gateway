# home-llm-gateway TODO

> 基于实际代码审查与需求梳理（2026-08），按优先级排列。
> 状态：P0 主体已实施（2026-09）；其余按优先级推进，`[x]` 表示已完成，未勾选项为待办。
> 文末「2026-09 全项目代码审查（两轴）」登记了最近一次全量审查发现的代码问题与文档漂移。

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

- [ ] **同名 `agent_id` 会让网关静默不可用（2026-09 发现，已实测；修法已验证但代码已撤回）**：
      两台 edge 用同一个 `agent_id` 时，网关对同名注册会**关掉旧连接**（`registry.rs`，本意是
      让同一台机器重连时接管），而 agent 把"被踢"当成干净断开、把退避重置回 500ms
      （`agent/src/lib.rs` 的 `run()`）→ 两台机器每 ~500ms 互踢一次、永不收敛。每次踢都会
      掐断在途 QUIC 流，因此**凡是活得比踢连接周期长的请求全部失败**（实测：3 秒内新增 5 次
      连接；6 个 `/v1/slow` 请求 0 成功、全 502）。
      **表象极难察觉**：两侧进程都健康、`/admin/agents` 恒显示"1 个 agent 在线"、日志只有
      反复的 `disconnected from cloud, reconnecting`，唯一异常信号是
      `hlmg_agent_connections_total` 在飞涨（它是 counter，不看 rate 注意不到）。
      触发门槛很低：`agent/src/config.rs` 的默认值与 `Makefile` 生成的都是 `edge-1`，示例配置
      是 `home-1`，而 DEPLOY.md 全文没提"多台机器要改 agent_id"。
      **已定修法（跑通过，含红→绿）**：`agent_id` 改为「可读前缀 + 每进程唯一的随机后缀」
      （`edge-1-6d69369d`），在 `agent/src/config.rs` 的 `from_file` 里生成；需加依赖
      `getrandom = "0.3"`（gateway 已在用同版本，Cargo.lock 只多一条依赖边）。
      后缀**每进程生成一次**（不是每连接）→ 同一进程内重连沿用同一 id，网关"重连接管"
      逻辑不受影响。
      **撤回原因 / 待决**：每进程随机会导致**进程重启后 id 变化**（断链重连不变，只有重启变）。
      当前影响有限——**没有任何指标带 `agent_id` 标签**（`hlmg_requests_total` 唯一的 label 是
      `status`，其余 metrics 都是无标签标量），`/admin/agents` 是实时视图——但将来加"按 agent 的
      容量/负载指标"（见本文件"容量感知路由"那条）时会咬人。三个候选改法（择一）：
        1. **主机名后缀**（`home-1-mac-mini`）：跨重启稳定且最可读；需加安全小依赖
           `gethostname`（workspace lints 禁 `unsafe`，不能直接用 libc）；两台机器主机名
           相同（克隆 VM/容器）时仍会撞
        2. **持久化随机后缀**：首次生成后写进配置同目录的 `agent-id` 文件、以后复用；稳定且
           不会撞、无需新依赖；代价是多一个状态文件、目录需可写（只读挂载/临时 FS 时退化）
        3. **主机名 + 随机回退**：两者结合，复杂度叠加
      **回归测试（已写好并验证过红，重做时照搬）**：
        - e2e `e2e_two_agents_sharing_one_config_coexist`（`tests/e2e/agents.rs`）：两台机器读
          **同一份配置**（走生产路径 `agent::config::from_path`）→ 断言两个 agent 同时在册、
          3 秒内新增连接 ≤2、慢请求 200；修复前红在 `expected 2 agents, got 1`
        - 单测 `agent_id_gets_a_unique_suffix_per_load`（`agent/src/config.rs`）：同一份配置
          加载两次 → 前缀保留 + 8 位十六进制后缀 + 两次必须不同
        ⚠️ **更正（2026-09 全项目审查）**：这两个测试**目前不在树中**（随修法一并撤回，
        `grep` 只命中本文件）——重做时必须重新写，不要以为能直接跑。另外当时的默认值
        `edge-1` 仍在 `agent/src/config.rs:51-53` 与 `Makefile` 中生效，`DEPLOY.md` 与
        `README.md` 已在本次审查中补上"每台机器 `agent_id` 必须唯一"的警告与排障行。
      注：网关侧"踢旧连接"的机制本身是对的（同机重连接管），无需改动——现在的问题只是它
      会被配置撞车误触发。
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
- [x] **HTTP 层总并发 admission（2026-09 实施）**：配置 `max_concurrent_requests`
      （0 = 不限，默认关闭）；metrics_middleware 在 record_start 后检查
      `metrics.active_count() > limit` → 立即 429（复用 OpenAI 语义 error_response，
      带 Retry-After 与 x-request-id），防多 key 总和压垮单实例。
      测试：lib 单测（占 1 槽后第 2 请求 429 / 0 不限 / 释放后恢复）+ e2e
      `e2e_http_concurrent_request_limit`（limit=1 并发两慢请求 → 200 + 429）
- [ ] **请求体大小限制可配置（C 档，可选）**：`DefaultBodyLimit::max(16MB)` 硬编码
      （http.rs）——多模态图像/大上下文请求 413 无法调；config 加字段即可
- [ ] **首次部署 bootstrap（B 档，可选）**：第一个 API key 目前必须走 admin API
      （admin_token 配置文件明文）；考虑"首次启动自动建默认 key"或引导提示
- [ ] **usage 数据保留策略（B 档，可选）**：`key_usage` 无限累积（reset 是待定项）——
      长时间运行表会涨；建议与 reset 一并设计保留窗口/归档
- [ ] **Dockerfile / docker-compose（C 档，可选）**：~~当前部署是 systemd + 手动传文件~~
      **更正（2026-09 审查）**：`Dockerfile` 已存在（多阶段，产出 gateway/agent/mock-llm 三个二进制），
      并已在 README 目录结构中登记；剩余缺口是 **docker-compose**，以及镜像不含 `web/dist`
      （容器内 `/` 会是构建提示页）——容器化需多阶段构建把前端一并打进去
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

---

## 2026-09 全项目代码审查（两轴）— 发现登记

> 方法：按 code-review 的两条轴——**规范轴**（是否符合本仓库已文档化的规范 + Fowler 坏味道基线）
> 与**规格轴**（代码是否兑现 DESIGN / MODEL_ROUTING / OPTIMIZATION / TODO / README 的承诺）——
> 对**整个仓库**（不是 diff）做并行审查，基线提交 `745e8e8`。
> 基线健康度：`cargo fmt --check` ✅、`cargo clippy --workspace --all-targets -- -D warnings` ✅、
> `cargo test --workspace` ✅（119 个测试全绿）——即下列问题都不是构建/测试造成的。
> 本节只登记**尚未修复**的代码问题；已随本次一并修掉的文档漂移见本节末尾清单。
> 同名 `agent_id` 互踢那条已在上文 P1 单独登记（并已补"回归测试不在树中"的更正），此处不重复。

### P1 — 正确性 / 健壮性

- [ ] **usage 内存累加竞态（少报用量）**：`gateway/src/keystore/mod.rs:318-335` 在 map 无 cell 时
      新建 `c` 再 `or_insert_with(|| c.clone())`，然后**返回本地 `c`**——若并发请求先插入成功，
      `or_insert_with` 保留的是别人的 cell，本次增量就记进了不在 map 里的孤儿 cell。
      后果：SQLite 的 `key_usage` 正确，但 `/admin/usage`、`/admin/keys` 的内存视图少报，
      **重启后自愈**（启动时从 SQLite 重载，见 `:185-199`）；窗口 = 新建 key 的首批并发请求。
      修法：返回 entry 里的值（`usage.entry(..).or_insert_with(..)` 的返回值）。
- [ ] **失联 agent 不摘除，却被当成"健康"计数**：`registry.rs:91` 的 `len()` 不做新鲜度过滤，
      直接喂给 `/metrics hlmg_agents`（HELP 文案是 "Registered healthy agents"，`metrics.rs:136-138`）
      与 `/admin/agents`（`admin.rs:173`）；只有 `try_acquire`（`registry.rs:145`）过滤了
      `agent_stale_secs`。活跃但沉默的连接会一直多报。修法：`len()`/`snapshot()` 接 `stale_after`，
      或另给一个 `healthy_len()` 供指标使用。
- [ ] **慢客户端无限占并发槽**：`http_proxy.rs:419` 的 `tx.send(...).await` 无超时，也没有响应写超时
      → 停止读取的客户端会无限期持有 `SlotGuard`（连带占住该 agent 的并发额度与 QUIC 流）。
      DESIGN §11.2 已列"SSE 流式转发增加内存缓冲上限"，与本项合并做。
- [ ] **公网入口 accept 出错即永久停服**：`gateway/src/lib.rs:175` 的 `listener.accept().await?`
      用 `?` 结束整个循环，外层只有一句 `warn!("https server stopped")`。对比 QUIC 侧专门做了
      `hlmg_quic_accepting` + `error!` 告警（`quic.rs:29-36`），HTTP 入口（唯一公网入口）反而没有
      等价信号——瞬时错误（EMFILE 等）就能让网关"进程活着但不监听"。修法：accept 错误重试 + 计数指标。
- [ ] **Cancel→上游缺上游侧断言**：`mock-llm` 没有"请求被取消"的可观测信号，`chain.rs:205-217`
      只断言断开后 `/v1/models` 仍可用；README 承诺的"客户端断开 → 不白算 token"因此只有间接覆盖。
      修法：mock-llm 暴露取消计数（或日志端点），e2e 断言断开后上游请求确实被中断。

### P2 — 契约 / 一致性

- [ ] **`error.type` 分叉**：`http_proxy::error_response` 自我声明是 OpenAI 错误格式的唯一来源
      （`http_proxy.rs:27-29`），但 `admin.rs:34/110/121/156/166` 与 `http.rs:117` 手搓了 5 种
      不一致的 type（`auth_error` / `invalid_request` / `gateway_error` / `not_found`）。
      修法：admin 与 UI fallback 也走同一个构造器/映射表。
- [ ] **`x-request-id` 只在 `req-<u64>` 形状下才等于隧道 `request_id`**：`http_proxy.rs:168-173`
      只认 `strip_prefix("req-")`，其他形状（Codex/DSH 发的是 UUID 形态）回落到**第二个**静态计数器
      （`http_proxy.rs:25`，与 `http.rs:320` 的计数器都从 1 开始）→ 数值撞车；P0 宣称的
      "HTTP 层 / 隧道帧 / 日志三方对账一致"在真实客户端上并不成立。修法：统一 id 生成器，
      客户端 id 原样进隧道（改名叫 trace id）或帧内改用字符串。
- [ ] **`extract_model` 卡住非 chat 的 `/v1/*`**：`http_proxy.rs:142-147` 对 `http.rs:46-53`
      catch-all 注册的**所有方法与路径**都要求 body 是带 `model` 的 JSON → `GET /v1/files`、
      `DELETE /v1/files/{id}`、multipart（`/v1/audio/transcriptions`）现在一律 400，
      与 DESIGN §5.1"一律透传"冲突。修法：按路径/方法白名单要求 model（chat/completions、
      embeddings…），其余透传。
- [ ] **A3 类型化错误收尾**（OPTIMIZATION.md 已改标 ⚠️ 部分）：`Agent::start`
      （`agent/src/lib.rs:40`）与 `tls::https_server_config`（`gateway/src/tls.rs:51-54`）仍返回 anyhow；
      `config_err`、`AgentError::Forward`、`GatewayError::Sqlite` 是从未被构造的死变体。
- [ ] **Makefile `deny` 目标 ≠ hook/CI**：目标只跑 `cargo deny check licenses`，而 pre-commit hook
      与 CI 跑完整 `cargo deny check`（广告语已改，行为未变）。二选一：把目标改成完整检查，
      或明确 `make check` 不含完整 cargo-deny。
- [ ] **Heartbeat 载荷空洞**：`Frame::Heartbeat { inflight }` 恒为 0（`agent/src/lib.rs:136-140`），
      网关只打 debug 日志（`quic.rs:76-84`）。它是"容量感知路由"的前置数据：要么实现上报，
      要么删掉该字段（现在是死载荷，容易误导）。
- [ ] **重连退避无抖动、上限 30s**（DESIGN §6.1 原设计为抖动 + 上限 60s）：多台 agent 同时断线
      会同步重连；与同名 `agent_id` 互踢叠加时更糟。修法：加 jitter（±20%）并对齐上限。

### P3 — 坏味道 / 清理（不成灾，但会持续收利息）

- [ ] **e2e 证书 fixture 重复且已分叉**：`tests/e2e/common.rs` 的 `gen_certs`（`:24-82`）与
      `gen_certs_pem`（`:85-123`）逐行重复，CA 的 `key_usages` 一个 3 项、一个 2 项；全仓另有
      23 处 `CertificateParams::default()` 的 PKI 脚手架（`agent/src/lib.rs:326-366`、
      `gateway/src/tls.rs:75-109`、`gateway/src/main.rs:76-100`、`agent/src/main.rs:75-99`、
      `registry.rs:212-255`、`quic.rs:103-125`）。抽一个共享 fixture。
- [ ] **重复逻辑**：`proxy` 内联了 `auth_and_rate_limit` 已封装的认证 + 限流（`http_proxy.rs:133-140`）；
      `Accept: text/html` 探测复制两份（`http.rs:103-107` 与 `:197-201`）。
- [ ] **`UsageCollector` 位置与自我声明矛盾**：110 行、有状态的它住在 `http_proxy.rs:292-395`，
      而 `usage.rs:10` 自称"只含纯函数"，OPTIMIZATION S1 又把 http_proxy 限定为"代理转发"——
      二选一：搬去 `usage.rs`，或改掉那句注释。
- [ ] **前端四份独立 `/metrics` 轮询**：`Layout.tsx:24`、`Overview.tsx:9`、`MetricsPage.tsx:10`、
      `Agents.tsx:61` 各实例化一个 `useMetricsHistory()`（各自 5s 轮询、各自一份历史）。抽 context 共享。
- [ ] **小体积/常量类**：`Agents.tsx:72` 用 `error.message.includes("404")` 嗅探状态码
      （`ApiError.status` 就在手边）；`Agents.tsx:28` 硬编码 `agent_stale_secs` 的默认值 `15`；
      `registry.rs:124,151,158` 三处裸比较 `"*"`；`extract_model -> Result<String, ()>` 丢掉失败原因；
      `HeadOutcome::Error(u16, String)` 用裸状态码。
- [ ] **死代码 / 死常量**：`KeyStore::authorize_id`（`keystore/mod.rs:210`）、`Metrics::request_count`
      （`metrics.rs:98`）、`HISTORY_LEN` 被导出但 `useMetricsHistory.ts:41` 硬编码 `60`。

### 本次一并修掉的文档漂移（无需再动代码）

- `README.md` / `README.en.md`：API Key 认证机制（"恒定时间比较" → sha256 索引 + argon2 校验）、
  失联 agent 语义（"自动摘除" → 不再参与路由，但计数仍包含失联连接）、`/metrics` 被浏览器访问时
  返回 Dashboard、目录结构补 `Dockerfile` / `deny.toml` / git hook、
  **每台机器 `agent_id` 必须唯一**的警告；英文版另修了"keys.db 存明文"的错误描述。
- `DESIGN.md`：Heartbeat 实际载荷、§5.2 认证机制、§5.4 模型感知路由、§5.6 只有逐帧空闲超时、
  §6.1 退避无抖动 / 上限 30s、§7 公网入口现状（TLS 需显式配置、审计日志缺来源 IP 与 key id）、
  §8 配置文件名、§10.4 摘除语义、§11.1/§11.2 的已实施项标注。
- `DEPLOY.md`：删掉"openssl 生成静态 API Key"这一步（网关没有静态 key）、
  已删除的 CLI 旗标（`--server-name` / `--agent-stale-secs` / `--admin-token`）改为配置项、
  新增 `agent_id` 唯一性警告与对应排障行、安全清单同步。
- `CODE_READING.md` / `OPTIMIZATION.md` / `EDGE_REBRAND.md`：e2e 数量（13 → 23）、
  测试总数（85 → 119）、模块地图补 `usage.rs` / `error.rs`、A3 与 C3 的状态标注更正。
- `web/README.md` + `web/src/api/{client,types}.ts`、`web/src/pages/Agents.tsx`、
  `web/src/hooks/useMetricsHistory.ts`：`/admin/agents` 已实现（不再是"契约预留"），
  404 分支改为"旧版网关或未启用 `/admin/*`"的降级说明。
- `Makefile` 的 `deny` 目标注释、`deploy/gateway.service` 的 `Description`（Home → Edge）。
