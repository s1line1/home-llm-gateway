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

- [x] **网关 fd 软上限只有 1024（2026-09-17 实测；已由进程启动时自愈）**：
      云端 `gateway.service` **没有**设 `LimitNOFILE`，于是吃 systemd 的全局默认
      （`/etc/systemd/system.conf` 的 `#DefaultLimitNOFILE=1024:524288`，注释状态=内置默认），
      `/proc/<gateway>/limits` 显示 `Max open files 1024 524288`。**不是内核限制**：
      `fs.nr_open = 1048576`，同机 `cron` 也是 1024（同一个默认），`sshd` 则自己抬到了 1048576。
      撞上时的症状是**新连接被拒**而进程健康：`accept error: Too many open files (os error 24)`
      （实测日志里已有 296 次，与压测窗口吻合），客户端表现为 `connection reset by peer`；
      同时内核 accept 队列（128，见下一条）被卡住 → `Possible SYN flooding ... Sending cookies`。
      实测口径：768 并发客户端连接时网关 fd 峰值 **785**（≈ 每连接 1 fd + QUIC/DB/日志十余个），
      所以**安全水位约 900 并发连接**（按 16384 的新上限则是 16000+）。
      **已实施**：`gateway/src/nofile.rs` 在启动时（绑 socket 之前）把 soft 抬到
      `min(hard, 16384)`，失败只 WARN 不阻止启动；**没有**选择"抬到 hard"（云端 524288）——
      上限给到几十万会把 fd 泄漏的引爆点从本进程 `EMFILE` 推到整机 `fs.file-max`/内存。
      ⚠️ 实现上**不要**改用 `rlimit::increase_nofile_limit`：它在 macOS 上会把 soft 设成
      `min(lim, hard, kern.maxfilesperproc)`，而后者可能低于当前 soft（实测 1048575 → 61440），
      等于把额度改小。回归测试：`nofile::tests::raises_soft_from_the_systemd_default_to_the_target_and_is_idempotent`
      （先把 soft 降到 1024 复现 systemd 默认，断言抬到 16384、只抬不降、hard 不动、幂等；
      已验证过红）。**编译期保险**：`install()` 返回一个只能由它产出的凭证（`nofile::Raised`），
      而 `Gateway` 结构体带一个该类型的 `pub` 字段——于是"删掉 install 调用"会变成
      `missing field nofile` 编译错误，而不是静默退回 1024（已验证过红；
      `pub fn` + 忘了调用本来**不会**有任何 dead_code 警告）。
      **运行期保险**：e2e `e2e_startup_raises_the_nofile_soft_limit_in_the_real_process`
      先把本进程 soft 降到 1024 复现 systemd 处境，再起真实网关，然后读**进程自己的**
      `/proc/self/limits` 核对生效值（不以自家日志为准），并断言 hard 未被改动
      （同样已验证过红）。**仍可选的加强**：unit 里写 `LimitNOFILE=65536` 抬高天花板——
      不写也不会再撞那个 1024，但日志里 `limited_by_hard=true` 表示天花板比目标值低。
- [ ] **缺"768 并发档"修复后的可信读数（口径：只数 `status="200"` + 记 200 占比）**：
      README《网关自身的吞吐上限》里那张表 768 行是**修复前**的旧读数（51–73 QPS / 3.6–5.4%），
      而它当初不可用的机制（agent 心跳零余量 → `select!` 当致命 → 重连撞 10s 握手 → 1s 重试风暴）
      已经在代码里修掉了三处：心跳等待 `3 × interval` + 连续 2 次才断、握手 30s、
      网关连续 3 次隧道超时才摘除且延迟关闭。**修复后那次复测的原始输出没有归档**，
      所以文档里既不写"已经好了"也不写"仍然坏"——需要时按同一口径重跑一档即可补齐。
- [ ] **链路饱和会被 `head_timeout` 放大成"agent 摘除"（链路部分未改；网关行为部分 2026-09-18 已修）**：
      云 ECS 的**下行带宽被限在 ≈0.40 MB/s（3.2 Mbps）**（HTTP/SSH-TCP/QUIC 三种测法一致；
      对照：清华镜像→同一台 Mac 是 10.1 MB/s，排除家庭带宽）。当 `QPS × (请求字节+响应字节)`
      超过这个上限时，响应头 15s 内到不了 → `head_timeout` 判定"隧道已坏" → 摘除 agent →
      连接被关 → agent 重连（退避最长 30s）→ 期间注册表为空 → **全量 503**。
      实测（k6 `http_req_failed` 口径，同一施加速率、只改 body 大小）：**只改单个 body 大小**得到
      一条单调曲线——1 KB → **0.00%**、4 KB → 5.35%、8 KB → **48.16%**、16 KB → 76.53%、
      64 KB → **98.38%**；A/B 那一对是 16 B → **0.06%**、8 KB → **48.97%**（8 KB 档重复跑两次
      得 48.16% / 48.97%，属正常波动）。
      折算一下为什么必然如此：8 KB 那档每迭代 ≈28 KB（请求 base64 后 body ≈11 KB + `/v1/echo`
      把整包回吐 ≈15 KB + 流式端点 ≈2.5 KB）× 50 iters/s ≈ **1.4 MB/s**，对 0.4 MB/s 的上限
      是**超载约 3.5 倍**（按载荷折算的估算，未直接采 `data_sent`）；16 B 那档 ≈150 KB/s 在上限内。
      同一窗口内 `upstream head timeout; evicting agent` 1 026 次、`registry-empty` +3 753。
      ⚠️ 期间 `hlmg_tunnel_open_timeouts_total` 恒为 **0** —— 也就是说开流路径完全正常，
      失败与摘除全部走"响应头超时"这条路径；两者必须分开看，否则会把链路问题误判成网关缺陷。
      **原因分两层（写清楚，避免以后两半混着读）**：
        · **链路层（代码解决不了）**：出口 ≈0.40 MB/s，超出的字节必然来不及时 → 只能调带宽
          或减少字节（别整包回吐、压缩、把大请求拆小）。
        · **网关行为层（代码能解决）**：响应头超时**被当成"隧道已死"**——`http_proxy.rs:530`
          的 head 超时分支**无条件**调 `registry.evict()`；而摘除计数与开流超时**共用**
          （`registry.rs:148` 的 `TUNNEL_TIMEOUTS_BEFORE_EVICT = 3`），且**只在收到响应头时清零**
          （`registry.rs:151` 的 `note_tunnel_op_ok`，唯一调用点 `http_proxy.rs:507` 的
          `HeadOutcome::Head` 分支）。链路饱和时"一个响应头都收不到" → 计数必然涨到 3 →
          摘除 + 关连接 → 重连期间注册表为空 → **全量 503**。**这条放大是行为问题，不是链路的
          必然结果。**
        ⇒ 结论：**链路那半决定"有多少请求做不完"，网关那半决定"做不完的请求是变成几个 504，
          还是把整队拖下线变成全量 503"。** 候选改法 2 只修后者（不减字节就不提吞吐）。
      **数据完整性不受影响**：所有档位（含严重超载）`mismatch` 全为 0，到达的字节逐字节正确。
      候选改法（都未实施，需先定取舍）：
        1. **运维**：把 ECS 带宽调上去（固定带宽上调或改按流量）——最直接，先做这个再谈验收；
        2. **判据 —— 已实施（2026-09-18）**：`Entry::head_timeout_is_fatal(window)` 把"忙≠死"
           推广到响应头超时。窗口 = `4 × head_timeout`（默认 60s，不另设配置项）：窗口内有过成功
           响应头 → 只回 504、**不计连续超时、不摘除**（记 `hlmg_upstream_head_timeouts_total{class="slow"}`）；
           窗口内一次都没回过、或**从未回过**（注册不算"活着"）→ 走原来的连续 3 次摘除（`class="silent"`）。`note_tunnel_op_ok`
           顺带刷新 `Entry.last_head_ok`。回归测试：`tests/e2e/head_timeout.rs` 两条（都做过红检：
           强制判死时"三次慢请求"立刻变 `silent` 且日志出现 3 次 `evicting agent`）
           + `registry::tests::head_timeout_is_fatal_only_after_a_window_of_total_silence`。
           **云端验证（2026-09-18 21:39，部署 `c7f298e`）**：同一档（8 KB body、RATE=50、30s、
           4 agent）复测——失败率 48.97% → **41.55%（全部是 504）**；`{class="slow"}` **+924**、
           `class="silent"` **0**；`hlmg_agent_connections_total` **+0**、`registry-empty` **+0**、
           502/503/429 **全 0**、4 个 agent 重连 **全 0**、`mismatch` 0；日志窗口内
           `not evicting` 924 / `silent; evicting` 0 / `agent evicted` 0。对照（16 B body、同参数）
           3 000 请求 0.00% 失败、中位 60.6ms。**即：同样超载，从"整队下线 → 全量 503"变成
           "924 个请求各自 504"。**
           **效果边界**：这只是把"局部超载"与"全站不可用"分开——链路饱和时 504 依旧存在，
           **不减字节就不提吞吐**；真死但"最近刚成功过"的 agent 会晚一个窗口才被摘除
           （不影响路由：心跳停掉后 `agent_stale_after` 先把它剔出候选）；
        3. **验收规范**：任何云端压测都要先声明字节预算（`QPS × 字节 ≤ 链路`），
           否则测的是链路不是网关。本地栈（RTT≈0、无带宽瓶颈）对照很有用：
           同样 64 KB body，本地 13.7ms vs 云端 1.64s；同样 256KB 响应，本地 18ms vs 云端 616ms。
      **已试过且无效（别再重复）**：把 agent 侧 `with_bidirectional_remote_data_window(1 MiB)` +
      `with_data_window(16 MiB)` 调大 —— 8 KB 请求体延迟 240ms → 229ms，基本没变。
      说明瓶颈不在对端授予的流控窗口，而在**链路本身**（这点从"TCP 直下也只有 0.40 MB/s"
      就能反证）。同理，`initial_congestion_window`（`cubic::Builder::with_initial_congestion_window`
      是公开 API）当时没来得及试，但在 3.2 Mbps 的链路上下调它不会突破上限。
- [ ] **监听 backlog 被硬编码成 128**：`tokio::net::TcpListener::bind` 走 mio，而 mio 为对齐 std
      写死 `listen(.., 128)`（`mio-1.2.2/src/net/tcp/listener.rs`），云端 `net.core.somaxconn=4096`
      完全用不上。实测 `ss -lnt` 的 Send-Q 就是 128；dmesg 里 10 次
      `Possible SYN flooding on port 0.0.0.0:9090`（全机 164 天里只出现在网关端口）。
      修法：用 `socket2` 建 socket → `listen(4096)` → `TcpListener::from_std`。
      属**次要因素**（accept 被上面那条 EMFILE 卡住时才会放大），故排在 fd 之后。
- [ ] **网关日志无轮转、体量失控**：`StandardOutput=append:/var/log/home-llm-gateway/gateway.log`，
      每请求至少一行 INFO，实测单日 **652MB**（`tail -c 6000000` 只覆盖约 20 秒，
      排查时按时间 grep 会误以为"日志里什么都没有"）。修法：`logrotate` + 降级为
      `RUST_LOG=info,gateway::access=debug` 之类的分级，或按请求采样。

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

## P1 — argon2 使用方式重构（提案）

> **触发点**：按"几百人团队 / 4 vCPU / 8 GB"做容量评估时发现，网关**内存峰值唯一不受控的来源
> 就是 argon2**：一次校验 19 MiB，而并发校验没有任何上界。算力不是问题，这一处才是 8 GB
> 机器上真正会 OOM 的地方。

### 现状（含代码位置）

| 环节 | 位置 | 事实 |
|---|---|---|
| 发号 | `keystore/hash.rs:116` | key 恒为 `sk-` + 24 随机字节（**192 位熵**）；`/admin/keys` 只收 `name`，**不存在"运维自己填 key"的入口**（`admin.rs:98`） |
| 存储 | `keystore/mod.rs:374` | 同时存 `lookup = sha256(明文)`（O(1) 索引）与 `key_hash = argon2id(明文)`（PHC 串，`m=19456 KiB / t=2 / p=1`） |
| 校验 | `keystore/mod.rs:350` → `hash.rs:94` | 按 sha256 索引命中记录后，**再跑一次 19 MiB 的 argon2id 校验**（在 `spawn_blocking` 里，`http_proxy.rs:81`） |
| 缓存 | `keystore/verified.rs:55` | `(lookup, cred_version)` 命中即跳过校验；有 TTL 与上限（`verified_cache_max: 1650`） |
| 单飞 | `keystore/verified.rs:57` | `inflight: HashMap<lookup, FlightSlot>`——**只对同一个 token 串行；不同 token 完全并行且无上界** |

### 问题

1. **它现在没换来任何安全收益**：key 是 192 位随机值，库里已经有 `sha256(token)`，对随机
   token 而言不可离线爆破；argon2 的"内存硬"是用来拖慢**低熵口令**猜测的，用在这里不成立。
   代价却是每次未命中 19 MiB + 10–30 ms CPU（debug 下 0.4–0.6s）。
2. **内存峰值无上界**：`Argon2InFlight`（`hash.rs:84-91`）**是个空结构**，`enter()` 只返回
   `Self`，不做任何限流（注释仍写"它标出了并发校验的边界"，但边界并不存在）。峰值 =
   `同时首用的不同 token 数 × 19 MiB`：**300 把 key 重启后同时首用 ≈ 5.7 GB**，8 GB 机器会被
   打穿。注意 `max_concurrent_requests` **拦不住**它——那道闸限的是请求数，不是"不同 token 的首次校验数"。
3. 附带成本：真跑 argon2 会占住 `spawn_blocking` 线程 10–30 ms，重启/轮换 key 时是一波 CPU 尖峰。

### 方案

| 方案 | 做法 | 代价 / 取舍 |
|---|---|---|
| **B（先上，最小改动）** | 保留 argon2，给并发校验加**信号量上限**（如 2–4 路）→ 峰值确定在 38–76 MiB | 无迁移、改动小；冷启动/轮换时后到者排队（4 路 × 20 ms，300 把 key 约 1.5s 尾延迟）；不 OOM |
| **C（推荐，根治）** | 去掉 argon2：校验改为**恒定时间比较** `sha256(token)` 与存储的 `lookup`，发号时也不再跑 argon2 | 需要一次性迁移或双读旧记录；DB 泄漏时攻击者只拿到 sha256，对 192 位随机 token 无用 |
| **A（C 的加强版）** | 改存 `HMAC-SHA256(server_secret, token)`，配恒定时间比较 | 多一个要保管与下发的服务端 secret（文件或环境变量）；secret 泄漏等价于 DB 泄漏 |
| ~~D~~ | 调低 argon2 的 `m`（19 MiB → 1 MiB） | ❌ 不推荐：既没消除"并发无上界"，又削弱了唯一的理论保护 |

**前置决策**：现在没有任何低熵 key 的入口，所以 C/A 成立。**若将来要支持"运维自定义 key"
（口令式、可猜），必须在入口强制最小熵/最小长度**——这条要落进入口校验，而不是留作注记。

### 验收

1. **峰值内存与并发无关**：并发 N 个**不同 token** 的首次请求（N = 64 / 300），RSS 峰值不随
   N 增长（C/A），或上界 = 信号量宽度 × 19 MiB（B）。
2. 迁移可认证：既有 `$argon2id$` 记录在切换后仍能通过（迁移或双读），有测试守着。
3. 既有语义一条不少、各自有测试：吊销即时生效（`cred_version` 不一致立即拒绝）、单飞
   （同一 token 并发只校验一次）、热路径 O(1) 不跑重哈希、恒定时间比较仍用于 admin token。
4. **指标口径要一起改**：`hlmg_key_verify_misses_total` 现在的含义是"真跑了 argon2 的次数"，
   去掉 argon2 后变成"缓存未命中次数"——HELP 文案与 README《可观测性》
   《并发上限与内存（实测）》里的表述必须同步，否则又是一处口径漂移。

### 基线数字（改动前，均已实测）

- 单次校验：`m=19456 KiB`、`t=2` → **19 MiB / 10–30 ms**。
- 生产命中率：21 516 个 200 请求 → `hits` 22 426 / `misses` **3**（缓存生效时这笔账几乎不发生）。
- 缓存开启后网关稳态内存：**58–61 MB**（128–512 并发），转发缓冲 ≈0.2 MB/请求。

## P2 — 协议级去重（提案已写，未实现）

- [ ] **`request_uid` + agent 侧去重表**，让"响应头超时"也能安全重试。设计见
      [`EXACTLY_ONCE.md`](EXACTLY_ONCE.md)：现有重试只覆盖建立阶段（开流/写帧失败，
      那时帧未完整送达，重放安全）；504 不重试是因为请求可能已在模型侧执行。
      要点：全局唯一 uid（UUIDv7 或 instance+counter）、agent 侧 `InFlight/Done` 表、
      重复请求按"等待复用/明确拒绝"处理、流式只在"零字节响应"窗口内可复用、
      **帧协议不兼容变更**（需升级编排）。验收必须以上游调用次数为准，而不是客户端成功率。

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
- [x] **慢客户端无限占并发槽（2026-09-18 已修，三处都设了上限）**：以前有三处客户端侧等待
      没有超时，任一处都能让在途请求永久占住准入票据（实测云端沉淀 8 个僵尸槽位：
      `hlmg_active_requests` 恒为 8、`hlmg_request_count − Σ状态码 = 8`，只能重启恢复）：
        ① 读请求体（`Bytes` 提取器）→ 改为逐块读 + 停滞超时 → 408；
        ② 写响应体通道（`tx.send().await`）→ 停滞即取消上游并结束响应体；
        ③ **hyper 往 socket 写**（应用层修不到的那一半，数据已在缓冲里）→ IO 层
           `io_stall::WriteStall`，连续 `client_stall_secs` 写不进一字节就断开连接。
      语义统一为"**停滞**"而非"总时长"（有字节流动就续期），所以慢客户端不会被误伤；
      三处共用 `client_stall_secs`（默认 60s）。回归测试 `tests/e2e/stalls.rs`（判据：
      `max_concurrent_requests: 1` 下后续请求不得 429）+ `io_stall` 单测，均已红检。
      **仍未做**：响应体**内存缓冲上限**（DESIGN §11.2 与本项原本合并做的那半）——
      现在通道是 32 块的有界队列，但 hyper 侧仍会缓冲到 socket 缓冲被写满为止。
- [ ] **Cancel→上游缺上游侧断言**（原与本项相邻，仍缺）：`mock-llm` 没有"请求被取消"的
      可观测信号（新加的 `/v1/flood` 提供了持续产出的上游，但还没暴露"被中途丢弃"的计数）。
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

### 后续一轮文档更新（已验证缓存 + 每事件 CPU 实测）

- `README.md`：`/metrics` 补 `hlmg_key_verify_hits_total` / `_misses_total` 的告警用法；
  `verified_cache_max` 补生产实测（hits 22 426 / misses 3）；新增《agent 每事件的 CPU 成本》
  （成本随事件数而非字节数、sys 占 73–78%、单 agent 上限 ≈6 000 事件/秒）；目录结构 `quinn` → `s2n-quic`。
- `DESIGN.md`：§5.2 认证改为三步流程并补「已验证身份缓存」设计表；§3/§4.1/§5/§6 的 `quinn` → `s2n-quic`；
  §11.4 的 key 校验一行标注"单实例已实施"。
- `DEPLOY.md` §10：补 `cred_version` 列轻量迁移（只加列、旧 key 可用）与升级后的核对命令。
- **《并发上限与内存》整节重写**：原文把"每在途请求 15–20MB"当常态，而那是**缓存关闭**时的 argon2 成本。
  现改为两笔账（冷启动 19MiB/凭据 vs 转发缓冲 ~0.2MB/请求），并补同一台机器只改 `verified_cache_max`
  的对照实测（8 并发：172.8MB vs 31.6MB；64 并发：1236.5MB vs 27.1MB；128 并发关闭时 +1416MB 且 45% 失败）。
  同一旧公式还散落在 README 两处（压测小节、admission control 小节）与 `gateway_config.example.yml`，
  一并改为"仅缓存关闭时适用"。
- **`/metrics` 的坑**：`verified_cache_max: 0` 时 `hlmg_key_verify_{hits,misses}_total` 恒为 0（旧路径不加计数），
  已在《可观测性》写明，避免运维误判为"没有校验"。

- [x] **已实施：用量落库批量化（本轮）**。原来每个请求都 `spawn_blocking` 一次
      `INSERT ... ON CONFLICT`，实测把 2 vCPU 的上限摁在约 190 QPS（云端 515 个线程里 514 个
      卡在 futex 等同一把 `db` 锁）。现改为：热路径只做内存累加 → 后台每 1s 一个事务批量写
      **绝对累计值**（幂等、重启不重复累加）→ **SIGTERM/SIGINT 时强制再落库一次**，日志
      `usage flushed before shutdown keys=N`，正常关闭不丢数据（仅 SIGKILL/断电会丢最后一个
      flush 周期 ≤1s 的用量）。顺带开 `journal_mode=WAL` + `synchronous=NORMAL`。
      可信口径（只数 `status="200"`，同时记录 200 占比）下的对比在云端做：每请求 CPU 从
      0.55–0.9ms（改造前，2.1 核 ÷ 190 QPS）降到 **0.30ms**（改造后，0.149 核 ÷ 496 QPS），
      同一台 2 vCPU 的吞吐 ≈190 → **≈496**。⚠️ 当时那组本机 `oha` 对照的绝对 QPS
      （934 → 15 744）**不作引用**：oha 的 Success rate 含 503，口径不可信。
      **仍未实测：修好后的云端真实上限**——记录到的 496 是**出口带宽**的上限（ECS 下行
      ≈0.4 MB/s），不是网关算力的上限；要探算力上限得先解决带宽。
- [ ] **待评估：agent 侧事件批处理**。实测 agent 的开销由 SSE 事件**次数**决定（与字节无关，
      1 字节 → 101 字节的 payload 不改变 CPU/事件），而 `write_frame` 目前每事件一次 `write_all`
      且每次分配两个 `Vec`。可考虑攒批合并写，但需要两个端点同时改帧协议 → 属协议变更，先不动。

## 重建蓝图 §6 未修项

> 来源：`REBUILD.md` §6 的 12 条验收断言。它那列"反面案例"钉在 `745e8e8`，其中一部分
> 此后已经修掉；**本节只登记仍未修的**，避免同一件事在两处各维护一份。行号对应 `6609a8c`。

- [ ] **R1 帧头固定自描述 + golden bytes 契约测试**：线格式仍是 `[u32 BE 长度][postcard 枚举]`，
      帧类型 tag 就是**变体声明序号**（`crates/proto/src/io.rs:29-33`、`crates/proto/src/frame.rs:7-43`）
      ——增删变体即破坏线格式，且没有 golden bytes 断言兜住。
- [ ] **R2 按帧类型分设长度上限**：`MAX_FRAME = 64 MiB` 硬编码，且按声明长度直接
      `vec![0u8; len]`（`crates/proto/src/io.rs:11,54-62`）——敌意前缀声明 64 MiB 就真分配 64 MiB。
      目标：上限按帧类型分设，分配量对声明值不敏感（计数型分配器断言）。
- [ ] **R3 读路径合一（取消安全）**：现在有两条读路径——`read_frame`
      （`crates/proto/src/io.rs:43`，`read_exact` 包装、不可取消）与 `FrameReader`
      （`io.rs:100`，走 `DribbleReader`，`io.rs:287`，可取消）。`read_frame` 仍用在控制面
      `crates/gateway/src/quic.rs:87`。目标：只留可取消的那条。
- [ ] **R4 EOF 四格分明**：`read_frame` 读 4 字节前缀时**任何 `UnexpectedEof` 都返回 `Ok(None)`**
      （`crates/proto/src/io.rs:47-53`）——1–3 字节的头部截断被当成干净关闭。`FrameReader`
      那侧已经分清了（`io.rs:108-115`，测试 `frame_reader_truncated_frame_errors`），差的只是老路径。
- [ ] **R6 "流即会话"可断言**：首帧必须是 `ProxyRequest`、后续帧 `request_id` 必须一致
      ——现在既无断言也无日志，不一致只会表现成"上游好像没在收流"。
- [ ] **R8 原子占位改 CAS**：`Admission::try_enter` 仍是 `fetch_add` 后回滚
      （`crates/gateway/src/metrics.rs:83-92`），并发下存在"双双误拒"窗口。
- [ ] **R9 背压按字节有界**：回写客户端的通道仍是 `mpsc::channel(32)`，**按条数**有界
      （`crates/gateway/src/http_proxy.rs:566`）——大帧场景下"32 条"不等于"字节有界"。
      相关的"响应体内存缓冲上限"见上文 P1。
- [ ] **R10 总时长上限**：`timeout_secs`（120s）是响应体**逐帧空闲**超时，没有整请求总时限
      （`DESIGN.md` §5 自认）。SSE 长流不能被总时限误杀，动之前要先把语义想清楚。
- [ ] **R11 延迟分位数**：`hlmg_request_duration_ms` 只有 sum，没有直方图
      （`crates/gateway/src/metrics.rs:316`）——"p99 变差"从求和值里看不出来。
- [ ] **R12 healthz 豁免闸门 + 深度检查**：`/healthz` 恒返 `"ok"`
      （`crates/gateway/src/http.rs:287-289`），且只有 `/metrics` 豁免准入（`http.rs:357-359`）
      ——闸门打满时健康检查会 429，把"慢"放大成"全挂"。
- [ ] **R12 drain 式关闭**：`Gateway::shutdown`（`crates/gateway/src/lib.rs:290`）目前只是
      `abort()` 掉四个任务（两个 HTTP 监听、QUIC accept、用量 flusher），**没有排空**——
      `systemctl restart`（SIGTERM）会把在途 SSE 流切断，客户端看到的是"流被截断"而非正常结束；
      agent 的隧道连接随进程消失、靠自身退避（≤30s）重连。做法：先停 accept → 宽限期 →
      到期前给在途流一个明确的结束/错误事件 → 再 abort。配套 `TimeoutStopSec`
      （`deploy/gateway.service` 未设 = systemd 默认 90s）必须 > 宽限期，且 `flush_usage_on_shutdown`
      是阻塞式 SQLite 写、无超时，卡住就只能等那 90s 后的 SIGKILL。
      注：`registry.rs::close_when_drained` 是"摘除单个 agent"用的，不是进程退出路径。

**已修、不要再照 §6 做一遍的**：R7 票据绑响应 body（钉点时即正确）、R10 的
`open_bi`/写帧/agent 侧握手三项超时、R11 的 `agent_id` 进日志与 agent 拒绝按 `reason` 分源、
§5.1 的 `hlmg_agents` 语义（已拆出 `hlmg_agents_healthy`）。
