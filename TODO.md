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
      1. **error.type 按状态码映射**（`openai::error_response`，唯一构造器）：400→
         `invalid_request_error`、401→`authentication_error`、403→`permission_error`、
         404→`not_found_error`、409→`conflict_error`、429→`rate_limit_error`、
         5xx→`server_error`、其余→`api_error`
      2. **429 响应带 `Retry-After: 60`**（限流/配额拒绝，SDK/脚本退避依赖）
      3. **`x-request-id` 响应头**：metrics_middleware 确定隧道 id（`req-<u64>` 沿用、
         其他形状分配新号，唯一分配器见 `gateway::request_id`），规范化的 `req-{n}`
         写回入站 headers 供 proxy 复用为隧道 request_id——HTTP 层/隧道帧/日志
         三方对账一致；响应头回显客户端原值，不一致时日志另记 `client_request_id`
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
        · **网关行为层（代码能解决）**：响应头超时**被当成"隧道已死"**——`proxy/mod.rs:530`
          的 head 超时分支**无条件**调 `registry.evict()`；而摘除计数与开流超时**共用**
          （`registry.rs:148` 的 `TUNNEL_TIMEOUTS_BEFORE_EVICT = 3`），且**只在收到响应头时清零**
          （`registry.rs:151` 的 `note_tunnel_op_ok`，唯一调用点 `proxy/mod.rs:507` 的
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
- [x] **进程级优雅关闭（网关侧已补齐 drain）**：gateway/agent 注册 SIGTERM/SIGINT（`tokio::signal`），
      收到后打 INFO 日志 → 调用 `Gateway::shutdown()` / `Agent::shutdown()` 退出；
      覆盖 systemd stop、Ctrl+C、harness job_kill 场景（对应 OPTIMIZATION.md A1 ✅）。
      网关侧现在是**两阶段有界关闭**（先停 accept 并排空，宽限期后才带明确事件切断），见下方
      R12 drain 式关闭；**agent 侧仍是立即 abort（无排空）**。
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
      1. 数据来源：`crates/gateway/src/usage_meter.rs` 透传层提取——非流式整包缓冲后解析
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
      5. 测试：单测（usage_meter.rs 提取/SSE 行/无 usage 估算 ×6、keystore 累加+持久化+
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
         usage_meter.rs 提取时顺手读 cached_tokens，算命中率 = cached/prompt）——
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
      （`http/mod.rs`，上限常量在 `body.rs`）——多模态图像/大上下文请求 413 无法调；config 加字段即可
- [ ] **首次部署 bootstrap（B 档，可选）**：第一个 API key 目前必须走 admin API
      （admin_token 配置文件明文）；考虑"首次启动自动建默认 key"或引导提示
- [ ] **usage 数据保留策略（B 档，可选）**：`key_usage` 无限累积（reset 是待定项）——
      长时间运行表会涨；建议与 reset 一并设计保留窗口/归档
- [ ] **镜像不含 `web/dist`（C 档，可选）**：`Dockerfile` 与 `docker-compose.yml` 均已就绪
      （容器化的路径映射、ENTRYPOINT 与 UDP 端口三个坑见 `DEPLOY.md` §11），**仅剩**容器内没有
      管理面板：访问 `/` 只得到"UI 未构建"的提示页。要做就在多阶段构建里加一个 pnpm 阶段把
      `web/dist` 打进去，或在 compose 里挂载 `web/dist` 并把 `ui_dir` 指过去。
- [ ] **结构化访问日志 JSONL（C 档，可选）**：tracing 文本日志给人看；如需审计
      "谁何时调了什么"可加 JSON 行落盘
- [ ] **keys.db 迁移规模化**：当前自动迁移（`storage/mod.rs::migrate_legacy_keys`）同步执行、
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
| 发号 | `storage/hash.rs:116` | key 恒为 `sk-` + 24 随机字节（**192 位熵**）；`/admin/keys` 只收 `name`，**不存在"运维自己填 key"的入口**（`admin.rs:98`） |
| 存储 | `storage/mod.rs:374` | 同时存 `lookup = sha256(明文)`（O(1) 索引）与 `key_hash = argon2id(明文)`（PHC 串，`m=19456 KiB / t=2 / p=1`） |
| 校验 | `storage/mod.rs:350` → `hash.rs:94` | 按 sha256 索引命中记录后，**再跑一次 19 MiB 的 argon2id 校验**（在 `spawn_blocking` 里，`proxy/mod.rs:81`） |
| 缓存 | `storage/verified.rs:55` | `(lookup, cred_version)` 命中即跳过校验；有 TTL 与上限（`verified_cache_max: 1650`） |
| 单飞 | `storage/verified.rs:57` | `inflight: HashMap<lookup, FlightSlot>`——**只对同一个 token 串行；不同 token 完全并行且无上界** |

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
4. **指标口径要一起改**：`hlmg_key_verify_misses_total` 现在的含义是"真跑了 argon2 的次数"
   （**2026-09 已把自增点从 `put` 挪到"将要跑 argon2"那一处，口径与 HELP 对齐**；在那之前
   `verified_cache_max: 0` 时它恒为 0，而每请求都在烧 19MiB），去掉 argon2 后变成"缓存未命中
   次数"——HELP 文案与 README《可观测性》《并发上限与内存（实测）》里的表述必须同步，
   否则又是一处口径漂移。

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

- [ ] **usage 内存累加竞态（少报用量）**：`gateway/src/storage/mod.rs:318-335` 在 map 无 cell 时
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
- [x] **Cancel→上游缺上游侧断言（2026-09-22 完成）**：`mock-llm` 现在有 `GET /stats`，里面的
      `cancelled` = **被中途丢弃的响应体数**（`CancelGuard` 的 Drop 计数：流正常跑完置
      `completed`，被 axum 丢掉 body 时 +1）。上游侧可观测 ⇒ H5 的 e2e 判据落在这里
      （`lifecycle::e2e_shutdown_cancels_a_client_stalled_stream_without_waiting_for_the_stall`：
      先读完整条 flood 断言 `cancelled == 0` 作对照，再制造"客户端停读 + 关停"断言 >0）。
- [ ] **公网入口 accept 出错即永久停服**：`gateway/src/lib.rs:175` 的 `listener.accept().await?`
      用 `?` 结束整个循环，外层只有一句 `warn!("https server stopped")`。对比 QUIC 侧专门做了
      `hlmg_quic_accepting` + `error!` 告警（`quic.rs:29-36`），HTTP 入口（唯一公网入口）反而没有
      等价信号——瞬时错误（EMFILE 等）就能让网关"进程活着但不监听"。修法：accept 错误重试 + 计数指标。
- [x] **Cancel→上游缺上游侧断言（2026-09-22 完成）**：见上一条——`mock-llm` 的 `GET /stats`
      暴露 `cancelled`（被中途丢弃的响应体数），不再只有"断开后 `/v1/models` 仍可用"这种间接覆盖。
      修法：mock-llm 暴露取消计数（或日志端点），e2e 断言断开后上游请求确实被中断。

### P2 — 契约 / 一致性

- [x] **`error.type` 分叉（已修）**：`openai::error_response` 自我声明是 OpenAI 错误格式的
      唯一来源，但 `admin.rs` 的 5 处（401 `auth_error` / 400 `invalid_request` /
      500×2 `gateway_error` / 404 `not_found`）与 `http/ui.rs` 的 SPA 404（`not_found`）
      手搓了 4 种只有本文件认识的名字。现在这 6 处全部走同一个构造器：
      401→`authentication_error`、400→`invalid_request_error`、404→`not_found_error`、
      5xx→`server_error`（**响应体的 type 值变了**，这是本条的目的）。
      测试：`admin::tests::{admin_errors_use_the_openai_error_shape, create_key_rejects_overlong_name}`
      （先红后绿）+ `http::ui::tests::ui_fallback_serves_spa_to_browser_but_404_to_api` 的 type 断言。
      仅剩的"自有名字"是 `web/` 前端自己的展示文案，与协议面无关。
- [x] **`x-request-id` 只在 `req-<u64>` 形状下才等于隧道 `request_id`（已修）**：
      拆分前 `metrics_middleware` 与 `proxy` 各持一个从 1 开始的静态计数器，UUID 客户端
      （Codex/DSH 的真实形态）让两个数列独立递增 → 撞号；e2e 在旧代码上实测同一 agent
      连续收到 `request_id = [1,1,2,2,3,3]`（先红后绿：
      `chain.rs::e2e_tunnel_request_id_is_unique_across_x_request_id_shapes`）。
      修法：`gateway::request_id` 作**唯一**分配器（`req-<u64>` 沿用、其他形状分配新号），
      中间件把规范化的 `req-{n}` 写回入站 headers 供 `proxy` 原样使用；响应头仍回显客户端
      原值，两者不一致时访问日志同时记 `request_id` 与 `client_request_id`。
      **未**采用"帧内改用字符串"：动协议字段类型要改 proto/agent/mock-llm 三处，
      收益只是省掉那条日志映射。
- [ ] **`extract_model` 卡住非 chat 的 `/v1/*`**：`proxy/mod.rs:28-34` 的 `extract_model`
      对 catch-all 路由（`http/mod.rs:27-34` 的 `/v1/{*rest}`，注册了 GET/POST/PUT/DELETE/PATCH）
      **所有方法与路径**都要求 body 是带 `model` 的 JSON（调用点 `proxy/mod.rs:81-86` → 400）→
      `GET /v1/files`、`DELETE /v1/files/{id}`、multipart（`/v1/audio/transcriptions`）现在一律 400，
      与 DESIGN §5.1"一律透传"冲突。修法：按路径/方法白名单要求 model（chat/completions、
      embeddings…），其余透传。
- [ ] **A3 类型化错误收尾**（OPTIMIZATION.md 已改标 ⚠️ 部分）：`Agent::start`
      （`agent/src/lib.rs:40`）与 `tls::https_server_config`（`gateway/src/tls.rs:51-54`）仍返回 anyhow；
      `config_err`、`AgentError::Forward`、`GatewayError::Sqlite` 是从未被构造的死变体。
- [ ] **Makefile `deny` 目标 ≠ hook/CI**：目标只跑 `cargo deny check licenses`，而 pre-commit hook
      与 CI 跑完整 `cargo deny check`（广告语已改，行为未变）。二选一：把目标改成完整检查，
      或明确 `make check` 不含完整 cargo-deny。
- [ ] **工具链没真的锁版本 → 本地与 CI 的 lint 会漂移**（`OPTIMIZATION.md` 的 E2 已从 ✅ 改标 ⚠️ 名义）：
      `rust-toolchain.toml` 是 `channel = "stable"`（**浮动 channel，不是钉版本**），
      `.github/workflows/ci.yml:18-21` 用 `dtolnay/rust-toolchain@stable`——**不读那个文件**，
      装的是 CI 当刻的最新 stable（步骤名却叫 `Install Rust (rust-toolchain.toml)`），
      `Cargo.toml` 也没有 `rust-version` 兜底。后果实测过：`clippy::result_large_err`
      只在 CI 触发、本地（stable 1.97.1）无论加不加 `-D` 都不报，于是"本地全绿 → CI 红"。
      修法：`channel` 钉到具体版本（与 CI 一致）+ CI 侧指向同一版本（别再用 `@stable` 隐式浮动）
      + 在 `[workspace.package]` 补 `rust-version` 声明 MSRV；升级工具链变成一次显式提交。
      根因不清掉，后面每轮 CI 都可能冒出新的 nightly/stable 新 lint（例如 `Atomic::fetch_update`
      弃用就是靠本地 nightly 才提前发现的，见本文件「坏味道 / 清理」里那条）。
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
- [x] **重复逻辑（认证+限流这一半已修，2026-09）**：`proxy` 曾内联复制一份已封装的
      认证 + 限流。现在两条路径（`/v1/{*rest}` 与 `/v1/models`）都走 `auth::authenticate`，
      401/429 的文案与顺序只存在一处：`auth.rs`。另一半未修：`Accept: text/html` 探测
      仍复制两份（`http/ui.rs:34` 与 `http/api.rs:53`）。
- [x] **`UsageCollector` 位置与自我声明矛盾（2026-09 已修）**：它原先是"有状态的状态机住在
      `proxy/mod.rs`"，与 `usage_meter.rs` 自称"只含纯函数"、OPTIMIZATION S1 把 proxy 限定为
      "代理转发"三方矛盾。**两个选项都没选**：它没有搬进 `usage_meter.rs`（那会让"纯函数"
      那一格也不再成立），而是独立成 `proxy/usage.rs`——策略（何时提取/估算/结算）自己一格，
      纯函数在 `usage_meter`，落库在 `storage`，`proxy/mod.rs` 只剩转发编排。
- [ ] **前端四份独立 `/metrics` 轮询**：`Layout.tsx:24`、`Overview.tsx:9`、`MetricsPage.tsx:10`、
      `Agents.tsx:61` 各实例化一个 `useMetricsHistory()`（各自 5s 轮询、各自一份历史）。抽 context 共享。
- [ ] **小体积/常量类**：`Agents.tsx:72` 用 `error.message.includes("404")` 嗅探状态码
      （`ApiError.status` 就在手边）；`Agents.tsx:28` 硬编码 `agent_stale_secs` 的默认值 `15`；
      `registry.rs:124,151,158` 三处裸比较 `"*"`；`extract_model -> Result<String, ()>` 丢掉失败原因；
      `HeadOutcome::Error(u16, String)` 用裸状态码。
- [ ] **死代码 / 死常量**：`KeyStore::authorize_id`（`storage/mod.rs:210`）、`Metrics::request_count`
      （`metrics.rs:98`）、`HISTORY_LEN` 被导出但 `useMetricsHistory.ts:41` 硬编码 `60`。
- [x] **`Atomic::fetch_update` 已弃用 → 改 `try_update`**：`registry.rs:406`（`try_acquire`
      抢并发槽位那处）。nightly 1.100.0 的措辞是 `deprecated: renamed to try_update for
      consistency`——**纯改名**，签名与返回值语义完全一致（本地实测对照：成功路径两边都
      `Ok(prev)`、闭包返 `None` 时两边都 `Err(cur)`，原子终值也相同）。`try_update` 在
      **stable 1.97.1 上就能编译**，所以不必等新 stable，一行即可消掉未来的 deprecation 警告；
      注意它现在只在 nightly 报警，稳定版 CI 不会提示（这也是"工具链没锁版本"那条的连带损失）。
      **2026-09 已改**：`try_acquire_excluding` 里现在是 `try_update`（该处行号已随重构移动到
      `registry.rs` 的抢槽位分支内），并在原处留了"为什么用 `try_update`"的注释。

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
  测试总数（85 → 119）、模块地图补 `usage_meter.rs` / `error.rs`、A3 与 C3 的状态标注更正。
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
      `usage flushed before shutdown keys=N`。关闭时先排空/收尾、**最后**才强制落库，所以排空与收尾
      期间结算的用量也在里面；仍可能丢的只有"强制落库之后、进程退出之前"那一瞬（SIGKILL/断电则丢
      最后一个 flush 周期 ≤1s 的用量）。顺带开 `journal_mode=WAL` + `synchronous=NORMAL`。
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
      （`crates/gateway/src/proxy/mod.rs:566`）——大帧场景下"32 条"不等于"字节有界"。
      相关的"响应体内存缓冲上限"见上文 P1。
- [ ] **R10 总时长上限**：`timeout_secs`（120s）是响应体**逐帧空闲**超时，没有整请求总时限
      （`DESIGN.md` §5 自认）。SSE 长流不能被总时限误杀，动之前要先把语义想清楚。
- [ ] **R11 延迟分位数**：`hlmg_request_duration_ms` 只有 sum，没有直方图
      （`crates/gateway/src/metrics.rs:316`）——"p99 变差"从求和值里看不出来。
- [x] **R12 healthz 深度检查（2026-09-22 完成）**：`/healthz` 现在是真探针——
      **200 ⇔ 隧道入口仍在接受新 agent**（`hlmg_quic_accepting`），否则 `503` + `status:"degraded"`
      + `detail`（处置：重启网关）；body 改成 JSON，同时报 `agents.registered` /
      `agents.healthy` / `agents.oldest_last_seen_secs_ago`（与 `Registry::status` 同源，
      也用上了这个此前只进失败日志的接口）。
      - 为什么**只有**隧道入口进状态码：它是唯一一个"探针还答得上、但实例已经没用"的故障
        （QUIC 端点停摆后进程/systemd/HTTP 入口/`/metrics` 全正常，而此后每个 `/v1` 都 503）。
        HTTP 入口自己不查——它一停探针本身不可达，失败即是信号。
      - 为什么 agent 数**只在 body**：没有 agent ≠ 进程不健康；塞进状态码会让"刚启动、还没注册"
        触发摘除/重启循环，而重启并不能让 agent 出现。
      - 配套不变量：`Gateway::start` 现在等 `quic::await_accepting`（5s 上界，超时只告警），
        于是「`start()` 返回 ⇒ 隧道入口接受中」成立，探针不会在启动窗口里误报 degraded；
        新增 `Gateway::tunnel_accepting()` 作为它的程序化读数。**实测**：把那次等待去掉后
        e2e `lifecycle::e2e_healthz_reports_the_same_agent_counts_as_the_api` 3 次里红 2 次
        （真竞态），加上即确定绿。
      - 证据：单测两条（degraded 时必须 503 + detail；接受中时 200 + 三个 agent 字段且空注册表
        时 `oldest_last_seen_secs_ago` 为 `null`）+ `quic::tests::await_accepting_waits_for_the_mark_and_gives_up_on_timeout`
        （延迟 60ms 标记时必须**等**它，且超时要返回 false 而不是卡住启动）+ e2e
        `lifecycle::e2e_healthz_reports_the_same_agent_counts_as_the_api`（真 agent 注册后
        body 计数与 `agent_count()`/`healthy_agent_count()` 逐字一致；心跳过期后 registered 仍 1、
        healthy 变 0 而状态码仍 200）。
      - **明确不在本条**：落库可写性——唯一可靠判据是"真写一次"，而 SQLite 尚无 `busy_timeout`
        （P2-7），探针写入可能撞 `SQLITE_BUSY` 把健康实例判死；要做得先落 P2-7。用量 flusher
        任务是否还活着也不在探针里（它死了只影响落库，把"落库坏了"变成 503 会引入重启，而重启
        修不了磁盘）。
      - ⚠️ 对外契约变更：`/healthz` 的 body 从纯文本 `ok` 变成 JSON（状态码语义只多不少——
        原先恒 200，现在只在隧道入口停摆时 503）。只按状态码判的 `curl -sf` / Docker
        `HEALTHCHECK` / `scripts/bench-*` 不受影响；`README.md` 的《可观测性》与 `DEPLOY.md`
        已同步。（闸门豁免那一半早已修：`limit = 0` 绕过准入，
        `observability::tests::healthz_is_exempt_from_the_admission_gate` 锁住。）
- [x] **R12 drain 式关闭（已实施）**：`Gateway::shutdown`（`crates/gateway/src/gateway.rs`）
      现在是**有界四阶段关闭**：
      ① **停 accept**：广播 `ShutdownPhase::Draining`，公网入口的 accept 循环返回并 drop
         `TcpListener`（新连接被拒），**在途请求继续正常跑**；
      ② **排空**：等 `hlmg_active_requests` 归零或到 `shutdown_grace_secs`（默认 15s）；
      ③ **收尾**：到期仍有在途 → 广播 `Terminating`，在途 **SSE** 收到一个明确的
         `event: error`「response is incomplete」事件后**干净结束**（刻意不用 `data: [DONE]`：
         那是"正常完成"标记，用它等于谎报），同时向上游发 Cancel 并结算已转发用量；
         **非 SSE 没有合法的"追加事件"语义**，只能诚实截断。随后给 1s 收尾窗口；
      ④ **有界落库**（`shutdown_flush_secs`，默认 10s，跑在阻塞池上）→ **abort** 三个任务。
      配套：`deploy/gateway.service` 未设 `TimeoutStopSec`（systemd 默认 90s），必须**大于**
      `shutdown_grace_secs + shutdown_flush_secs + 1s 收尾窗口`。验收见
      `crates/gateway/tests/e2e/lifecycle.rs`（排空、在途 SSE 事件两条）。
      注：`registry.rs::close_when_drained` 是"摘除单个 agent"用的，不是进程退出路径。

**已修、不要再照 §6 做一遍的**：R7 票据绑响应 body（钉点时即正确）、R10 的
`open_bi`/写帧/agent 侧握手三项超时、R11 的 `agent_id` 进日志与 agent 拒绝按 `reason` 分源、
§5.1 的 `hlmg_agents` 语义（已拆出 `hlmg_agents_healthy`）。

## 2026-09-21 结转：本轮评估（gateway / registry / storage）的收尾项

> 三份评估的 §7 迁移计划都已执行到"可单独发布"的程度（storage `6f5cc74`…`9719d26`、
> registry `d0f1d39`…`710a5a8`），**本节只登记仍未做的**，省得下次再从评估正文里翻。
> 评估正文在 `docs/*-assessment*.md`，**那份是 gitignore 的本地取证记录**（不入库）：
> 过程与并集裁决看那里，可执行清单看本节。

- [x] **A. 锁中毒兜底（全 crate 完成，2026-09-21）**（`PROJECT_SCAN` P2-12 / registry 评估 M2）
      - 已做：三个助手提到 crate 级 `crates/gateway/src/sync.rs`（`lock_or_recover` /
        `read_or_recover` / `write_or_recover`，模块头写明"唯一允许的加锁方式"），
        调用点全部替换——storage 26 处、`metrics.rs` **14** 处、`registry.rs` 生产代码
        **12** 处（另有 3 处测试内的读取保持原样）。
        **补（2026-09-22）**：当时"全 crate 完成"说早了——`ratelimit.rs:38` 与 `ui.rs:66,75`
        仍漏在外面（`crates/gateway/src/` 并集评估的三份独立样本一致命中）。现已改走
        `lock_or_recover` 并各配一条中毒测试；机器化核验确认生产代码里已无裸加锁。
        这条纪律**没有强制点**（无 lint 拦新的裸锁），只能靠复核。
      - 测试：`storage` 三条（毒化 runtime / db / entries+inflight）+ `metrics` 一条
        （毒化后 `/metrics` 仍渲染出中毒前后的计数）+ `registry` 一条（毒化后仍能注册并
        选路），共 5 条 `a_poisoned_*`，都在修复前**先红**（panic 就发生在被毒化的
        `.unwrap()` 那一行）。
      - 后果（备忘）：`status_counts` 等中毒 ⇒ `/metrics` 永久 500（排障时最需要它）；
        registry 表中毒 ⇒ 注册/选路/准入永久失败；`runtime` 中毒 ⇒ 每个 `/v1/*` 都 500。
      - M2 的另一半（"写锁内含外部调用与 `tokio::spawn`"）**此前已修**：`register` 与
        `evict` 的写锁范围只够 map 与原子量，关闭动作与 `defer_close` 调度留在锁外，
        代码里有纪律注释（`registry.rs` 的 `register`/`evict`）。

- [x] **B. 公网入口：握手/请求头超时 + 连接数上限（2026-09-21 完成）**（`PROJECT_SCAN` P1-1 / 评估 H8）
      - 已做：① `http1::Builder::new().timer(TokioTimer::new()).header_read_timeout(client_stall)`
        —— hyper 默认那个 30s 请求头超时此前**静默失效**（`Time::Empty` 分支只打一条 warn），
        现在既生效又可配；② TLS 握手 `tokio::time::timeout(client_stall, acceptor.accept(..))`，
        超时记 WARN 并断开；③ 新旋钮 `max_entry_connections`（默认 1024，0 = 不限）：
        **先取额度再 accept**，满额时暂停 accept、新连接留在内核 backlog 排队。
      - 为什么这三处特殊：它们是整条请求链上**唯一"客户端会等、服务端没有上界"**的步骤，
        而且不进准入闸门（闸门在解析出请求之后才生效）→ 只吃 fd 与任务，此前只受 NOFILE 约束。
      - 证据：`tests/e2e/entry_limits.rs` 三条（半开握手 / 半个请求头 / 额度满时排队），都**先红**。
      - 明确不在本条：`listener.accept()` 拿到 `Err`（EMFILE）仍会结束整个 accept 循环 —— 那是
        P2-10（第 2 批），**仍未修**；本条只是让它不再能被半开连接触发。

- [x] **C. 其余 e2e 的等待全部上界（2026-09-21 完成）**（`PROJECT_SCAN` P2-17 的剩余）
      - 已做：`common.rs` 新增 `test_client()` / `test_client_within()`——**整条请求（含读响应体）**
        的总超时为 `STEP_TIMEOUT`(30s)；**34 处** `reqwest::Client::new()` 换成它（admin 5、
        agents 11、chain 9、https 1、head_timeout 3、lifecycle 2、evict_close 1、metrics 1、
        entry_limits 1）；另 6 处非 HTTP 的"本该完成"等待用 `bounded(step, ..)` 包住
        （5 处原始 QUIC 帧读：注册回应/控制流 EOF/ghost 心跳；1 处跨任务 `rx.recv()`）。
      - **刻意保持裸 client 的三类**（要的就是"卡住"）：`stalls.rs`（请求体/响应体停滞）、
        `write_backpressure.rs`（写背压）、`https::e2e_proxy_protocol_edge_cases`（多个断言
        期待"body 读到一半出错"，加总超时会变成"超时才出错"——断言仍通过但验的不是同一件事）。
      - 本来就有界、无需再包：`Gateway::shutdown`（排空+落库+收尾 ≈26s 上界）、
        `Agent::shutdown`（`abort()`）、`wait_for_agents`（自带 10s deadline）、
        raw agent 应答循环里的 `read_frame`（事件循环，靠连接关闭结束，不是"步骤"）。
      - 哨兵：`a_bare_client_waits_forever_while_a_bounded_one_gives_up` **在测试里同时证明**
        "裸 client 对黑洞连接不会自己放弃"（缺陷本身）与"带窗口的 client 会自己放弃"（契约）。
      - 注意：这些 client 与 `bounded` 共用同一个 `STEP_TIMEOUT`，所以窗口若调整（见 B 之后的
        讨论），全部一起变。

- [x] **D. 限流桶：键改 `key_id` + 吊销回收 + 空闲清扫（2026-09-22 完成）**
      （`PROJECT_SCAN` P2-19 / 评估 H3 的另一半；锁那半见上一条 A）
      - 已做：① **桶键从明文 token 改成 `key_id`**（`auth.rs` 里 `try_acquire(&key.key_id)`），
        `AuthenticatedKey` 随之不再持有明文 token（顺带删掉 `verify_api_key` 里那次
        `token.clone()`）。keystore 那边是"只存 sha256 索引 + argon2 哈希、明文不落盘"，
        而桶表是**长生命周期的内存状态**——拿明文作键等于把每个用过的 key 常驻到进程退出
        （`/proc/<pid>/mem`、core dump、panic 报告都带着它），还随轮换/吊销无上限增长。
        ② `RateLimiter::evict(key)`：`admin::delete_key` 吊销成功后立即回收该桶。
        ③ 空闲清扫 `Buckets::sweep`：**只丢"已回满 + 空闲 ≥ `IDLE_BUCKET_TTL`(10 分钟)"的桶**，
        每 `SWEEP_PERIOD`(60 秒) 至多一次全表 `retain`（取令牌保持 O(1)）。
      - 两个容易写错的点（都写了注释）：判据里必须**先把令牌按 `elapsed` 补到 `now` 再比**——
        补充是按需算的，只看存下来的 `tokens` 会让空闲桶永远停在"上次用完的样子"，
        一个都回收不掉；而**没回满的桶不能丢**——丢了等于白送配额。
      - 证据（先红）：`auth::tests::the_rate_limiter_keys_buckets_by_key_id_not_by_the_plaintext_token`
        修复前直接观察到桶键就是 `sk-…`；`admin::tests::deleting_a_key_also_drops_its_rate_limit_bucket`
        把那三行接线摘掉即红（`bucket_count` 1 ≠ 0）。另有 4 条：补速率（抽干→空闲 250ms→放行）、
        双 key 隔离、吊销回收、清扫只丢满桶——前两条是**特性钉**，改前改后都绿，防顺手改坏。
      - 明确不在本条：多实例各算各的（`DESIGN.md:240` 的登记项）、租户级总配额、Redis 外置配额。

- [x] **E. 路径穿越 P1-2：两道守卫都到位（2026-09-22 完成）**（`PROJECT_SCAN` P1-2）
      - **网关侧（§7 步骤 1，`439e78a`）**：`DELETE /v1/../api/delete` 这类路径原本会**原样**
        进隧道（catch-all 不做点段归一），agent 拼 URL 时被 WHATWG 归一成 `/api/delete`，
        持 key 者于是能驱动上游任意端点（Ollama 的 `/api/delete` 直接删模型）。现在在
        **认证之后、读 body 之前**判：不安全 → `400` + WARN（不读那 16MiB body、也不泄露
        "路径合法与否"给未认证探测）。判据是**保守拒绝**而非"归一后转发"——归一拦不住
        `%2e`/`%2f` 这类**由上游解码**的形态。
      - **agent 侧（本次）**：判据搬到 `proto::path::safe_upstream_path`，**网关与 agent 共享
        同一份实现**（与 `proto::headers` 的逐跳/凭据两张表同一模式）。agent 在拼上游 URL 前
        再判一次；不合法就回 `code: 400` 的 `Error` 帧（网关把帧里的 code 直接当客户端状态码
        → 客户端看到的就是 400）。
      - 为什么必须共享而不是各写一份：这是**同一条判据的两道防线**，两份实现会漂移，而漂移的
        方向恰好会是"后面那道更松"（第一道在远端，第二道才在放上游请求的本机）——纵深防御会
        静默失效。agent 侧那道还覆盖"新 agent 配旧网关"的混版本场景。
      - 两个刻意的边界：① agent **只判路径、不判 query**（先把 `?` 之后切开）——网关同样只判
        `uri.path()`，整串一起判会让 agent 比网关更严，把 `?x=/../` 这类合法请求 400 掉；
        ② 拒绝用 `Error` 帧而不是直接断流，否则客户端只会拿到一条没有因果的 502。
      - 证据：`proto::path::tests::safe_upstream_path_allows_only_verbatim_forwardable_paths`
        （从网关搬来，逐条不变）+ agent 5 条单测：越权路径不得拼出 URL（**摘掉守卫即红**）、
        合法 target 逐字转发、query 不参与判据、拒绝 = 400 Error 帧（内存 writer 解帧断言）、
        "裸拼接真的会被 WHATWG 归一"的前提钉；外加**接线级**一条
        `agent::tests::a_traversal_path_never_reaches_the_upstream_and_returns_400`——复用 agent
        已有的 QUIC 夹具（真连一条 s2n-quic 连接）让"假网关"写 PoC 进双向流、真跑
        `handle_stream`，断言 ① 回包是 400 Error 帧 ② **上游 listener 一次连接都没有**；
        把接线摘掉即红（5s 超时）。网关侧回归网是 e2e
        `chain::e2e_dot_segment_path_is_rejected_instead_of_forwarded`（**先红**：修复前实测
        转发过、上游归一后回 404）。

- [x] **F. 公网入口：`accept()` 出错不再永久停服（2026-09-22 完成）**（`PROJECT_SCAN` P2-10 / 评估 H2）
      - 缺陷：两条 accept 循环（HTTPS 与明文）都是 `listener.accept().await?`，**一次**暂时性错误
        （`EMFILE` 最常见，`nofile.rs` 记录线上实测 296 次）就结束整个公网入口：进程活着、
        systemd active、日志一行 warn，端口再也不接受连接。QUIC 侧有 `hlmg_quic_accepting` +
        `error!`，唯一公网入口反而没有等价信号。
      - 已做：① 两条近乎逐字重复的循环合并成**一个** `serve_entry`（差异只剩 `Option<TlsAcceptor>`）
        ——策略只有一处，改一处不会再漏另一边；② 失败**退避重试、绝不退出**：`accept_backoff`
        从 50ms 起翻倍、封顶 1s，退避期间也能被关闭信号打断；**没有退避的重试是忙等热循环**
        （CPU 满载 + 日志刷屏），比"安静地停摆"更难排查；③ 新计数 `hlmg_http_accept_errors_total`；
        ④ 失败的 accept 先把连接额度还回去，免得退避期间白占名额。
      - 取证到的一段历史：那 296 次 `EMFILE` 发生在**明文入口还在用 `axum::serve`** 的时期（它记
        日志后继续接受连接，所以网关没停摆）；`55c56f1`（2026-09-18，为写超时把明文入口也换成
        自研循环）之后这点容错丢了；HTTPS 入口从 `73365b0` 起就是 `accepted?`。README 的 FD 一节
        已把这段写进去。
      - 证据：`http::entry::tests` 三条。关键那条用**注入的假 accept 源**（真实 `EMFILE` 要耗尽整个
        进程的 fd，会污染同进程其它测试）先失败两次再给一个真连接，断言 ① 第三次连接被正常服务
        ② 计数为 2 ③ **退避真的睡过**（≥100ms，专门防"重试但没退避"）；把它退回旧行为（Err 分支
        直接返回）即红——实测 0.02s 就失败（端口不再接受连接）。另一条钉住"退避期间收到关闭信号
        要立刻退出，不能等满一个退避周期"。
      - 明确不在本条：`/healthz` 的深度（评估 R12）——它查不了自己的 HTTP 入口（入口一死探针本身
        就不可达），但 QUIC 入口停摆时确实看不到；`is_serving()` 也仍无生产消费者。


- [x] **G. 请求体路径：一次解析 + 帧里用 `Bytes`（2026-09-22 完成）**（评估 H6）
      - 缺陷（评估原文："16MiB 请求体在 async worker 上解析/拷贝 3–4 次"）：**两遍**全量 JSON
        解析（`extract_model` 一遍 + `estimate_prompt_tokens` 又一遍）、`body.to_vec()` 进帧、
        以及 postcard 序列化。**实测（release，16MiB 合法 chat body）改写了对成本的判断**：
        | 环节 | 改动前 | 改动后 |
        |---|---|---|
        | JSON 解析 | 3.6ms × **2 遍** | 3.6ms × 1（且 >256KiB 时走阻塞池，**不占 worker**） |
        | body 进帧 | 0.37ms 拷贝 | 移动（≈0；`Bytes` 引用计数） |
        | postcard 序列化 | **20.0ms** | **1.6ms** |
        即最大的一笔不是内存也不是解析，而是 **postcard 把 `Vec<u8>` 当"元素序列"逐字节过一遍
        序列化器**（12×）。评估里"瞬时数百 MB"那句只在 body 的**结构项**极多时成立（DOM 与结构
        数量成正比）；纯字符串内容时 DOM 与 body 同量级——这条已在并集报告里更正为实测口径。
      - 已做：① `Frame::{ProxyRequest::body, ProxyResponseBody::chunk}` 改 `bytes::Bytes`
        （postcard 因此走 `serialize_bytes` 一次写整块），**线上格式逐字节不变**——由
        `proto::io::tests::bytes_body_encodes_identically_to_a_plain_vec` 与"变体顺序一致"的镜像
        枚举钉住（新网关 + 旧 agent 的滚动升级仍然互通）；顺带消掉响应侧每 chunk 的一次拷贝
        （SSE 长流上按 chunk 累积）。② `usage_meter::request_facts` 一次解析同时给出 `model` 与
        prompt 字符数（`estimate_tokens_from_chars`），不再拼 16MiB 字符串再数。
        ③ 大 body（≥256KiB）的解析走 `spawn_blocking`，小 body 原地解析（避免每次请求多一次
        线程池往返）；阻塞池任务 panic 报 500 而不是把锅推给客户端的 400。
      - 证据：`proto` 的线上格式逐字节比对（空/单字节/跨 0x80/1KiB 四种边界 + 反向解码）；
        `usage_meter::tests::request_facts_parses_once_and_keeps_the_estimation_semantics`
        （估算口径逐条：content 字符串、分片数组只取 `text`、数字 content 跳过、无 messages → 0
        字符 → 下限 1、缺/空/非字符串 model 与非法 JSON → Err）；`proxy::tests::
        routing_takes_the_top_level_model_string_only`（路由判据不变）；`proxy::tests::
        request_facts_for_offloads_large_bodies_and_keeps_the_same_result`（阈值两侧同结果 + 非法
        JSON 必须报 400 而不是 500）；e2e 54 条全绿（真 QUIC 隧道两端现在传的就是 `Bytes` 帧）。
      - 明确不在本条：`extract_model` 那条"所有 `/v1/*` 都要求 body 带 `model`"的**策略**问题
        （卡住非 chat 端点）原样保留（`PROJECT_SCAN` 已登记，改它要按路径/方法白名单）；
        帧体进 postcard 的那次拷贝现在只剩 1.6ms/16MiB，且 streaming 帧写要动线格式处理，
        不值得再切一刀。


- [x] **H. 关停语义：在途转发任务不再活过 `shutdown` 返回（2026-09-22 完成）**（评估 H5）
      - 缺陷：`forward_body` 只在**循环顶部**查 `shutdown_terminating`，而它可以 park 在
        `tx.send` 上（客户端不读 → 通道满）直到 `client_stall`（默认 60s）。`Gateway::shutdown`
        的收尾窗口只有 1s ⇒ 它返回时那个游离任务还持有 agent 槽位（`SlotGuard`）与 QUIC 流，
        Cancel 也要 60s 后才发给上游（= 上游白算 token 一分钟）。
      - 已做：① 新增 `send_to_client_or_shutdown`——发送与 `Terminating` 赛跑，被卡住时立刻返回
        `SendOutcome::ShuttingDown`，转发循环因此马上走收尾分支（发"不完整"事件 + Cancel + 结算）。
        **`Draining` 刻意不叫停**（那个阶段只停 accept，在途响应必须跑完，丢一块就是数据丢失），
        所以那条分支是**重试发送**。② 关停时"不完整"事件的写入上限用新的
        `SHUTDOWN_EVENT_WRITE_TIMEOUT`（250ms）而不是 `client_stall`：正常读取的客户端微秒级就
        收下，不读的不能把关停拖住。③ 终止性的错误帧也走可叫停版本。④ 收尾窗口到点仍有在途时
        **WARN**（并说清那是 HTTP 连接任务在等客户端，不是转发任务泄漏）。
      - **刻意不做**：不在关停末尾 abort 这些转发任务——`usage.finish()` 的结算排在落库之前，
        abort 会丢掉它们尚未结算的用量。也**不**保证 `hlmg_active_requests` 归零：那张票据由
        响应 body（HTTP 连接任务）持有，客户端停读时要到 `client_stall` 才归还，与转发任务是否
        退出无关（这条已写进 `shutdown` 的文档，免得后人误判）。
      - 证据：`proxy::forward::tests::terminating_interrupts_a_stalled_send_but_draining_does_not`
        （容量 1 的通道灌满 → `Draining` 不许结束、`Terminating` 必须 500ms 内结束；另含"阶段
        发送端被 drop 也算收尾"）+ `a_stalled_send_still_reports_stalled_without_a_shutdown`
        （没有关停信号时停滞判定不变，仍记 `hlmg_client_stalls_total`）+ e2e
        `lifecycle::e2e_shutdown_cancels_a_client_stalled_stream_without_waiting_for_the_stall`
        （**上游侧**判据：`client_stall` 设成 30s、宽限 200ms，客户端读完响应头就停读，随后
        `shutdown()`；断言 5s 内 mock-llm 的 `/stats.cancelled` > 0。**退回旧的裸
        `send_to_client` 即红**——实测等满 5s 仍为 0）。
      - 顺带关闭记录里的缺口「`Cancel` → 上游确实被取消**缺上游侧断言**」（`mock-llm` 新增
        `/stats`，见本节上一条）。

- [x] **I. quic 每连接清理上 Drop guard（2026-09-22 完成）**（`PROJECT_SCAN` P2-11 / 评估 H10）
      - 缺陷：`accept_loop` 的每连接任务里是"先 `agent_connected()`、末尾 `agent_disconnected()`"，
        `handle_conn` 里则把注册表条目摘除写成末尾一句 `remove_if_same`。**panic 展开时末尾语句不
        执行** ⇒ `hlmg_quic_connections` 永久虚高、条目永久留在注册表（本仓库**没有 stale 清扫器**，
        心跳过期只是不再可路由），表现为 `hlmg_agents` 虚高 + `/admin/agents` 里的幽灵条目，
        只能重启。仓库其它资源（`AcceptingGuard`/`Admission`/`SlotGuard`）早就是 RAII，这是最后一处例外。
        另外 `agent_disconnected` 是裸 `fetch_sub`：在 0 上回绕会把 gauge 变成 `u64::MAX`。
      - 已做：① `Metrics::mark_agent_connected()` 返回 `AgentConnectionGuard`（Drop 减一），
        **删掉**旧的 `agent_connected`/`agent_disconnected` 两个公开方法——只留一条配对路径；
        递减改成饱和 `fetch_update`（第二道保险）。② 新增 `registry::Registration`
        （`new/note` + Drop 时 `remove_if_same`），`quic::handle_conn` 用它取代末尾语句。
        两条 Drop 路径覆盖**正常返回 / `?` 提前返回 / panic 展开**。
      - 证据：`metrics::tests::the_connection_gauge_is_released_even_when_the_task_panics`
        （在 `catch_unwind` 里持有守卫后 panic，断言 gauge 归零、counter 不回退）、
        `the_connection_gauge_never_wraps_around`；
        `registry::tests::registration_guard_removes_the_entry_on_drop_and_on_panic`、
        `registration_guard_removes_only_the_last_registration`（同名重复注册只摘最后一次；
        stable_id 不匹配时不许误删别人的条目）。**把两个 Drop 体改空即红**——实测两条断言同时失败。

- [x] **D. registry 评估 §7 步骤 6 的可选清理（2026-09-21 处置完毕：两项落地、两项裁定不做）**
      - ✅ **`pick()` 抽成纯函数**（`registry::pick`）：次序（新鲜 → 排除 → 模型 → 精确优先 →
        负载轻 → 心跳新）与两个错误变体（`NoAgent` / `NoModel`）都在一处；新增
        `pick_orders_exact_over_wildcard_then_lightest` 与 `pick_reports_no_model_when_none_declares_it`
        直接用条目断言规则（既有 4 条 `try_acquire_*` 测试同时证明行为没变）。
      - ✅ **`Registry::try_acquire` 收进 `#[cfg(test)]`**：生产零调用，但**单测里有 24 处在用**
        （我原先在 TODO 里记的"只有它自己的一条测试"是**错的**），所以选择"退出公开 API"而不是删——
        测试一字未改。`Registry::is_empty` 保留：`len()` 在，clippy `len_without_is_empty` 会报，
        代码里已写明"与 `len` 配对存在，不是死代码"。
      - ❌ **C4 双索引：不做**。评估 §2 的裁决是"**不要在没有 profiling 的情况下动**"——
        部署实测 `hlmg_agents 1`（n=1–4），扫 4 个元素比它旁边那次 HTTP 往返便宜；
        `note_tunnel_op_ok` 上方也写着同一条裁定。
      - ❌ **`tunnel_health` 拆分：不做**。按评估自己的否决条款（"只搬迁同一份状态"是**否决**理由），
        此时把 3 个 strike 计数 + `last_head_ok` 搬走恰好是"搬走计数、不搬走**决定**"——而决定
        （`Disposition`）已经在 `registry::report_*` 里，计数与判据也贴在 `Entry` 上。
        评估原话：C1 模块化是"**第二步的可选精化**，先有处置接口，再看计数是否需要自己的模块"；
        现在处置接口在、Entry 也不透明了，但**没有第二个消费者、也没有 profiling 说话**，
        所以先不付这份搬迁成本（真有需要再拆，那时 `Entry` 不透明的前提已经满足）。
