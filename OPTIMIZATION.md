# home-llm-gateway 优化方案（2026-09 定稿）

> 基于对项目全量代码的结构审查（workspace 结构、gateway/agent/proto/mock-llm、
> web 前端、测试与部署文件）。分四类优化项，标注优先级 / 工作量 / 收益，
> 按三阶段实施。状态：**方案定稿，未实施**。

---

## 一、结构优化（组织方式）

| # | 优化项 | 现状 | 方案 | 优先级/工作量 |
|---|---|---|---|---|
| S1 ✅ | gateway crate 按职责拆模块 | ~~混合~~ → `http_proxy.rs`（代理转发独立）、`keystore/hash.rs`（哈希原语独立）、`config.rs`（配置解析独立）；http.rs 只剩路由/中间件/fallback | 高 / 中 |
| S2 | e2e 测试拆文件 | `e2e.rs` 1199 行单文件（12 测试 + 大量辅助） | 按主题拆 `e2e/chain.rs`、`agents.rs`、`admin.rs`、`stream.rs` + `common/mod.rs`（证书/栈辅助） | 中 / 中 |
| S3 ✅ | 配置解析抽独立模块 | → gateway/agent 各建 `config.rs`（from_path/from_file + 14 个测试），main.rs 只留 CLI 入口与信号处理 | 中 / 低 |
| S4 ✅ | 共享代码去重 | ~~两处重复~~ → `proto::pem`（load_certs/load_key）+ `proto::headers`（is_hop_by_hop），gateway/agent 引用统一，测试移入 proto | 高 / 低 |

## 二、整体架构优化（运行时能力）

| # | 优化项 | 现状 | 方案 | 优先级/工作量 |
|---|---|---|---|---|
| A1 ✅ | 优雅关闭（TODO P1 已定稿） | ~~pending 永久挂起~~ → SIGINT/SIGTERM 监听（tokio::signal）→ 打日志 → shutdown() 干净退出；实机验证 SIGTERM 生效 | **高 / 中** |
| A2 | 隧道层可观测性 | metrics 只有 HTTP 层；QUIC 连接数/流数/重连次数无指标 | 加 `hlmg_quic_connections`、`hlmg_quic_streams`、`hlmg_agent_reconnects`（quic.rs/metrics.rs 挂钩） | 中 / 中 |
| A3 ✅ | 错误类型化 | ~~全 anyhow~~ → `error.rs` 定义 `GatewayError`/`AgentError`（thiserror），Gateway/Agent::start 与 tls 配置返回类型化错误，anyhow 只留二进制入口 | 中 / 中 |
| A4 | 配置热加载 | 配置只启动时读 | SIGHUP 重载运行时参数 | 低 / 高（**不做**） |
| A5 | 健康检查深化 | `/healthz` 恒返 ok | 可选深度检查（QUIC endpoint 存活、agent 注册数） | 低 / 低 |

## 三、代码质量优化

| # | 优化项 | 现状 | 方案 | 优先级/工作量 |
|---|---|---|---|---|
| C1 ✅ | registry 锁粒度 | ~~Mutex 全锁~~ → `RwLock`（register/remove 写锁，try_acquire/snapshot 读锁） | 高 / 低 |
| C2 | keystore 写操作异步化 | SQLite create/delete 在 async handler 里同步执行（阻塞 worker） | `spawn_blocking` 包写操作 | 中 / 低 |
| C3 | 转发零拷贝 | `ProxyResponseBody { chunk: bytes.to_vec() }` 每块克隆 | 帧 body 改 `Bytes`（reqwest bytes 直接复用，免拷贝） | 中 / 中 |
| C4 | 公共头过滤统一 | HOP_BY_HOP 过滤两处重复 | 归并到共享模块（与 S4 合并） | 高 / 低 |
| C5 | 帧类型微调 | `headers: Vec<(String,String)>` 每次分配 | 评估 HeaderMap-like / 容量预分配（收益小，先测再定） | 低 / 低（**不做**） |

## 四、工程化优化

| # | 优化项 | 现状 | 方案 | 优先级/工作量 |
|---|---|---|---|---|
| E1 ✅ | CI | ~~无~~ → `.github/workflows/ci.yml`：rust job（fmt/clippy -D warnings/test）+ web job（pnpm build） | 高 / 低 |
| E2 ✅ | 工具链锁定 | → `rust-toolchain.toml`（stable + rustfmt/clippy） | 中 / 低 |
| E3 ✅ | workspace lints | → `[workspace.lints]`（unsafe_code=deny、dbg_macro/todo=deny），各 crate 继承；现有 clippy 警告全部清零 | 中 / 低 |
| E4 | 版本与 changelog | 0.1.0 未动 | 0.2.0 + CHANGELOG（配合 P3 协议迁移约定） | 低 / 低 |

## 五、实施顺序（三阶段）

**阶段 1 — 快速赢项 ✅ 已完成（2026-09）**
- S4 + C4 共享代码去重（pem/headers 抽到 proto）
- C1 registry 换 RwLock
- E1 CI（fmt/clippy/test 跑通）
- E2/E3 工具链 + workspace lints

**阶段 2 — 结构性重构 ✅ 已完成（2026-09）**
- S1 gateway 模块拆分（http/config/keystore）
- S3 配置解析独立化
- A3 thiserror 错误类型化
- A1 优雅关闭（TODO P1 实现）

**阶段 3 — 深化**（按需）
- S2 e2e 拆文件
- A2 隧道层指标
- C2/C3 keystore 异步化 + 转发零拷贝
- A4/A5/C5 明确不做

## 六、明确不做（防过度优化）

- **A4 配置热加载**：当前场景无需求
- **C5 帧类型微调**：先 benchmark 再定
- **微服务化**：DESIGN.md §11.5 已明确单体优先
- **协议层改造（postcard → protobuf）**：TODO P3 已定稿，最低优先级

## 七、与既有规划的关系

- A1 优雅关闭：TODO P1 已定稿，本方案将其纳入阶段 2
- C2：TODO P1「keys.db 迁移规模化」提及的 spawn_blocking 思路延伸
- E4 版本号：与 P3 协议迁移的 0.2.0 版本校验约定一致
- 多 CA 信任根 / token 计量（TODO P1 已定稿）为独立功能项，与本文档无冲突
