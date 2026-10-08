# home-llm-gateway — 存储层多库抽象（设计；P0–P2 属重构，P3+ ⛔ 登记）

> **状态：设计已定，未实现。** 登记见 `TODO.md`《2026-10-07 存储层多库抽象》；
> 该节把这套设计切成两半——**P0–P2 是"不改变对外行为的重构"（按顶部范围约定可做）**，
> **P3/P4 是"新增依赖"与"多实例无状态化"（明令 ⛔，只登记）**。
> **触发问题**：后续要对接 MySQL / PostgreSQL，而今天的持久化层**写死了 SQLite**：
> 方言（DDL 类型、upsert 语法、加列探测）散在**生产路径 10 处 SQL** 里，加一张新表要写
> DDL 常量 + 装载 `SELECT` + upsert + 删除 + 加列迁移 + 结构体 + codec。
> **目标**：换库只换一个实现；**加表只声明表本身 + 写业务查询**。

**三句话**：
1. **端口比想象的小得多**——DB 只被 **4 个数据操作**碰（装载 / 插入 / upsert / 删除），
   其余 15+ 个方法**全纯内存零 IO**（§4.1）。所以这不是"给 ORM 换驱动"，是"抽一条很窄的缝"。
2. **因此不需要 async**——只有那几个操作碰 DB，而它们**今天就已经在阻塞池上**（§4.6）。
   为多库引入 async trait 是**过度设计**，会把 20 个方法签名和一堆调用点全拖下水。
3. **换库不难，难的是换库之后你会不会多副本**——那才会踩到今天**明确单写者**的用量与吊销语义（§3）。

---

## 1. 先划边界：抽象的是「持久化端口」，不是 `Storage`

`Storage`（`storage/mod.rs:89`）现在混了**四件事**，只有第 4 件该进抽象层：

```
                    ┌─────────────── Storage（公开 API 不变）───────────────┐
                    │                                                        │
   不该动 ──────────┤  ① runtime: RwLock<HashMap<lookup, KeyRecord>>         │  热路径内存索引
                    │     storage/mod.rs:95                                  │  （零 IO）
                    │                                                        │
   不该动 ──────────┤  ② verified::VerifiedCache                             │  argon2 结果缓存
                    │     storage/verified.rs                                │  + 单飞 + 版本校验
                    │                                                        │
   不该动 ──────────┤  ③ usage::UsageStore                                   │  绝对累计值、
                    │     storage/usage.rs                                   │  批量区间、增量口径
                    │                                                        │
   ★ 就抽象这一层 ──┤  ④ db: Arc<Mutex<Option<Connection>>>                  │  SQL 读写 +
                    │     storage/mod.rs:100                                 │  DDL + 迁移
                    └────────────────────────────────────────────────────────┘
```

**把整个 `Storage` 变成 trait 是错的**——那会把 ①②③ 拖进每个实现里，换一次库要把内存索引、
缓存、用量口径**各重写一遍**。要抽象的是**一条缝**，不是一堵墙。

## 2. 现状盘点（实测，非估计）

| 项目 | 事实 |
|---|---|
| 表数量 | **2 张**：`api_keys`、`key_usage` |
| 生产路径 SQL 点 | **10 处**（`mod.rs` 8 + `usage.rs` 2）；另有 1 处在 `#[cfg(test)]` 里 |
| 代码量 | `storage/` 共 2963 行（mod 1532 + usage 604 + verified 589 + hash 238）|
| 依赖 | `rusqlite 0.40`（bundled）——**唯一**的数据库依赖 |
| 连接 | **一个** `Connection` 藏在 `Mutex` 背后（`:100`）|
| API 形态 | `Storage` 的 **20 个公开方法全是同步 `fn`**，无一个 `async fn` |
| 测试 | `mod.rs` 31 个测试，其中 **12 个**直连真实 SQLite |
| 耦合面 | **16 个文件**提到 `Storage`（但见 §4.1：真正碰 DB 的调用点只有 **4 处**）|
| schema 版本机制 | **无**——没有 `user_version`、没有版本表，只有手写 `PRAGMA table_info` 探列（`mod.rs:586`）|

**方言硬点（全部要收进方言层）**：

| 位置 | 现状 | PostgreSQL | MySQL |
|---|---|---|---|
| `mod.rs:388` | `INSERT OR REPLACE` | `ON CONFLICT(id) DO UPDATE SET …` | `ON DUPLICATE KEY UPDATE …` |
| `usage.rs:233` | `ON CONFLICT(key_id) DO UPDATE SET c=excluded.c` | 同左 | `c=VALUES(c)` |
| `mod.rs:586`、`:941` | `PRAGMA table_info(t)` | `information_schema.columns` | 同 PG |
| `mod.rs:175`、`:185` | `TEXT` / `INTEGER` | `text` / `bigint` | `VARCHAR` / `BIGINT` |
| `mod.rs:177` | `lookup TEXT NOT NULL UNIQUE` | `text NOT NULL UNIQUE` | `VARCHAR(64) NOT NULL UNIQUE` |
| `enabled` | `INTEGER` 存 bool | 原生 `boolean` | `TINYINT(1)` |
| 占位符 | `?1` | `$1` | `?` |
| 唯一冲突错误码 | `SQLITE_CONSTRAINT_UNIQUE`（2067）| `23505` | `1062` |

### 2.1 必须显式决定、不能靠"翻译看起来一样"带过去的四点

**① `create()` 不该是 upsert —— 这是 P0 的第一件事。**

`create()`（`mod.rs:372`）今天写的是 `INSERT OR REPLACE`（`mod.rs:388`）。它在 SQLite 是
**删+插**，不是更新——所以未列出的列会**退回默认值**：插入列清单是
`(id, lookup, key_hash, name, created_at, enabled)`，**没有 `cred_version`**，
而内存里的 `KeyRecord.cred_version` 是 `bump_cred_generation()` 之后的值（`mod.rs:383`）。

**但结论不是"换个 upsert 写法"，而是 `create()` 根本不该是 upsert：**

- 它的语义是"**造一把新 key**"，不是"创建或覆盖"
- 主键冲突**不是天文概率**：`generate_id_key()` 的 id 只有 **4 随机字节 = 32 位**
  （`hash.rs:120-124`；192 位的是**明文 key**，不是 id）。按生日问题：

  | key 数量 | 至少一次主键冲突 |
  |---|---|
  | 500 | 0.003% |
  | 1,000 | 0.012% |
  | 5,000 | 0.29% |
  | 20,000 | 4.5% |

- 命中时 `OR REPLACE` 会**静默顶掉别人那一行**——受害者那把 key 直接失效
  （`lookup` / `key_hash` 被新 key 覆盖），而管理员收到 **201 Created**，全程无提示。
  更糟的是它对**任何**唯一索引冲突都靠"删掉那一行"解决：`lookup` 撞车会删掉**另一个 id** 的行
- 改成普通 `INSERT` 后：冲突 → `StoreError::Conflict` → admin 回 500 → 重试（或换 id 重试）

**所以 (a)/(b) 那个二选一应当取消——`INSERT OR REPLACE` 从代码里彻底消失：**

| 位置 | 今天 | 结论 |
|---|---|---|
| `create()`（`mod.rs:388`）| `INSERT OR REPLACE` | **改普通 `INSERT`**（冲突即错）|
| 用量 flush（`usage.rs:233`）| `ON CONFLICT(key_id) DO UPDATE` | **不动**——它**已经是**真 upsert |

**"真 upsert"作为端口能力仍然需要**（用量 flush 用它），只是 `create()` 不再用它。
端口因此有**两个**写操作：`insert`（冲突即错）与 `upsert_batch`（幂等写）。

**改动代价已核实为零：**

| 检查 | 结果 |
|---|---|
| 有没有测试依赖 `OR REPLACE` 的冲突语义 | ✅ **没有**——全仓只有 `mod.rs:388` 一处出现它 |
| 现有错误路径测试还成立吗 | ✅ 成立（`dbg_reject_insert` 触发器靠 INSERT 失败，与 REPLACE 无关）|
| 验收"31 个测试一个都不改" | ✅ 满足，只需**新增**一个冲突测试来钉死新语义 |

**② `u64` 映射到 PG `bigint` 是收窄。** `created_at` / `last_used_at` 是 `u64` 秒
（`mod.rs:381`）。PG `bigint` 是**有符号**（上限 2^63−1）——时间戳远小于此，**实际安全**，
但那些 `as i64` 现在散在多处（`mod.rs:395`、`usage.rs:246-250`），应收敛到**一处类型映射**。

**③ 190 QPS 那个结论未必跟着走。** 放弃"每请求写库"的理由写在 `usage.rs:292`：
每请求抢**全局 `db` 锁** + 提交事务，把 2 vCPU 摁在约 190 QPS。
但那是被**单连接 + Mutex** 摁住的，**不是被数据库摁住的**。换成带**连接池**的服务器库之后，
这个数字**必须重测**，不要把它当作"数据库写都慢"的既成事实带过去。

**④ `cred_version` 这一列今天是死重**（独立发现，与换库无关，但同一片代码）。
它不只"没被写对"——**它的值跨进程没有意义**：`cred_generation` 每次启动都是
`AtomicU64::new(1)`（`mod.rs:316`），**不从库里的最大值播种**（`bump_cred_generation()`，
`mod.rs:324`）。于是库里恒为 1、内存里是 2/3/4…，重启后两者又都回到 1；
而缓存比对的是**内存那份记录**，**没有任何东西读这一列的实际值**。

| 方向 | 做法 | 用途 |
|---|---|---|
| (A) 让它成真 | 内存计数器从库里 `MAX(cred_version)` 播种 + `create()` 真正写入 | 这才是**跨副本吊销传播**的天然载体 |
| (B) 删列 | 承认"凭据版本"是进程内概念，不落库 | 少一个会误导人的列 |

**两个都留到 P4 再定，P0 不碰**：它对多库抽象毫无必要，却会改变重启后的内存状态——
正是 §8 那条"别在换方言时顺手改语义"。而它的**唯一价值场景**（跨副本）属于阶段规则
明令 ⛔ 的"多实例无状态化"。**在那之前不要依赖这一列。**

## 3. 这是三个问题，不是一个

| # | 问题 | 难度 | 与"换库"的关系 |
|---|---|---|---|
| **①** | **SQL 方言**（类型、占位符、upsert、加列探测、错误码）| 低 | 直接相关 |
| **②** | **声明式表**（加表只写表本身）| 中 | 直接相关 |
| **③** | **共享状态语义**（多副本下的用量与吊销）| **高** | **换库的真正代价** |

**只做 ①② 就上 MySQL/PG，会在那一刻踩 ③。** 因为后端一变成服务器库，部署形态几乎必然变成
**多网关副本共库**，而今天的实现是**明确单写者**：

| 现状 | 代码事实 | 多副本后果 |
|---|---|---|
| 用量按**绝对累计值**周期覆盖写 | `flush_once` 写 `prompt_tokens = excluded.prompt_tokens`（`usage.rs:233-243`）| 副本 A/B 各持一份内存计数，**后写覆盖先写** → 账目少算（**这是钱**）|
| 累加写路径**只在测试里** | `persist()` 标着 `#[cfg(test)]`（`usage.rs:292`）| 加回累加写＝性能回退（但见 §2.1③）；不加＝多副本账目错 |
| 吊销靠**进程内**凭据代数 | `cred_generation: AtomicU64`（`mod.rs:107`）+ `verified` 缓存 TTL 30 分钟 | 在 A 上吊销，**B 最长 30 分钟仍放行** |
| key 索引是**进程内** HashMap | `runtime` 启动装载一次（`mod.rs:95`）| 在 A 上建 key，**B 不认识**，直到重启 |

## 4. 方案

### 4.1 端口的真实大小：**5 个方法，不是 20 个**（本节是整份方案的地基）

热路径**零 IO** 是既有设计（见 `storage/mod.rs` 模块注释），实测确认——DB **只**被这几处碰：

| `Storage` 方法 | 碰 DB？ | 证据 |
|---|---|---|
| `create` | ✅ INSERT | `mod.rs:388` |
| `delete` | ✅ DELETE | `mod.rs:433` |
| `flush_usage_once` / `flush_usage_blocking` | ✅ 批量 UPSERT | `mod.rs:494`、`:499` → `usage.rs:233` |
| `persist_usage`（`#[cfg(test)]`）| ✅ UPSERT | `usage.rs:296` |
| 构造期装载 | ✅ SELECT | `mod.rs:599`（keys）、`usage.rs:359`（usage）|
| `authorize` / `authorize_record` | ❌ 纯内存 | `runtime` HashMap |
| `list` | ❌ 纯内存 | |
| `usage_of` / `usage_snapshot` / `usage_has_pending` | ❌ 纯内存 | |
| `record_usage` / `accumulate_usage` | ❌ 纯内存 | |
| `verified_counters` / `argon2_runs` / `persistence_state` | ❌ 计数 / 启动自检结果 | |

**所以端口只有 5 个方法**（4 个数据操作 + 1 个建表/迁移）：

```
   ┌──────────────── Database（端口，同步）────────────────┐
   │  ensure_schema(&[TableSpec])       -> Result<()>     │  DDL + 迁移
   │  load_all(&TableSpec)              -> Result<Vec<Row>>│  启动装载
   │  insert(&TableSpec, &Row)          -> Result<()>     │  create：冲突 → Conflict
   │  upsert_batch(&TableSpec, &[Row])  -> Result<()>     │  用量 flush（幂等写）
   │  delete_by_pk(&TableSpec, &Value)  -> Result<bool>   │  delete
   └──────────────────────────────────────────────────────┘
        ↑ SqliteDatabase（现有行为的搬运，P0–P2）
        ↑ PostgresDatabase / MysqlDatabase（P3，⛔）
```

**`insert` 与 `upsert_batch` 刻意分开，不合并成"带 mode 的 upsert"**——两者的差别
**就是语义本身**（冲突报错 vs 幂等覆盖）。合成一个带开关的原语，会让人以为调用方
可以随便选，而 §2.1① 那个坑正是这么来的。

**推论**：这不是"给 ORM 换驱动"，而是"把 10 处散落 SQL 收成 4 个数据操作 × 3 个方言"。
方案的主体因此落在 **§4.3 声明式表**上，而不是驱动层。

### 4.2 方言层

```
   ┌───────────────┐        ┌──────────────────────────────────────┐
   │  领域代码      │        │  Dialect（每库一份，纯字符串生成）      │
   │  KeyRecord    │───────▶│  ddl_create(spec)                    │
   │  UsageRecord  │  spec  │  ddl_add_column(spec, col)           │
   └───────────────┘        │  ddl_create_index(spec, index)       │
                            │  columns_query(table)                │
                            │  upsert(spec)                        │
                            │  placeholder(i)                      │
                            │  is_unique_violation(err) -> bool    │
                            └──────────────────────────────────────┘
```

`Dialect` **只生成 SQL 字符串、只判错误码**，不碰连接、不碰数据——因此可以用**纯字符串单测**
覆盖三个方言，**不需要起数据库**。这是把它单独切出来的主要理由。

### 4.3 声明式表（要的那个"加表只写表本身"）

**目标**：加一张表 = 声明列与索引 + 写业务查询；DDL / 迁移 / 装载 / upsert / 删除**全部派生**。

```rust
table! {
    /// API Key（sha256 快速索引 + argon2id 哈希）
    api_keys {
        id:           Text @ pk,
        lookup:       Text @ unique,          // ← 上一版草案漏了这个，导致表达不了已有的表
        key_hash:     Text,
        name:         Text,
        created_at:   Int,
        enabled:      Bool = true,
        cred_version: Int  = 1,
    }
}

table! {
    /// 用量账本
    key_usage {
        key_id:             Text @ pk,
        name:               Text = "",
        prompt_tokens:      Int  = 0 @ additive,
        completion_tokens:  Int  = 0 @ additive,
        requests:           Int  = 0 @ additive,
        estimated_requests: Int  = 0 @ additive,
        last_used_at:       Int  = 0,
    }
}
```

**spec 至少要能表达（按现有两张表倒推，一条都不能少）**：

| 能力 | 依据 |
|---|---|
| 主键 | 两张表都有 `TEXT PRIMARY KEY` |
| **唯一约束** | `api_keys.lookup`（`mod.rs:177`）——**上一版草案漏了，会直接卡住 P1** |
| `NOT NULL` + `DEFAULT` | `enabled INTEGER NOT NULL DEFAULT 1`、`cred_version … DEFAULT 1` |
| 布尔语义 | `enabled` 三方言表示不同 |
| 可加列（`@additive`）| `key_usage` 的累加 upsert 形态 |
| 列序稳定 | `to_row/from_row` 按序对齐，且 `ADD COLUMN` 只能追加 |

**两档，建议先 A 后 B（不冲突——B 只是把 A 的常量与 codec 生成出来）：**

| | 形态 | 每表代价 | 备注 |
|---|---|---|---|
| **A（建议先做）** | `TableSpec` 常量 + 手写 `to_row/from_row` | ~15 行 | 零宏、易 review |
| **B（在 A 之上叠加）** | `table!` 宏，连结构体与 codec 一起生成 | ~8 行，零样板 | `macro_rules!`，**不引入新依赖** |

**关键：`key_usage` 里的领域逻辑不该被抽象掉**——`snapshot()`、`flush_once()` 的批量区间、
`accumulate()` 的增量口径、`UsageDelta` 的估算/精确之分。该归零的只有 DDL / 装载 /
upsert / 删除这部分样板。

### 4.4 迁移：要 schema 版本 + 有序步骤，不能只做"加列差集"

现状**没有任何版本机制**，只有手写探列（`mod.rs:586` 的 `table_has_column`）驱动 `ADD COLUMN`。
它覆盖不了：改名、改类型、加索引、数据回填，以及**顺序**。

建议：

```
  schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER)
       ↑ 版本号 + 已应用记录

  步骤表：有序的 Vec<Step>
    - AutoAddColumns(table)   ← 由 TableSpec 差集自动生成（覆盖最常用的一种）
    - AddIndex(table, index)  ← 由 spec 差集自动生成
    - Custom(version, fn)     ← 改名 / 改类型 / 回填：手写并登记
```

⚠️ **一次性数据迁移要隔离**：`migrate_legacy_keys`（明文 → argon2，`mod.rs:530`）是
**SQLite 历史包袱**，不进通用层、也不该让新后端实现它（新部署没有 legacy 数据）。
它属于 `Custom` 类别，且**只在 SQLite 实现里执行**。

### 4.5 错误模型：唯一冲突必须归一

今天 `rusqlite::Result` 与 `GatewayError` 混用。端口需要自己的错误枚举，其中**唯一冲突**
必须跨方言归一，否则上层写不出"重名就拒绝"这类逻辑：

| 方言 | 错误码 |
|---|---|
| SQLite | `SQLITE_CONSTRAINT_UNIQUE`（2067）|
| PostgreSQL | `23505`（`unique_violation`）|
| MySQL | `1062`（`ER_DUP_ENTRY`）|

→ `Dialect::is_unique_violation(&err) -> bool`，上层只匹配 `StoreError::Conflict`。

### 4.6 **不需要 async** —— 这一步我上一版判断错了，纠正如下

上一版我主张"端口用 `async fn`"，理由是"MySQL/PG 驱动都是异步的"。**那是过度设计**，因为：

1. 只有 **4 个数据操作**碰 DB（§4.1），其余 15+ 个是纯内存；
2. 那 4 个操作**今天就已经在阻塞池上**：
   `admin.rs:127`、`admin.rs:177`（create / delete）、`usage_flush.rs:39`（周期 flush）、
   `gateway.rs:408`（关闭前强制 flush）；
3. 服务器库**也有同步客户端**（[`postgres`](https://docs.rs/crate/postgres/0.19.14) 是
   `tokio-postgres` 的同步封装；`mysql` 同样提供同步客户端），配连接池即可。

**保持端口同步，则 P2 的调用点改动 = 0。** 反之若改成 `async fn`：

- 20 个方法签名全变 → 调用点连带改（`admin.rs` 9 处、`auth.rs` 7 处、`proxy/usage.rs` 6 处、
  `state.rs` 4 处、`gateway.rs` 3 处，其余若干）；
- **收益为零**，因为热路径本来就不碰 DB。

⚠️ **一个反直觉点**：`auth.rs:111` 的 `spawn_blocking` **不能删**——那里阻塞的是
**argon2（10–30ms + 19MiB 工作内存）**，不是 SQL。它和数据库无关。

## 5. 加一张表要写多少（前后对比）

| | 今天 | 声明式之后 |
|---|---|---|
| DDL 常量 | 1 处 | 0（派生）|
| 索引 / 唯一约束 | 写进 DDL 字符串 | 0（`@unique` 声明）|
| 启动装载 | 1 个 `SELECT` | 0（派生）|
| upsert | 1–2 条语句 | 0（派生，`@additive` 标一下）|
| 删除 | 1 条语句 | 0（派生）|
| 迁移 | 手写探列 + `ALTER` | 0（自动加列）+ 手写步骤（仅特殊情形）|
| 错误码映射 | 各写各的 | 0（方言层归一）|
| 结构体 + codec | 手写 | A: ~15 行 / B: ~8 行 |
| **业务查询** | 手写 | **手写（本来就该）** |

以 `key_usage` 为参照：`usage.rs` 生产代码约 **380 行**（测试从 `:390` 起），其中约 **1/3**
是可派生样板、**2/3** 是领域逻辑。声明式之后**样板归零，领域逻辑原样保留**。

## 6. 阶段划分（并与当前阶段规则对齐）

`TODO.md` 顶部范围约定原文：

> **不新增能力/接口/表结构/依赖/配置旋钮**……包括多租户、配额与超限拒绝、按 model 归因、
> 用量 reset/告警、**Redis 外置**、协议换 protobuf、管理面板扩展、**多实例无状态化**等
> **仍在做**：已登记**缺陷**的修复、测试补齐、**以及不改变对外行为的重构**。

| 阶段 | 内容 | 行为变化 | 调用点改动 | 规则判定 | 新增依赖 |
|---|---|---|---|---|---|
| **P0** | 抽 `Dialect` + `TableSpec`；**`create()` 改普通 `INSERT`**（§2.1①，`OR REPLACE` 下线）；SQLite 为唯一实现；10 处 SQL 收进方言层；错误码归一 | **一处显式变更**：不可达路径上的"静默覆盖别人的行"变成报错 | 0 | ✅ 属"不改变对外行为的重构"，**现在可做** | 0 |
| **P1** | 两张表改成声明式（含 `@unique`）；迁移改"自动加列 + 有序步骤" | **无** | 0 | ✅ 同上 | 0 |
| **P2** | 抽 `Database` 端口（**同步**）+ `SqliteDatabase`（现有行为的搬运）| 无 | **0**（见 §4.6）| ✅ 同上 | 0 |
| **P3** | 加 PostgreSQL / MySQL 实现 + 连接池 | 有（换后端）| 配置层 | ⛔ **新依赖** | +1～2 |
| **P4** | 多副本共享状态（用量改累加/对账、吊销传播、key 增量刷新）| 有 | 用量与鉴权 | ⛔ **"多实例无状态化"** | 可能 +1 |

**P0–P2 现在就能开工**（纯重构、零依赖、零行为变化、零调用点改动）；
**P3/P4 只登记、不排期**。

**每阶段的共同验收**：`storage` 现有 **31 个测试全绿且一个都不改**。
重构若要求改测试语义，说明动到了不该动的地方。
（唯一例外是 P0 为 §2.1① 的 upsert 语义**新增**一个测试——那是新增，不是改动。）

## 7. 考虑过但否决的方案（留痕，勿再捡起）

| 方案 | 为什么否决 |
|---|---|
| **把整个 `Storage` trait 化** | 会把内存索引、argon2 缓存、用量口径一起拖进每个实现 → 换库要重写三遍（§1）|
| **为多库引入 async 端口** | 只有 4 个数据操作碰 DB，且它们已在阻塞池上；改 async 收益为零、代价是 20 个签名加一堆调用点（§4.6）|
| **让 `create()` 继续做 upsert**（即上一版的"选 (b)"）| **问法就错了**——它把问题当成"怎么把 `OR REPLACE` 翻译到别的方言"，预设了要保留它。`create()` 的语义是"造一把新 key"，冲突该报错而不是覆盖（§2.1①）|
| **引入 SeaORM / Diesel** | 依赖与抽象都比需求重；本仓库访问模式极窄（装载 / upsert / 删除），用不着关系映射 |
| **sqlx 的 `query!` 编译期校验** | 需要活库或 `.sqlx` 离线缓存 → 构建摩擦；且它把 SQL 钉死在某个方言上，与"方言无关"直接冲突 |
| **把 WAL / `synchronous=NORMAL` / 0600 收口抬到公共层** | 这些是 **SQLite 特有**的运维属性，抬上去只会变成其他方言里的空实现 |

## 8. 明确不做的事

- ❌ 不要动 SQLite 特有的东西：WAL / `synchronous=NORMAL` pragma、`tighten_db_to_owner` 的
  0600 收口、`flush_usage_blocking` 的关闭期语义——**这些留在 SQLite 实现里**
- ❌ 不要为了"抽象干净"把 `usage::UsageStore` 的内存记账搬进 DB（那是性能设计，不是持久化）
- ❌ 不要在换方言的同时顺手把并发模型也换了——两件事一起改，出问题分不清是谁的（§3）

## 9. 待定决策（需要人工拍板）

| # | 问题 | 影响 |
|---|---|---|
| 1 | **确认 `create()` 改普通 `INSERT`**（`OR REPLACE` 下线、冲突报错）？（§2.1①）| P0 的第一件事；代价已核实为零（无测试依赖它），只需**新增**一个冲突测试 |
| 2 | **目标形态是哪个？** ① 单副本 + 外置库（只为运维/备份）② 多副本共库 | ① 只做 ①②，最省；② **③ 无法回避**，且撞上阶段规则的 ⛔ |
| 3 | **先做哪个后端？** PostgreSQL 还是 MySQL | PG 的 `ON CONFLICT` 与现状最接近、移植最省；MySQL 还要处理 `VALUES()`、布尔、标识符大小写 |
| 4 | **P0–P2 是否现在开工？** | 若严格守"只还债"，其定性为**技术债偿还**（10 处 SQL 散在两文件、加列迁移手写、无 schema 版本，本身就是债）|
| 5 | **`cred_version` 这一列怎么处置？**（§2.1④：(A) 让它成真 / (B) 删列）| 现在是**死重**（值跨进程无意义、恒为 1）。两个方向都留到 **P4**，P0 不碰；**在那之前不要依赖它** |
