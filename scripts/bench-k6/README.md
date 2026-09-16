# k6 宏观压测脚本

[k6](https://k6.io)（Grafana 负载测试工具）模板：覆盖 SSE 并发长流与非流式吞吐两个场景，
内置断言（成功率 / 延迟分位），不达标直接 FAILED，可进 CI。

## 前置

1. 安装 k6：`brew install k6`（或官网下载二进制）
2. 起全栈并创建 API key：

```bash
make dev                                     # mock-llm + gateway + agent
KEY=$(curl -s -X POST http://127.0.0.1:8080/admin/keys \
  -H "Authorization: Bearer dev-admin" -H "Content-Type: application/json" \
  -d '{"name":"k6"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['key'])")
```

3. （压纯吞吐时）调大 agent 并发上限：`agent-config.yml` 里 `max_concurrency: 200`，
   否则高并发会大量 429（admission control 的正常行为，见下）

## 运行

```bash
# SSE 并发长流：20 个虚拟用户同时流式对话，30s
k6 run -e GATEWAY_URL=http://127.0.0.1:8080 -e GATEWAY_KEY=$KEY scripts/bench-k6/sse.js

# 非流式吞吐：50 虚拟用户，30s
k6 run -e GATEWAY_URL=http://127.0.0.1:8080 -e GATEWAY_KEY=$KEY scripts/bench-k6/qps.js

# 经 Makefile（KEY 必填）
make bench-k6 KEY=$KEY VUS=20 DUR=30s
```

> 想一次跑完两组扫描并直接出图/出表：见文末《扫描 + 出图（sweep.sh / report.py）》。

## 参数（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `GATEWAY_URL` | `http://127.0.0.1:8080` | 网关地址 |
| `GATEWAY_KEY` | （必填） | API Key |
| `VUS` | 20（qps.js 为 50） | 并发虚拟用户数 |
| `DURATION` | 30s | 压测时长 |
| `CONTENT_LEN` | 100 | SSE 提示词长度（字；mock 逐字 10ms） |

## 断言（thresholds）

- `sse.js`：成功率 > 99%、p95 整流耗时 < 5s
- `qps.js`：失败率 < 1%、p95 < 2s

## 关于 429

网关按 agent `max_concurrency` 做 admission control（超限返回 429）。这是**设计行为**：
- 想压 HTTP 层纯吞吐 → 调大 agent 并发上限
- 想验证 admission 正确性 → 保持小上限，观察 429 比例（见 `cargo test` 的 e2e_admission_control）

## HTTP 层闸门验证（admission.js）

验证网关 `max_concurrent_requests`（HTTP 全局在途上限）是否精确钳制并发：

```bash
# 云上已运行的 gateway（agent 上游需能响应 /v1/slow 慢端点，放大在途窗口）
make bench-admission KEY=sk-xxx GATEWAY_URL=http://IP:9090 VUS=200 DUR=20s

# 本地自建临时栈（mock+gateway+agent，专用端口，不碰现有配置）
make bench-admission-local LIMIT=20 VUS=200
```

**判定**：
- 429 占比 = 被闸门拒绝的请求（超出 limit 的并发）
- 压测期间网关 `/metrics` 的 `hlmg_active_requests` **峰值应精确等于 limit**（闸门生效铁证）
- 本地验证脚本已自动采样并输出峰值；云上需自行 ssh 到网关侧轮询 `/metrics`

注意：agent 声明 `models` 若与默认 `MODEL=qwen2.5` 不一致，用 `MODEL=xxx` 覆盖（模型路由要求匹配）。

## 扫描 + 出图（sweep.sh / report.py）

单跑 `sse.js` 只能得到"这条流一共花了多久"，分不清时间花在哪。这两个脚本把它拆开：

```
实测整流耗时 ≈ 地板 + F + 事件数 × e + 排队
  地板   = CONTENT_LEN × 10ms   （mock 逐字 10ms，是上游自己的节奏，与网关无关）
  事件数 = CONTENT_LEN + 2      （N 个 token 块 + finish_reason + [DONE]）
  F      = 每请求固定开销（网络 RTT + 鉴权 + 开流 + 上游建连）
  e      = 每事件开销
```

`sweep.sh` 跑**两组**扫描，因为这是两个不同的问题，混在一起会互相污染：

| 组 | 怎么跑 | 回答什么 |
|---|---|---|
| ① N 扫描 | `VUS=1` + 多个 `CONTENT_LEN` | **F 与 e**。只有一条流在跑 = 没有排队，才能干净拟合。固定 VU 下改变流长会同时改变 QPS（流越短 QPS 越高），med/avg 会被排队污染，两轮相减得到的"每事件开销"是假的 |
| ② VUS 扫描 | 固定 `CONTENT_LEN` + 多个 `VUS` | **排队**。p95 什么时候抬头、非 2xx（约等于 429）什么时候出现 |

### 用法

```bash
# 本地（默认 http://127.0.0.1:8080）
GATEWAY_KEY=$KEY scripts/bench-k6/sweep.sh

# 云端：改 GATEWAY_URL 即可（带端口、不带路径）
GATEWAY_URL=http://47.100.86.38:9090 GATEWAY_KEY=$KEY \
  OUT=sse-bench-report-remote.svg scripts/bench-k6/sweep.sh
```

开跑前脚本会自检三件事，任何一项不满足都**直接退出**（`FORCE=1` 可跳过）：

1. `GET /healthz` 必须 200 —— 网关可达；
2. `GET /v1/models` 必须返回**非空的 `data` 数组** —— 至少有一个 agent 在线。网关活着但 agent 掉线时每个请求都是 503，而失败请求几乎瞬时返回，k6 会在 30s 里打出上万条（实测 VUS=50 打出 9267 条），且每条在网关侧仍要付一次 argon2 —— 既白压一轮，又给对方添无谓压力；
3. 同一请求若返回 `error`（key 无效/被吊销）或其他非预期响应，也直接停 —— 否则会白跑好几轮 401（实测每轮上千个请求）。

### 参数（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `GATEWAY_URL` | `http://127.0.0.1:8080` | **打云端就改这个** |
| `GATEWAY_KEY` | （必填） | API Key |
| `LENS` | `10 100` | ① 的 `CONTENT_LEN` 列表（至少两个**不同**值才能分离 F/e） |
| `VUSS` | `1 5 20 40` | ② 的并发列表（注意：给空值会退回默认，不能用来"跳过"） |
| `BASE_LEN` | `100` | ② 用的固定流长 |
| `DUR` / `DUR_N` | `30s` / `30s` | ② / ① 每轮时长。① 的样本数 = `DUR_N ÷ 单条流耗时`（N=100 约 1.3s/条 → 30s 只有 ~23 个样本，想稳就 60s） |
| `OUT` | `sse-bench-report.svg` | 图输出（PNG 同名）。⚠️ **默认落在仓库根目录且覆盖同名文件**，建议显式改名 |
| `OUTDIR` | `.tmp/bench` | 原始 export / 每轮日志 / 汇总表（`.gitignore` 内） |
| `FORCE` | `0` | `1` = 跳过上面两项自检 |
| `SKIP_SWEEP` | `0` | `1` = 不跑 k6，只用已有 export 重画（仍需给 `GATEWAY_KEY` 一个非空值） |

`OUT` / `OUTDIR` 的相对路径按**仓库根**解析（脚本会先 `cd` 过去），所以在任何目录调用都一样。

### 典型配方

```bash
# 只要 F/e（快）：① 给足样本，② 只跑一轮短
GATEWAY_URL=http://IP:9090 GATEWAY_KEY=$KEY VUSS="1" DUR=10s DUR_N=60s \
  scripts/bench-k6/sweep.sh

# 找 p95 拐点：固定 N=100，只扫并发
# （LENS 故意给两个相同值 → 退化成"单轮模式"，正合适）
GATEWAY_URL=http://IP:9090 GATEWAY_KEY=$KEY LENS="100 100" VUSS="20 50 100 200" \
  scripts/bench-k6/sweep.sh

# 不重跑，只重画
SKIP_SWEEP=1 GATEWAY_KEY=x scripts/bench-k6/sweep.sh
```

### 产物

- `$OUTDIR/summary.md` —— 两组扫描的 markdown 汇总表（req/s、min/med/p95、**非 2xx**、成功率）
- `$OUT` 与同名 `.png` —— F/e 分解图（PNG 需要 `rsvg-convert`，`brew install librsvg`；没有就只出 SVG）
- `$OUTDIR/n*.json`、`v*.json` —— 原始 k6 `--summary-export`，可单独喂给 `report.py`

### report.py 单独用

```bash
# manifest 是 [{label, content_len, summary}] 的 JSON 数组
python3 scripts/bench-k6/report.py --runs runs.json -o out.svg \
  --where "http://IP:9090" --vus "VUS=1" --dur 30s
rsvg-convert -o out.png out.svg        # 需要 PNG 时

# 只要汇总表
python3 scripts/bench-k6/report.py --runs runs.json --table --dur 30s
```

`report.py` 纯 stdlib、手写 SVG、无第三方依赖；兼容 k6 v2 与 v0.x 两种 summary schema；只给一次跑批也能出图（不分离 F/e，图上会写明"单轮模式"）。

### 经 Makefile

`Makefile` 里 `bench-sweep` / `bench-report` / `bench-k6-export` 三个 target **默认是注释状态**（注释里写了原因：单轮分不出 F/e，手工拼 manifest 才是摩擦所在）。要用就去掉注释：

```bash
make bench-sweep KEY=$KEY GATEWAY_URL=http://IP:9090 LENS="10 100" VUSS="1 5 20 40"
```

