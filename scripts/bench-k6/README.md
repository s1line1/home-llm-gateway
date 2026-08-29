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
