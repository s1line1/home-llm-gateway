// SSE 并发长流压测（k6 模板）
// 用法：
//   k6 run -e GATEWAY_URL=http://127.0.0.1:8080 -e GATEWAY_KEY=sk-xxx scripts/bench-k6/sse.js
//   # 或 make bench-k6 KEY=sk-xxx VUS=20 DUR=30s
//
// 场景：vus 个虚拟用户同时各发一条流式对话，读完整（[DONE]）算成功。
// 指标：sse_success（成功率）、sse_duration_ms（整条流耗时，p95 断言）。

import http from 'k6/http';
import { check } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';

const BASE = __ENV.GATEWAY_URL || 'http://127.0.0.1:8080';
const KEY = __ENV.GATEWAY_KEY || 'sk-missing';
const CONTENT_LEN = Number(__ENV.CONTENT_LEN || 100); // 提示词长度（mock 逐字 10ms）

const sseDur = new Trend('sse_duration_ms');
const sseOk = new Rate('sse_success');
const sseEvents = new Trend('sse_events_per_stream');
// 状态码分布：报告中可直接看到 200 / 429 / 5xx 各占多少
const statusCounts = new Counter('http_status_counts');

export const options = {
  vus: Number(__ENV.VUS || 20),
  duration: __ENV.DURATION || '30s',
  thresholds: {
    'sse_success': ['rate>0.99'],        // 断言：成功率 > 99%
    'sse_duration_ms': ['p(95)<5000'],   // 断言：p95 整流耗时 < 5s
  },
};

export default function () {
  const res = http.post(
    `${BASE}/v1/chat/completions`,
    JSON.stringify({
      model: 'qwen2.5',
      stream: true,
      messages: [{ role: 'user', content: '你'.repeat(CONTENT_LEN) }],
    }),
    { headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' } },
  );

  const events = (res.body.match(/data: /g) || []).length; // SSE 事件数（≈ token 数）
  const done = res.body.includes('[DONE]');                // 流是否完整结束
  const ok = res.status === 200 && done;

  sseDur.add(res.timings.duration);
  sseOk.add(ok);
  if (events > 0) sseEvents.add(events);
  statusCounts.add(1, { code: String(res.status) });

  check(res, {
    'status 200': (r) => r.status === 200,
    'stream complete [DONE]': () => done,
    // 429 = admission control 按设计拒绝（agent max_concurrency 上限），可接受
    'accepted (200 or 429)': (r) => r.status === 200 || r.status === 429,
    // 5xx = 网关/上游真故障，出现即排查
    'no 5xx': (r) => r.status < 500,
  });
}
