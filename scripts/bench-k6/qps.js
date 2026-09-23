// 非流式请求吞吐压测（k6 模板）
// 用法：
//   k6 run -e GATEWAY_URL=http://127.0.0.1:8080 -e GATEWAY_KEY=sk-xxx scripts/bench-k6/qps.js
//
// 场景：vus 个虚拟用户循环打 /v1/chat/completions（非流式）+ /v1/models。
// 指标：k6 内置 http_req_duration / http_req_failed + 自定义 qps_ok。
// 注意：QPS 会受 agent max_concurrency（admission control）限制，超限返回 429，
//       压纯吞吐前建议把 agent-config.yml 的 max_concurrency 调大。

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Counter } from 'k6/metrics';

const BASE = __ENV.GATEWAY_URL || 'http://127.0.0.1:8080';
const KEY = __ENV.GATEWAY_KEY || 'sk-missing';
// 与 sse.js 同一套口径：MODEL 必须匹配 agent 声明；默认只断言"没有 5xx"（429 是设计行为），
// 严格档用 STRICT=1（P3-24）。
const MODEL = __ENV.MODEL || 'qwen2.5';
const STRICT = __ENV.STRICT === '1';

const qpsOk = new Rate('qps_success');
// 状态码分布：报告中可直接看到 200 / 429 / 5xx 各占多少
const statusCounts = new Counter('http_status_counts');
const serverErr = new Rate('server_5xx');

export const options = {
  vus: Number(__ENV.VUS || 50),
  duration: __ENV.DURATION || '30s',
  thresholds: {
    // 默认只卡真故障：k6 把 429 计进 `http_req_failed`，所以它和 `qps_success` 一起放进
    // STRICT 档（P3-24）。
    server_5xx: ['rate<0.01'],
    http_req_duration: ['p(95)<2000'],    // 断言：p95 < 2s
    ...(STRICT
      ? { http_req_failed: ['rate<0.01'], 'qps_success': ['rate>0.99'] }
      : {}),
  },
};

export default function () {
  // 非流式对话
  const chat = http.post(
    `${BASE}/v1/chat/completions`,
    JSON.stringify({
      model: MODEL,
      messages: [{ role: 'user', content: 'hi' }],
    }),
    { headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' } },
  );
  // 模型列表
  const models = http.get(`${BASE}/v1/models`, {
    headers: { Authorization: `Bearer ${KEY}` },
  });

  qpsOk.add(chat.status === 200);
  serverErr.add(chat.status >= 500);
  statusCounts.add(1, { code: String(chat.status) });
  check(chat, {
    'chat status 200': (r) => r.status === 200,
    'accepted (200 or 429)': (r) => r.status === 200 || r.status === 429,
    'no 5xx': (r) => r.status < 500,
  });
  check(models, { 'models status 200': (r) => r.status === 200 });

  sleep(0.05); // 极短思考时间，避免无限打满
}
