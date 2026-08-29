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
import { Rate } from 'k6/metrics';

const BASE = __ENV.GATEWAY_URL || 'http://127.0.0.1:8080';
const KEY = __ENV.GATEWAY_KEY || 'sk-missing';

const qpsOk = new Rate('qps_success');

export const options = {
  vus: Number(__ENV.VUS || 50),
  duration: __ENV.DURATION || '30s',
  thresholds: {
    http_req_failed: ['rate<0.01'],       // 断言：失败率 < 1%
    http_req_duration: ['p(95)<2000'],    // 断言：p95 < 2s
    'qps_success': ['rate>0.99'],
  },
};

export default function () {
  // 非流式对话
  const chat = http.post(
    `${BASE}/v1/chat/completions`,
    JSON.stringify({
      model: 'mock-llm',
      messages: [{ role: 'user', content: 'hi' }],
    }),
    { headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' } },
  );
  // 模型列表
  const models = http.get(`${BASE}/v1/models`, {
    headers: { Authorization: `Bearer ${KEY}` },
  });

  qpsOk.add(chat.status === 200);
  check(chat, { 'chat status 200': (r) => r.status === 200 });
  check(models, { 'models status 200': (r) => r.status === 200 });

  sleep(0.05); // 极短思考时间，避免无限打满
}
