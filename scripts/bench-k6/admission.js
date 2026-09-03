// HTTP admission 闸门验证（max_concurrent_requests）
// 前置：由 .tmp/admission-test.sh 起栈（agent max_concurrency 调大，排除 agent 层干扰）
// 用法：k6 run -e GATEWAY_URL=... -e GATEWAY_KEY=... -e VUS=100 \
//         -e DURATION=20s scripts/bench-k6/admission.js
//
// 打 /v1/slow（mock 睡 800ms）放大在途窗口：闸门放行 ≤ limit 个在慢处理，
// 其余应在 HTTP 层立即 429。429 比例突增的 VUS 点 = 闸门阈值。
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Counter } from 'k6/metrics';

const BASE = __ENV.GATEWAY_URL || 'http://127.0.0.1:8080';
const KEY = __ENV.GATEWAY_KEY || 'sk-missing';
// 请求的 model 必须匹配 agent 声明的 models（模型路由）。默认 qwen2.5（生产 edge 声明）；
// 本地自建栈验证时 mock 实例名不同，用 -e MODEL=xxx 覆盖。
const MODEL = __ENV.MODEL || 'qwen2.5';

const okRate = new Rate('ok_200');
const throttle = new Rate('throttle_429');
const serverErr = new Rate('server_5xx');
const statusCounts = new Counter('http_status_counts');

export const options = {
  vus: Number(__ENV.VUS || 100),
  duration: __ENV.DURATION || '20s',
  // 闸门生效的断言：无 5xx；200 与 429 之和占绝大多数（其余为等待）
  thresholds: {
    server_5xx: ['rate<0.01'],
  },
};

export default function () {
  // mock /v1/slow 睡 800ms：放行的请求长时间占用在途槽 → active 峰值可见
  const res = http.post(
    `${BASE}/v1/slow`,
    JSON.stringify({ model: MODEL }),
    { headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' } },
  );

  okRate.add(res.status === 200);
  throttle.add(res.status === 429);
  serverErr.add(res.status >= 500);
  statusCounts.add(1, { code: String(res.status) });

  check(res, {
    '200 (被闸门放行)': (r) => r.status === 200,
    '429 (被闸门拒绝)': (r) => r.status === 429,
    'no 5xx': (r) => r.status < 500,
  });

  // 无 sleep：打满并发压力，逼出闸门
}
