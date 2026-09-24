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
// 请求的模型名必须匹配 agent 声明的 models（网关按 model 路由）；本地自建栈常见 `mock-llm`。
const MODEL = __ENV.MODEL || 'qwen2.5';
// 默认**不**把 429 当失败（那是 admission control 的设计行为，见 README《关于 429》）；
// 想连"每条流都完整"一起卡住就 STRICT=1。
const STRICT = __ENV.STRICT === '1';

const sseDur = new Trend('sse_duration_ms');
const sseOk = new Rate('sse_success');
const sseEvents = new Trend('sse_events_per_stream');
// 状态码分布：报告中可直接看到 200 / 429 / 5xx 各占多少
const statusCounts = new Counter('http_status_counts');
// 真故障（5xx）= 唯一默认必须为 0 的东西
const serverErr = new Rate('server_5xx');

export const options = {
  vus: Number(__ENV.VUS || 20),
  duration: __ENV.DURATION || '30s',
  // 默认口径：429 是**设计行为**（agent max_concurrency 上限），不算失败——所以只断言"没有
  // 5xx"。把 `sse_success > 0.99` 放在 STRICT=1：小上限 + 高 VUS 时它按定义必然红
  // （P3-24；仓库自己的 admission.js 早就是这个口径）。
  thresholds: {
    server_5xx: ['rate<0.01'],
    'sse_duration_ms': ['p(95)<5000'],   // 断言：p95 整流耗时 < 5s
    ...(STRICT ? { sse_success: ['rate>0.99'] } : {}),
  },
};

export default function () {
  const res = http.post(
    `${BASE}/v1/chat/completions`,
    JSON.stringify({
      model: MODEL,
      stream: true,
      messages: [{ role: 'user', content: '你'.repeat(CONTENT_LEN) }],
    }),
    { headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' } },
  );

  // 请求失败（连不上/DNS/TLS 出错）时 res.body 是 null：直接 .match/.includes 会抛
  // TypeError，k6 报 "script exception"，把"成功率 0"这个清晰信号糊成脚本异常。
  const body = res.body || '';
  const events = (body.match(/data: /g) || []).length; // SSE 事件数（≈ token 数）
  const done = body.includes('[DONE]');                // 流是否完整结束
  const ok = res.status === 200 && done;

  sseDur.add(res.timings.duration);
  sseOk.add(ok);
  serverErr.add(res.status >= 500);
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
