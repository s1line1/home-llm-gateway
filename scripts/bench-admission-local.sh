#!/usr/bin/env bash
# 验证 HTTP 层 max_concurrent_requests 闸门：起独立栈（mock + gateway + agent，
# 专用端口与 keys.db），k6 阶梯加压，观察 /metrics 的 hlmg_active_requests 是否
# 贴住闸门值、429 是否在预期并发点出现。
#
# 用法: bash .tmp/admission-test.sh [LIMIT] [VUS]
#   LIMIT   gateway max_concurrent_requests（被测闸门，默认 20）
#   VUS     k6 并发虚拟用户数（默认 100）
set -euo pipefail
cd "$(dirname "$0")/.."

LIMIT="${1:-20}"
VUS="${2:-100}"
DUR=20s
TMP=.tmp/admission-run
mkdir -p "$TMP"
PIDFILE="$TMP/pids"

# 每个被测 LIMIT 用独立端口，避免冲突与残留
BASE_PORT=$((18000 + LIMIT % 500))
HTTP_PORT=$BASE_PORT
QUIC_PORT=$((BASE_PORT + 1))
MOCK_PORT=$((BASE_PORT + 2))
KEYS_DB="$TMP/keys-${LIMIT}.db"

cleanup() {
  [ -f "$PIDFILE" ] && xargs kill -9 < "$PIDFILE" 2>/dev/null || true
  rm -f "$PIDFILE"
}
trap cleanup EXIT

# ---- 1. 起 mock-llm ----
./target/debug/mock-llm --addr "127.0.0.1:${MOCK_PORT}" --name mock-adm \
  > "$TMP/mock.log" 2>&1 & echo $! >> "$PIDFILE"
sleep 0.3

# ---- 2. 起 gateway（被测 LIMIT）----
cat > "$TMP/gw-${LIMIT}.yml" <<EOF
listen_addr: "127.0.0.1:${HTTP_PORT}"
quic_addr: "127.0.0.1:${QUIC_PORT}"
cert: certs/out/server.crt
key: certs/out/server.key
ca: certs/out/ca.crt
admin_token: adm-test
keys_file: ${KEYS_DB}
ui_dir: ""
max_concurrent_requests: ${LIMIT}
EOF
./target/debug/gateway --config "$TMP/gw-${LIMIT}.yml" > "$TMP/gw.log" 2>&1 & echo $! >> "$PIDFILE"
for _ in $(seq 1 50); do
  curl -sf "http://127.0.0.1:${HTTP_PORT}/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -sf "http://127.0.0.1:${HTTP_PORT}/healthz" >/dev/null || { echo "gateway 未就绪"; tail -5 "$TMP/gw.log"; exit 1; }

# ---- 3. 建测试 key ----
KEY_JSON=$(curl -s -X POST "http://127.0.0.1:${HTTP_PORT}/admin/keys" \
  -H "Authorization: Bearer adm-test" -H "Content-Type: application/json" \
  -d '{"name":"adm-test"}')
KEY=$(echo "$KEY_JSON" | python3 -c "import sys,json;print(json.load(sys.stdin)['key'])" \
  || { echo "建 key 失败: $KEY_JSON"; exit 1; })

# ---- 4. 起 agent（max_concurrency 调大，排除 agent 层干扰）----
cat > "$TMP/agent-${LIMIT}.yml" <<EOF
cloud_addr: "127.0.0.1:${QUIC_PORT}"
ca: certs/out/ca.crt
cert: certs/out/client.crt
key: certs/out/client.key
agent_id: "adm-agent"
upstream: "http://127.0.0.1:${MOCK_PORT}"
models: [mock-adm]
max_concurrency: 500
heartbeat_secs: 1
request_log: false
EOF
./target/debug/agent --config "$TMP/agent-${LIMIT}.yml" > "$TMP/agent.log" 2>&1 & echo $! >> "$PIDFILE"
sleep 1.5

echo "==> 栈就绪: gateway :${HTTP_PORT} (limit=${LIMIT}), agent → mock :${MOCK_PORT}"

# ---- 5. /metrics 采样器（后台，每 200ms 抓 active 峰值）----
SAMPLES="$TMP/active-${LIMIT}.csv"
: > "$SAMPLES"
( while true; do
    A=$(curl -s "http://127.0.0.1:${HTTP_PORT}/metrics" 2>/dev/null \
        | awk '/^hlmg_active_requests/ {print $2}')
    [ -n "$A" ] && echo "$(date +%s.%N),$A" >> "$SAMPLES"
    sleep 0.2
  done ) &
SAMPLER_PID=$!
echo $SAMPLER_PID >> "$PIDFILE"

# ---- 6. k6 阶梯加压：打 /v1/slow（mock 睡 800ms，放大在途窗口）----
echo "==> k6 加压: VUS=${VUS}, DUR=${DUR}, 打 /v1/slow..."
k6 run --quiet -e GATEWAY_URL="http://127.0.0.1:${HTTP_PORT}" \
  -e GATEWAY_KEY="$KEY" -e VUS="$VUS" -e DURATION="$DUR" \
  -e MODEL="mock-adm" \
  scripts/bench-k6/admission.js 2>&1 | tail -30

sleep 1  # 等采样器多抓一会

# ---- 7. 汇总：active 峰值 vs 闸门值 ----
echo ""
echo "======== 结果（LIMIT=${LIMIT}, VUS=${VUS}）========"
if [ -s "$SAMPLES" ]; then
  echo "hlmg_active_requests: 峰值=$(awk -F, 'NR>1{print $2}' "$SAMPLES" | sort -n | tail -1)  (闸门=${LIMIT})"
  echo "  中位数=$(awk -F, 'NR>1{print $2}' "$SAMPLES" | sort -n | awk '{a[NR]=$1} END{print a[int(NR/2)]}')"
fi
echo "压测期间 gateway CPU/内存采样已存 $TMP/gw.log；429 统计见上方 k6 输出"
