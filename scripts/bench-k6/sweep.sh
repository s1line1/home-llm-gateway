#!/usr/bin/env bash
# 一次跑完两组扫描，并直接产出可看的对照图 + markdown 汇总表。
#
# 为什么是两组扫描（而不是把 VU 或流长随便拉一拉）：
#   ① N 扫描 @ VUS=1 —— 只有一条流在跑，**没有排队**，于是
#        实测 ≈ F + CONTENT_LEN×10ms + 事件数×e
#      可以干净地分离出"固定开销 F"和"每事件开销 e"。
#      固定 VU 下改变流长会同时改变 QPS（流越短 QPS 越高），med/avg 会被排队污染，
#      所以分离 F/e 必须用 VUS=1，不能用 20 VU 的两轮硬凑。
#   ② VUS 扫描 @ 固定流长 —— 这时才轮到"并发/排队"这个问题：
#      p95 什么时候抬头、非 2xx（约等于 429）什么时候出现。
#   两个问题分开测，才不会互相污染。
#
# 用法：
#   GATEWAY_KEY=sk-xxx scripts/bench-k6/sweep.sh
#   GATEWAY_URL=http://47.100.86.38:9090 GATEWAY_KEY=sk-xxx \
#     LENS="10 100" VUSS="1 5 20 40" DUR=30s DUR_N=30s scripts/bench-k6/sweep.sh
#
# 产物（默认都在 .tmp/bench/，gitignore 的）：
#   n<len>.json / v<vus>.json   每次跑批的 k6 summary-export
#   manifest-n.json / -v.json   自动拼好的 manifest
#   summary.md                  markdown 汇总表（两组）
#   $OUT                        F/e 对照图（N 扫描那组）
#
# 只想拿已有 export 重画图：SKIP_SWEEP=1（仍会重拼 manifest 并出图）
set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:8080}"
GATEWAY_KEY="${GATEWAY_KEY:-}"
LENS="${LENS:-10 100}"                  # N 扫描的 CONTENT_LEN 列表
VUSS="${VUSS:-1 5 20 40}"               # VUS 扫描的并发列表
BASE_LEN="${BASE_LEN:-100}"             # VUS 扫描用的固定流长
DUR="${DUR:-30s}"                       # VUS 扫描每轮时长
DUR_N="${DUR_N:-30s}"                   # N 扫描每轮时长（VUS=1，样本数 = DUR/单条流耗时）
MODEL="${MODEL:-qwen2.5}"                 # 请求的模型名（必须匹配 agent 声明的 models）
OUTDIR="${OUTDIR:-.tmp/bench}"
OUT="${OUT:-sse-bench-report.svg}"
FORCE="${FORCE:-0}"                     # 1 = 跳过 /healthz 可达性检查
SKIP_SWEEP="${SKIP_SWEEP:-0}"           # 1 = 不跑 k6，只用已有 export 重画

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
K6_JS="$SCRIPT_DIR/sse.js"

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33m警告: %s\033[0m\n' "$*" >&2; }
die() { printf '\033[31m错误: %s\033[0m\n' "$*" >&2; exit 1; }

# ---------- 前置检查 ----------
command -v k6 >/dev/null || die "找不到 k6（macOS: brew install k6）"
command -v python3 >/dev/null || die "找不到 python3"
[ -n "$GATEWAY_KEY" ] || die "必须给 GATEWAY_KEY=sk-xxx（用 /admin/keys 签发，或见 make bench-k6 注释）"

if [ "$FORCE" != "1" ] && [ "$SKIP_SWEEP" != "1" ]; then
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$GATEWAY_URL/healthz" || true)"
  [ "$code" = "200" ] || die "$GATEWAY_URL/healthz 返回 ${code:-连不上}：网关不可达（确认地址/端口/防火墙；确实要跑就 FORCE=1）"
  echo "网关可达：$GATEWAY_URL"

  # 还要确认**至少有一个 agent 在线**：网关活着但 agent 掉线时，每个请求都是 503，
  # 而失败请求几乎瞬时返回 —— k6 会在 30s 内打出成百上千个（实测 VUS=50 打了 9267 个），
  # 每个失败请求在网关侧仍要付一次 argon2。既白压一轮，又给对端添无谓压力。
  models="$(curl -sS --max-time 8 -H "Authorization: Bearer $GATEWAY_KEY" "$GATEWAY_URL/v1/models" 2>/dev/null | tr -d ' \n' || true)"
  # 只有"能看到非空 data 数组"才放行；其余一律停在这里。之前这里是"warn 后继续"，
  # 结果 key 被吊销时脚本照样跑了 4 轮、每轮上千个 401（失败请求瞬时返回 → k6 自旋）。
  case "$models" in
    *'"data":[]'*)
      die "网关在线但没有 agent：/v1/models 的 data 为空，跑起来全是 503（且失败请求会瞬间刷满 k6）。先启动 agent；确实要压就 FORCE=1" ;;
    *'"data":['*)
      echo "agent 在线：$(printf '%s' "$models" | head -c 100)" ;;
    *'"error"'*)
      die "key 被拒：/v1/models 返回 $(printf '%s' "$models" | head -c 80)。换一个有效 key（或确认它没被吊销）；确实要压就 FORCE=1" ;;
    *)
      die "无法确认 agent 状态：/v1/models 返回异常（$(printf '%s' "$models" | head -c 80)）。检查 GATEWAY_URL 与网络；确实要压就 FORCE=1" ;;
  esac
fi

# 顺序要紧（P3-23）：`OUTDIR`/`OUT` 是**相对路径**，而 README 承诺它们按仓库根解析
# （"在任何目录调用都一样"）。先把 cwd 切到仓库根再建目录，否则从子目录调用会把
# `.tmp/bench` 建在子目录里，而 k6 的 `--summary-export` 之后写向仓库根那个**不存在**的路径。
cd "$ROOT"
mkdir -p "$OUTDIR"

run_one() { # run_one <label> <content_len> <vus> <dur> <outfile>
  local label="$1" len="$2" vus="$3" dur="$4" out="$5"
  printf '  %-22s CONTENT_LEN=%-4s VUS=%-3s %s → %s\n' "$label" "$len" "$vus" "$dur" "$(basename "$out")"
  # k6 的 warning/error 走 stderr：落到每轮自己的日志里，别刷屏；
  # 跑失败时 summary-export 仍会写出（趋势指标为空 → 0），配合日志排查。
  if ! k6 run --quiet --summary-export="$out" \
    -e GATEWAY_URL="$GATEWAY_URL" -e GATEWAY_KEY="$GATEWAY_KEY" \
    -e VUS="$vus" -e DURATION="$dur" -e CONTENT_LEN="$len" -e MODEL="$MODEL" \
    "$K6_JS" >"${out%.json}.log" 2>&1; then
    warn "k6 退出非 0，见 ${out%.json}.log"
  fi
}

# ---------- ① N 扫描（VUS=1）----------
if [ "$SKIP_SWEEP" != "1" ]; then
  say "① N 扫描 @ VUS=1：分离固定开销 F 与每事件开销 e"
  for n in $LENS; do run_one "N=$n" "$n" 1 "$DUR_N" "$OUTDIR/n$n.json"; done
  say "② VUS 扫描 @ CONTENT_LEN=${BASE_LEN}：并发/排队"
  for v in $VUSS; do run_one "VUS=$v" "$BASE_LEN" "$v" "$DUR" "$OUTDIR/v$v.json"; done
else
  say "SKIP_SWEEP=1：跳过 k6，直接用已有 export 重画"
fi

# ---------- 拼 manifest ----------
python3 - "$OUTDIR" $LENS <<'PY'
import json, pathlib, sys
outdir, lens = pathlib.Path(sys.argv[1]), sys.argv[2:]
runs = []
for n in lens:
    f = outdir / f"n{n}.json"
    if f.exists():
        runs.append({"label": f"CONTENT_LEN={n}", "content_len": int(n), "summary": str(f)})
(outdir / "manifest-n.json").write_text(json.dumps(runs, ensure_ascii=False, indent=1))
PY
BASE_LEN="$BASE_LEN" VUSS="$VUSS" python3 - "$OUTDIR" <<'PY'
import json, os, pathlib, sys
outdir = pathlib.Path(sys.argv[1])
base = int(os.environ["BASE_LEN"])
runs = []
for v in os.environ["VUSS"].split():
    f = outdir / f"v{v}.json"
    if f.exists():
        runs.append({"label": f"VUS={v}", "content_len": base, "summary": str(f)})
(outdir / "manifest-v.json").write_text(json.dumps(runs, ensure_ascii=False, indent=1))
PY

# ---------- 自检：CONTENT_LEN 真的生效了吗 ----------
python3 - "$OUTDIR" $LENS <<'PY'
import json, pathlib, sys
outdir, lens = pathlib.Path(sys.argv[1]), sys.argv[2:]
bad = []
for n in lens:
    f = outdir / f"n{n}.json"
    if not f.exists():
        continue
    m = json.loads(f.read_text())["metrics"].get("sse_events_per_stream", {})
    got = m.get("avg", m.get("values", {}).get("avg"))
    if got is not None and int(got) != int(n) + 2:
        bad.append(f"CONTENT_LEN={n} 期望 {int(n)+2} 个事件，实际 {got}")
if bad:
    print("\n".join("警告: " + b for b in bad), file=sys.stderr)
PY

# ---------- 出图 + 汇总表 ----------
say "出图（N 扫描 → F/e 分解）"
python3 scripts/bench-k6/report.py --runs "$OUTDIR/manifest-n.json" -o "$OUT" \
  --where "$GATEWAY_URL" --vus "VUS=1" --dur "$DUR_N"
if command -v rsvg-convert >/dev/null; then
  rsvg-convert -o "${OUT%.svg}.png" "$OUT" && echo "  ${OUT%.svg}.png"
else
  warn "没有 rsvg-convert，跳过 PNG（brew install librsvg）"
fi

say "汇总表 → $OUTDIR/summary.md"
{
  echo "### ① N 扫描 @ VUS=1（分离 F/e）"
  echo
  python3 scripts/bench-k6/report.py --runs "$OUTDIR/manifest-n.json" --table --dur "$DUR_N"
  echo
  echo "### ② VUS 扫描 @ CONTENT_LEN=${BASE_LEN}（并发/排队）"
  echo
  python3 scripts/bench-k6/report.py --runs "$OUTDIR/manifest-v.json" --table --dur "$DUR"
} | tee "$OUTDIR/summary.md"

say "完成"
echo "  图：$OUT ${OUT%.svg}.png"
echo "  表：$OUTDIR/summary.md"
echo "  原始 export：$OUTDIR/n*.json $OUTDIR/v*.json"
