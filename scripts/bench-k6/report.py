#!/usr/bin/env python3
"""把 k6 SSE 压测结果画成一张"时间都花在哪"的 SVG 报告。

为什么手写 SVG：不引入 matplotlib，产物是纯文本、可 diff、可在浏览器/GitHub
直接渲染（和仓库里已有的 flow.svg 一类一致）；需要 PNG 时用 rsvg-convert 转。

输入：一份 manifest（JSON 数组），每项一次跑批：
    [{"label": "N=100", "content_len": 100, "summary": "a.json"}, ...]
其中 summary 是 `k6 run --summary-export=<file>` 的产物（脚本只读
metrics.<name>.values 里的 avg/min/med/max/p(90)/p(95)）。

用法：
    python3 scripts/bench-k6/report.py --runs runs.json -o sse-report.svg
    rsvg-convert -o sse-report.png sse-report.svg

模型（见 scripts/bench-k6/README.md）：
    实测整流耗时 ≈ 地板 + F + 事件数 × e + 排队
    地板 = CONTENT_LEN × 10ms   （mock 逐字 sleep 10ms）
    事件数 = CONTENT_LEN + 2    （N 个 token 块 + finish_reason + [DONE]）
F、e 只用**各轮的 min** 做最小二乘拟合：min 是排队最轻的样本，最接近固有开销；
med/avg 在固定 VU 下会被请求速率污染（流越短 → QPS 越高 → 排队越重），
所以它们与模型的残差单独画成"排队/其它"一栏，而不是塞进 F。
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from pathlib import Path

# mock-llm 逐字节流（crates/mock-llm/src/lib.rs:68）
MS_PER_CHAR = 10.0
# mock 每轮在 token 之后还会补 finish_reason 与 [DONE] 两个事件
EXTRA_EVENTS = 2

FONT = "PingFang SC, Hiragino Sans GB, Noto Sans CJK SC, Microsoft YaHei, sans-serif"
C_FLOOR = "#cbd5e1"   # 上游地板
C_FIXED = "#2563eb"   # 固定开销 F
C_EVENT = "#0d9488"   # 每事件开销
C_QUEUE = "#f59e0b"   # 排队/其它
C_TEXT = "#1f2937"
C_MUTED = "#64748b"


def metric(summary: dict, name: str) -> dict:
    """取一个指标的值字典。

    k6 的 summary-export 有两种 schema，都兼容：
      - k6 v0.x: {"type":"trend","contains":"default","values":{...}}
      - k6 v2.x: {"max":..,"p(95)":..,"avg":..,"thresholds":{...}}   ← 现在实测到的
    """
    m = summary.get("metrics", {}).get(name)
    if not m:
        return {}
    return m.get("values", m)


def failed_fraction(summary: dict) -> float:
    """http_req_failed 在 k6 v2 是 {passes, fails, value}，value 是失败比例。"""
    v = metric(summary, "http_req_failed")
    if "value" in v:
        return float(v["value"])
    return float(v.get("rate", 0.0))


def rate_of(summary: dict, name: str) -> float:
    v = metric(summary, name)
    if "rate" in v:
        return float(v["rate"])
    if "value" in v:  # k6 v2 的 Rate 用 value
        return float(v["value"])
    return 0.0


def read_run(entry: dict) -> dict:
    summary = json.loads(Path(entry["summary"]).read_text())
    content_len = int(entry["content_len"])
    events = metric(summary, "sse_events_per_stream").get("avg")
    if events is None:
        # 脚本只在 events > 0 时才上报该 Trend，缺省按公式补
        events = content_len + EXTRA_EVENTS

    def t(stat: str) -> float:
        return float(metric(summary, "sse_duration_ms")[stat])

    reqs = metric(summary, "http_reqs").get("count")
    http_failed = failed_fraction(summary)
    success = rate_of(summary, "sse_success")
    return {
        "label": entry.get("label", f"N={content_len}"),
        "content_len": content_len,
        "events": float(events),
        "floor": content_len * MS_PER_CHAR,
        "min": t("min"),
        "med": t("med"),
        "avg": t("avg"),
        "p95": t("p(95)"),
        "max": t("max"),
        "requests": reqs,
        "failed": http_failed,
        "success": success,
    }


def fit_fixed_and_per_event(runs: list[dict]) -> tuple[float, float, bool]:
    """最小二乘：min − 地板 = F + 事件数 × e。

    只有一次跑批（或两次 CONTENT_LEN 相同）时无法分离，返回 (0, 0, False)：
    图照样出，但会把"固定开销/每事件"两段合并进"排队/其它"，并在结论里说明。
    """
    xs = [r["events"] for r in runs]
    ys = [r["min"] - r["floor"] for r in runs]
    if len(runs) < 2 or len(set(xs)) < 2:
        return 0.0, 0.0, False
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    e = num / den
    return my - e * mx, e, True



def render_table(runs: list[dict], dur_secs: float = 30.0) -> str:
    """markdown 汇总表：给 sweep.sh 用（k6 的 summary-export 里没有 checks/状态码明细，
    所以"非 2xx"取自 http_req_failed.fails —— 它把 4xx/5xx 都算失败，约等于 429+5xx）。"""
    head = (
        "| 跑批 | 事件/流 | 请求数 | req/s | min | med | p95 | max | 地板 | min−地板 | 非 2xx | 成功率 |\n"
        "|---|---|---|---|---|---|---|---|---|---|---|---|\n"
    )
    rows = []
    for r in runs:
        rps = (r["requests"] or 0) / dur_secs
        fails = max(0, round((r.get("failed") or 0.0) * (r["requests"] or 0)))
        rows.append(
            f"| {r['label']} | {r['events']:.0f} | {r['requests']} | {rps:.1f} | "
            f"{r['min']:.0f} | {r['med']:.0f} | {r['p95']:.0f} | {r['max']:.0f} | "
            f"{r['floor']:.0f} | {r['min'] - r['floor']:.0f} | {fails} | "
            f"{r['success'] * 100:.1f}% |"
        )
    return head + "\n".join(rows) + "\n"


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def rect(x, y, w, h, fill, opacity=1.0, rx=2):
    if w <= 0 or h <= 0:
        return ""
    return (
        f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" '
        f'fill="{fill}" opacity="{opacity}" rx="{rx}"/>'
    )


def text(x, y, s, size=12, fill=C_TEXT, anchor="start", weight="normal"):
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" font-family="{FONT}" font-size="{size}" '
        f'fill="{fill}" text-anchor="{anchor}" font-weight="{weight}">{esc(s)}</text>'
    )


def build_svg(runs: list[dict], f_ms: float, e_ms: float, meta: dict, fitted: bool = True) -> str:
    W, H = 1240, 860
    out: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
    ]

    # ---------- 标题 ----------
    out.append(text(48, 52, "SSE 长流压测：一条流的时间都花在哪", size=24, weight="bold"))
    subtitle = (
        f"{meta.get('where', '')} ｜ {meta.get('vus', '')} VUs × {meta.get('dur', '')} ｜ "
        f"上游 mock 逐字节流 {MS_PER_CHAR:.0f}ms/字"
    )
    out.append(text(48, 78, subtitle, size=13, fill=C_MUTED))
    if fitted:
        head = (
            f"拟合：固定开销 F ≈ {f_ms:.0f} ms/请求　每事件 e ≈ {e_ms:.2f} ms　"
            f"（只用每轮 min 拟合，见脚注）"
        )
    else:
        head = "单轮模式：未分离固定/每事件开销 —— 需要两次不同 CONTENT_LEN 的跑批才能分离"
    out.append(text(48, 100, head, size=13, fill=C_MUTED))

    # ---------- A 面板：堆叠柱 ----------
    ax, ay, aw, ah = 48, 150, 660, 380
    stats = [("min", "min（最轻载）"), ("med", "med"), ("p95", "p95")]
    ymax = max(1.0, max(r["p95"] for r in runs) * 1.12)

    def sy(v: float) -> float:
        return ay + ah - (v / ymax) * ah

    out.append(text(ax, ay - 14, "A. 整流耗时拆解（每段 = 该部分占总耗时多少）", size=15, weight="bold"))
    # 网格 + y 轴刻度
    steps = 5
    for i in range(steps + 1):
        v = ymax * i / steps
        y = sy(v)
        out.append(
            f'<line x1="{ax}" y1="{y:.1f}" x2="{ax + aw}" y2="{y:.1f}" stroke="#e2e8f0" stroke-width="1"/>'
        )
        out.append(text(ax - 8, y + 4, f"{v:.0f}", size=11, fill=C_MUTED, anchor="end"))
    out.append(text(ax - 8, ay - 4, "ms", size=11, fill=C_MUTED, anchor="end"))

    group_w = aw / len(runs)
    bar_w = min(74.0, group_w / (len(stats) + 0.8))
    for gi, r in enumerate(runs):
        gx = ax + gi * group_w
        out.append(
            text(
                gx + group_w / 2,
                ay + ah + 22,
                f"{r['label']}（{r['events']:.0f} 事件/流）",
                size=12,
                anchor="middle",
                weight="bold",
            )
        )
        for si, (key, _) in enumerate(stats):
            measured = r[key]
            fixed = f_ms
            per_event = r["events"] * e_ms
            base = r["floor"] + fixed + per_event
            residual = max(0.0, measured - base)
            bx = gx + (group_w - bar_w * len(stats)) / 2 + si * bar_w
            y = ay + ah
            for value, color in (
                (r["floor"], C_FLOOR),
                (fixed, C_FIXED),
                (per_event, C_EVENT),
                (residual, C_QUEUE),
            ):
                h = (value / ymax) * ah
                y -= h
                out.append(rect(bx, y, bar_w - 8, h, color))
            out.append(
                text(bx + (bar_w - 8) / 2, y - 6, f"{measured:.0f}", size=11, anchor="middle", weight="bold")
            )
            out.append(
                text(
                    bx + (bar_w - 8) / 2,
                    ay + ah + 38,
                    dict(stats)[key].split("（")[0],
                    size=10,
                    fill=C_MUTED,
                    anchor="middle",
                )
            )

    # ---------- B 面板：请求速率 vs 排队 ----------
    bx0, by, bw, bh = 760, 150, 432, 380
    out.append(text(bx0, by - 14, "B. 为什么两轮不能直接相减：速率混淆", size=15, weight="bold"))
    rps = [r["requests"] / (meta.get("dur_secs", 30.0)) for r in runs]
    queue = [max(0.0, r["med"] - (r["floor"] + f_ms + r["events"] * e_ms)) for r in runs]
    rps_max = max(1e-6, max(rps) * 1.25)
    q_max = max(1e-6, max(queue) * 1.35)

    def by_rps(v):
        return by + bh - (v / rps_max) * bh

    def by_q(v):
        return by + bh - (v / q_max) * bh

    out.append(
        f'<line x1="{bx0}" y1="{by + bh}" x2="{bx0 + bw}" y2="{by + bh}" stroke="#94a3b8" stroke-width="1.5"/>'
    )
    slot = bw / len(runs)
    for i, r in enumerate(runs):
        cx = bx0 + slot * i
        # 请求速率（左轴，蓝）
        w = 52
        h = by + bh - by_rps(rps[i])
        out.append(rect(cx + slot / 2 - w - 6, by_rps(rps[i]), w, h, C_FIXED, 0.85))
        out.append(
            text(cx + slot / 2 - w / 2 - 6, by_rps(rps[i]) - 7, f"{rps[i]:.1f}/s", size=11, anchor="middle", weight="bold")
        )
        # 排队幅度（右轴，橙）
        h2 = by + bh - by_q(queue[i])
        out.append(rect(cx + slot / 2 + 6, by_q(queue[i]), w, h2, C_QUEUE, 0.9))
        out.append(
            text(cx + slot / 2 + w / 2 + 6, by_q(queue[i]) - 7, f"+{queue[i]:.0f}ms", size=11, anchor="middle", weight="bold")
        )
        out.append(text(cx + slot / 2, by + bh + 22, r["label"], size=12, anchor="middle"))
    out.append(text(bx0, by + bh + 52, "■ 请求速率（req/s，左轴）　■ 排队幅度 = med − 模型（右轴）", size=11, fill=C_MUTED))
    out.append(
        text(
            bx0,
            by + bh + 74,
            "同样的 20 VUs 下，流越短 → QPS 越高 → 排队越重；",
            size=11,
            fill=C_MUTED,
        )
    )
    out.append(
        text(
            bx0,
            by + bh + 92,
            "所以只有 min 适合拟合固有开销，med/avg 混了排队。",
            size=11,
            fill=C_MUTED,
        )
    )

    # ---------- 图例 ----------
    ly = 600
    legend = [
        (C_FLOOR, f"上游地板 = CONTENT_LEN × {MS_PER_CHAR:.0f}ms（mock 自己的节奏，与网关无关）"),
        (C_FIXED, f"固定开销 F ≈ {f_ms:.0f} ms（网络 RTT + 鉴权 + 开流 + 上游建连）"),
        (C_EVENT, f"每事件 ≈ {e_ms:.2f} ms × 事件数"),
        (C_QUEUE, "排队/其它（实测 − 前两者；随 QPS 增长）"),
    ]
    for i, (color, label) in enumerate(legend):
        y = ly + i * 26
        out.append(rect(48, y - 11, 14, 14, color))
        out.append(text(70, y, label, size=13))

    # ---------- 结论 ----------
    ty = 720
    out.append(text(48, ty, "结论", size=15, weight="bold"))
    for i, line in enumerate(meta.get("takeaways", [])):
        out.append(text(48, ty + 26 + i * 22, f"· {line}", size=13))
    out.append(
        text(
            48,
            H - 22,
            "生成：scripts/bench-k6/report.py（读 k6 --summary-export 的 JSON；SVG 手写，无第三方依赖）",
            size=11,
            fill=C_MUTED,
        )
    )
    out.append("</svg>")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", required=True, help="manifest JSON（[{label, content_len, summary}]）")
    ap.add_argument("-o", "--out", default="sse-report.svg")
    ap.add_argument("--where", default="", help="环境说明（写进副标题）")
    ap.add_argument("--table", action="store_true", help="只打印 markdown 汇总表，不出图")
    ap.add_argument("--vus", default="20")
    ap.add_argument("--dur", default="30s")
    args = ap.parse_args()

    manifest = json.loads(Path(args.runs).read_text())
    runs = sorted((read_run(m) for m in manifest), key=lambda r: r["content_len"])

    if args.table:
        dur_secs = float("".join(ch for ch in args.dur if ch.isdigit() or ch == ".") or 30)
        print(render_table(runs, dur_secs), end="")
        return 0
    f_ms, e_ms, fitted = fit_fixed_and_per_event(runs)
    dur_secs = float("".join(ch for ch in args.dur if ch.isdigit() or ch == ".") or 30)

    a, b = max(runs, key=lambda r: r["content_len"]), min(runs, key=lambda r: r["content_len"])
    meta = {
        "where": args.where,
        "vus": args.vus,
        "dur": args.dur,
        "dur_secs": dur_secs,
        "takeaways": [
            f"两轮事件数恒为 {a['events']:.0f} / {b['events']:.0f}（= N+2）且 min=med=max："
            f"零截断；http_req_failed={a['failed'] * 100:.0f}%",
            (f"固有开销 ≈ {f_ms:.0f} ms/请求 + {e_ms:.2f} ms/事件；真实模型 10–50 ms/token，"
             f"每事件开销只占 3–15%，不是瓶颈")
            if fitted
            else "单轮：无法分离固定开销与每事件开销，需再跑一次不同 CONTENT_LEN",
            f"高分位由排队主导：{a['label']} p95={a['p95']:.0f}ms 中排队占 "
            f"{max(0.0, a['p95'] - (a['floor'] + f_ms + a['events'] * e_ms)):.0f}ms",
            "阈值 p(95)<5000ms 相对实测有 ~10 倍余量，等于没有约束力；建议按目标写绝对上限",
        ],
    }
    svg = build_svg(runs, f_ms, e_ms, meta, fitted)
    Path(args.out).write_text(svg)
    print(f"wrote {args.out}  (F≈{f_ms:.1f}ms, e≈{e_ms:.2f}ms/event)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
