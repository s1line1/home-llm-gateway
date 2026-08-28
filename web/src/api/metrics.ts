// Prometheus 文本格式解析器（仅解析网关 /metrics 用到的子集）。
//
// 格式示例：
//   # HELP hlmg_requests_total Total gateway requests by HTTP status.
//   # TYPE hlmg_requests_total counter
//   hlmg_requests_total{status="200"} 42
//   hlmg_active_requests 3

import type { MetricsSnapshot } from "./types";

interface RawSample {
  name: string;
  labels: Record<string, string>;
  value: number;
}

/** 逐行解析：跳过 # 注释与空行，识别 `name{labels} value` 与 `name value`。 */
export function parsePrometheus(text: string): RawSample[] {
  const samples: RawSample[] = [];
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const sample = parseLine(line);
    if (sample) samples.push(sample);
  }
  return samples;
}

function parseLine(line: string): RawSample | null {
  const match = /^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{([^}]*)\})?\s+(-?[0-9.eE+]+)/.exec(line);
  if (!match) return null;
  const labels: Record<string, string> = {};
  const labelPart = match[2];
  if (labelPart) {
    for (const pair of labelPart.split(",")) {
      const eq = pair.indexOf("=");
      if (eq > 0) {
        const key = pair.slice(0, eq).trim();
        let value = pair.slice(eq + 1).trim();
        if (value.startsWith('"') && value.endsWith('"')) {
          value = value.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, "\\");
        }
        labels[key] = value;
      }
    }
  }
  return { name: match[1], labels, value: Number(match[3]) };
}

function first(samples: RawSample[], name: string): number | undefined {
  for (const s of samples) if (s.name === name) return s.value;
  return undefined;
}

/** 把 /metrics 文本解析为结构化快照（缺字段时回退 0）。 */
export function parseMetrics(text: string): MetricsSnapshot {
  const samples = parsePrometheus(text);

  const requests_by_status: Record<number, number> = {};
  for (const s of samples) {
    if (s.name === "hlmg_requests_total" && s.labels.status) {
      requests_by_status[Number(s.labels.status)] = s.value;
    }
  }

  return {
    fetched_at: Date.now(),
    requests_by_status,
    active_requests: first(samples, "hlmg_active_requests") ?? 0,
    agents: first(samples, "hlmg_agents") ?? 0,
    bytes_out: first(samples, "hlmg_bytes_out") ?? 0,
    request_duration_ms: first(samples, "hlmg_request_duration_ms") ?? 0,
    request_count: first(samples, "hlmg_request_count") ?? 0,
  };
}

/** 把 bytes 格式化为人类可读。 */
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = n;
  let u = -1;
  do {
    v /= 1024;
    u += 1;
  } while (v >= 1024 && u < units.length - 1);
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[u]}`;
}

/** 秒 → 人类可读时长。 */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  const sec = ms / 1000;
  if (sec < 60) return `${sec.toFixed(sec < 10 ? 1 : 0)} s`;
  const min = sec / 60;
  if (min < 60) return `${min.toFixed(min < 10 ? 1 : 0)} min`;
  return `${(min / 60).toFixed(1)} h`;
}
