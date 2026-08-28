// 轻量 SVG 折线图（无外部依赖）：输入数值序列，自动归一化绘制。

export function Sparkline({
  data,
  width = 320,
  height = 64,
  stroke = "#334155",
  fill = true,
}: {
  data: number[];
  width?: number;
  height?: number;
  stroke?: string;
  fill?: boolean;
}) {
  if (data.length < 2) {
    return (
      <div className="flex h-full items-center justify-center text-xs text-slate-400">
        采样中…
      </div>
    );
  }
  const min = Math.min(...data);
  const max = Math.max(...data);
  const span = max - min || 1;
  const pad = 4;
  const stepX = (width - pad * 2) / (data.length - 1);
  const y = (v: number) => height - pad - ((v - min) / span) * (height - pad * 2);

  const points = data.map((v, i) => `${(pad + i * stepX).toFixed(1)},${y(v).toFixed(1)}`);
  const area = `M ${pad} ${height - pad} L ${points.join(" L ")} L ${width - pad} ${height - pad} Z`;

  const gid = `spark-${stroke.replace(/[^a-zA-Z0-9]/g, "")}`;

  return (
    <svg viewBox={`0 0 ${width} ${height}`} width="100%" height={height} preserveAspectRatio="none" aria-hidden>
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={stroke} stopOpacity="0.25" />
          <stop offset="100%" stopColor={stroke} stopOpacity="0" />
        </linearGradient>
      </defs>
      {fill && <path d={area} fill={`url(#${gid})`} />}
      <polyline points={points.join(" ")} fill="none" stroke={stroke} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

/** 横排条形图（状态码分布等），值为整数。 */
export function BarList({ items }: { items: { label: string; value: number; color?: string }[] }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <div className="space-y-2">
      {items.map((it) => (
        <div key={it.label} className="flex items-center gap-2 text-xs">
          <span className="w-10 shrink-0 font-mono text-slate-500">{it.label}</span>
          <div className="h-3 flex-1 overflow-hidden rounded bg-slate-100">
            <div
              className="h-full rounded bg-slate-700 transition-all"
              style={{ width: `${(it.value / max) * 100}%`, background: it.color }}
              title={`${it.label}: ${it.value}`}
            />
          </div>
          <span className="w-14 shrink-0 text-right font-mono tabular-nums text-slate-600">{it.value}</span>
        </div>
      ))}
    </div>
  );
}
