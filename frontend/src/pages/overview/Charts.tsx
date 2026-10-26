import React, { useRef, useState } from 'react';

/**
 * A stat tile's trend: one 2px line in the de-emphasis gray, the latest point in the accent.
 * Decorative next to the tile's number, so the summary is text for screen readers.
 */
export const Sparkline: React.FC<{ values: number[]; summary: string }> = ({ values, summary }) => {
  if (values.length < 2) return <span className="sr-only">{summary}</span>;
  const W = 120;
  const H = 32;
  const lo = Math.min(...values);
  const hi = Math.max(...values);
  const x = (i: number) => 2 + (i / (values.length - 1)) * (W - 6);
  const y = (v: number) => (hi === lo ? H / 2 : 3 + (1 - (v - lo) / (hi - lo)) * (H - 6));
  const d = values.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join('');
  const last = values.length - 1;
  return (
    <>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-8 w-full" preserveAspectRatio="none" aria-hidden="true">
        <path d={d} fill="none" className="stroke-slate-300 dark:stroke-slate-600" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
      </svg>
      {/* The end dot sits outside the stretched svg so it stays round. */}
      <span
        className="pointer-events-none absolute h-2 w-2 -translate-x-1/2 -translate-y-1/2 rounded-full bg-brand-500 ring-2 ring-white dark:bg-brand-400 dark:ring-slate-900"
        style={{ left: `${(x(last) / W) * 100}%`, top: `${(y(values[last]) / H) * 100}%` }}
        aria-hidden="true"
      />
      <span className="sr-only">{summary}</span>
    </>
  );
};

/**
 * Columns per hour (24 of them, oldest first): one series, one hue, 4px rounded tops on a single
 * baseline. Hover or arrow keys pick a column; the same numbers are in a screen-reader table.
 */
export const HourlyBars: React.FC<{
  counts: number[];
  hourStart: number; // unix seconds of the first column
  title: string;
  valueLabel: (n: number) => string;
}> = ({ counts, hourStart, title, valueLabel }) => {
  const [hover, setHover] = useState<number | null>(null);
  const ref = useRef<SVGSVGElement | null>(null);
  const W = 560;
  const H = 140;
  const PAD = { l: 28, r: 4, t: 18, b: 18 };
  const max = Math.max(1, ...counts);
  const slot = (W - PAD.l - PAD.r) / counts.length;
  const bw = Math.min(24, slot - 2);
  const y = (v: number) => PAD.t + (1 - v / max) * (H - PAD.t - PAD.b);
  const hourText = (i: number) => new Date((hourStart + i * 3600) * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const pick = (clientX: number) => {
    const box = ref.current?.getBoundingClientRect();
    if (!box) return;
    const i = Math.floor((((clientX - box.left) / box.width) * W - PAD.l) / slot);
    setHover(i >= 0 && i < counts.length ? i : null);
  };
  const h = hover;
  return (
    <figure className="flex flex-col gap-1">
      <figcaption className="flex items-baseline justify-between text-xs">
        <span className="font-medium text-slate-700 dark:text-slate-200">{title}</span>
        <span className="font-mono text-slate-500 dark:text-slate-400" aria-live="polite">
          {h !== null ? `${hourText(h)}–${hourText(h + 1)} · ${valueLabel(counts[h])}` : ''}
        </span>
      </figcaption>
      <svg
        ref={ref}
        viewBox={`0 0 ${W} ${H}`}
        className="h-auto w-full touch-none select-none rounded-md focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60"
        role="img"
        aria-label={title}
        tabIndex={0}
        onPointerMove={(e) => pick(e.clientX)}
        onPointerLeave={() => setHover(null)}
        onBlur={() => setHover(null)}
        onKeyDown={(e) => {
          if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
          e.preventDefault();
          const i = hover ?? counts.length - 1;
          setHover(Math.max(0, Math.min(counts.length - 1, i + (e.key === 'ArrowRight' ? 1 : -1))));
        }}
      >
        <line x1={PAD.l} x2={W - PAD.r} y1={y(0)} y2={y(0)} className="stroke-slate-200 dark:stroke-slate-800" strokeWidth={1} />
        <line x1={PAD.l} x2={W - PAD.r} y1={y(max)} y2={y(max)} className="stroke-slate-200 dark:stroke-slate-800" strokeWidth={1} />
        <text x={PAD.l - 6} y={y(max) + 3} textAnchor="end" fontSize={10} className="fill-slate-500 dark:fill-slate-400">{max}</text>
        <text x={PAD.l - 6} y={y(0) + 3} textAnchor="end" fontSize={10} className="fill-slate-500 dark:fill-slate-400">0</text>
        {counts.map((n, i) => {
          const cx = PAD.l + i * slot + slot / 2;
          const top = y(n);
          const r = Math.min(4, (y(0) - top) / 2, bw / 2);
          const x0 = cx - bw / 2;
          // Rounded data end, square at the baseline.
          const d = n
            ? `M${x0},${y(0)}V${top + r}Q${x0},${top} ${x0 + r},${top}H${x0 + bw - r}Q${x0 + bw},${top} ${x0 + bw},${top + r}V${y(0)}Z`
            : '';
          return (
            <g key={i}>
              {h === i && <rect x={cx - slot / 2} y={PAD.t} width={slot} height={H - PAD.t - PAD.b} className="fill-slate-100 dark:fill-slate-800/60" />}
              {d && <path d={d} className={h === i ? 'fill-brand-600 dark:fill-brand-300' : 'fill-brand-500 dark:fill-brand-400'} />}
              {i % 6 === 0 && (
                <text x={cx} y={H - 4} textAnchor="middle" fontSize={10} className="fill-slate-500 dark:fill-slate-400">
                  {hourText(i)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <table className="sr-only">
        <caption>{title}</caption>
        <tbody>
          {counts.map((n, i) => (
            <tr key={i}>
              <th scope="row">{hourText(i)}</th>
              <td>{valueLabel(n)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </figure>
  );
};
