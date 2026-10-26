import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { UsageHistory } from '../services/api';
import { formatCpu, formatMem } from '../utils/format';
import { Spinner } from './ui';

type Kind = 'cpu' | 'mem';
const fmt = (kind: Kind, v: number) => (kind === 'cpu' ? formatCpu(v) : formatMem(v));

// Meter fill carries severity; the track is a lighter step of the same hue.
const TONES = {
  ok: { fill: 'bg-brand-500', track: 'bg-brand-100 dark:bg-brand-500/20' },
  warn: { fill: 'bg-amber-500', track: 'bg-amber-100 dark:bg-amber-500/20' },
  high: { fill: 'bg-rose-500', track: 'bg-rose-100 dark:bg-rose-500/20' },
};
export const toneOf = (pct: number) => (pct >= 90 ? TONES.high : pct >= 70 ? TONES.warn : TONES.ok);

/**
 * "412Mi / 512Mi" with a meter of usage against the limit, or the request
 * when there is no limit ("req"), or just the value when neither is set.
 */
export const UsageBar: React.FC<{
  kind: Kind;
  used?: number;
  limit?: number;
  request?: number;
  className?: string;
  /** One short line ("201m · 100%") for table cells; the full text goes to the title. */
  compact?: boolean;
}> = ({ kind, used, limit, request, className = '', compact = false }) => {
  const { t } = useTranslation();
  if (used === undefined || !Number.isFinite(used)) return <span className="font-mono text-xs text-slate-400">—</span>;
  const base = limit && Number.isFinite(limit) ? limit : request && Number.isFinite(request) && request > 0 ? request : 0;
  const isLimit = base === limit;
  const pct = base ? Math.round((used / base) * 100) : 0;
  const tone = toneOf(isLimit ? pct : 0);
  const label = kind === 'cpu' ? 'CPU' : t('dashboard.usage.memory');
  const full = `${fmt(kind, used)}${base ? ` / ${fmt(kind, base)}${isLimit ? '' : ` ${t('dashboard.usage.req')}`} · ${pct}%` : ` · ${t('dashboard.usage.noLimit')}`}`;
  return (
    <span className={`inline-flex min-w-0 flex-col gap-1 ${className}`} title={compact ? full : undefined}>
      {compact ? (
        <span className="whitespace-nowrap font-mono text-xs text-slate-700 dark:text-slate-200">
          {fmt(kind, used)}
          {base > 0 && <span className="text-slate-500 dark:text-slate-400"> · {pct}%</span>}
        </span>
      ) : (
      <span className="font-mono text-xs text-slate-700 dark:text-slate-200">
        {fmt(kind, used)}
        {base > 0 && (
          <span className="text-slate-500 dark:text-slate-400">
            {' / '}
            {fmt(kind, base)}
            {!isLimit && ` ${t('dashboard.usage.req')}`} · {pct}%
          </span>
        )}
        {!base && <span className="text-slate-500 dark:text-slate-400"> · {t('dashboard.usage.noLimit')}</span>}
      </span>
      )}
      {base > 0 && (
        <span
          role="meter"
          aria-label={`${label} ${isLimit ? t('dashboard.usage.ofLimit') : t('dashboard.usage.ofRequest')}`}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={Math.min(pct, 100)}
          aria-valuetext={`${pct}%`}
          className={`block h-1 w-full max-w-[140px] overflow-hidden rounded-full ${tone.track}`}
        >
          <span className={`block h-full rounded-full ${tone.fill}`} style={{ width: `${Math.min(pct, 100)}%` }} />
        </span>
      )}
    </span>
  );
};

const MEMORY_RANGES = ['1h', '6h', '24h'];
const W = 560;
const H = 120;
const PAD = { l: 44, r: 8, t: 8, b: 18 };

const clock = (t: number) =>
  new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

/** One series over time with an optional dashed limit line; crosshair + tooltip on hover / arrow keys. */
export const LineChart: React.FC<{
  kind: Kind;
  title: string;
  points: Array<{ t: number; v: number }>;
  limit?: number;
  /** Text before the limit value; "limit" by default ("allocatable" on the overview). */
  limitLabel?: string;
}> = ({ kind, title, points, limit, limitLabel }) => {
  const { t } = useTranslation();
  const [hover, setHover] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const t0 = points[0]?.t ?? 0;
  const t1 = points[points.length - 1]?.t ?? 1;
  const top = Math.max(...points.map((p) => p.v), limit && Number.isFinite(limit) ? limit : 0) * 1.1 || 1;
  const x = (tt: number) => PAD.l + ((tt - t0) / Math.max(1, t1 - t0)) * (W - PAD.l - PAD.r);
  const y = (v: number) => PAD.t + (1 - v / top) * (H - PAD.t - PAD.b);
  const path = points.map((p, i) => `${i ? 'L' : 'M'}${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join('');
  const last = points[points.length - 1];
  const peak = points.reduce((m, p) => Math.max(m, p.v), 0);
  const h = hover !== null ? points[hover] : null;

  const pick = (clientX: number) => {
    const box = svgRef.current?.getBoundingClientRect();
    if (!box || !points.length) return;
    const tt = t0 + ((clientX - box.left) / box.width * W - PAD.l) / (W - PAD.l - PAD.r) * (t1 - t0);
    let best = 0;
    points.forEach((p, i) => {
      if (Math.abs(p.t - tt) < Math.abs(points[best].t - tt)) best = i;
    });
    setHover(best);
  };

  return (
    <figure className="flex flex-col gap-1">
      <figcaption className="flex items-baseline justify-between text-xs">
        <span className="font-medium text-slate-700 dark:text-slate-200">{title}</span>
        <span className="font-mono text-slate-500 dark:text-slate-400">
          {h ? `${clock(h.t)} · ${fmt(kind, h.v)}` : last ? `${t('dashboard.usage.now')} ${fmt(kind, last.v)} · ${t('dashboard.usage.peak')} ${fmt(kind, peak)}` : ''}
        </span>
      </figcaption>
      <div className="relative">
        <svg
          ref={svgRef}
          viewBox={`0 0 ${W} ${H}`}
          className="h-auto w-full touch-none select-none rounded-md text-slate-400 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60"
          role="img"
          aria-label={`${title}: ${t('dashboard.usage.now')} ${last ? fmt(kind, last.v) : '—'}, ${t('dashboard.usage.peak')} ${fmt(kind, peak)}`}
          tabIndex={0}
          onPointerMove={(e) => pick(e.clientX)}
          onPointerLeave={() => setHover(null)}
          onBlur={() => setHover(null)}
          onKeyDown={(e) => {
            if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
            e.preventDefault();
            const i = hover ?? points.length - 1;
            setHover(Math.max(0, Math.min(points.length - 1, i + (e.key === 'ArrowRight' ? 1 : -1))));
          }}
        >
          {[0, 0.5, 1].map((f) => (
            <g key={f}>
              <line x1={PAD.l} x2={W - PAD.r} y1={y(top * f / 1.1)} y2={y(top * f / 1.1)} className="stroke-slate-200 dark:stroke-slate-800" strokeWidth={1} />
              {/* The middle label is dropped when rounding makes it read like the top one. */}
              {(f !== 0.5 || fmt(kind, top / 2.2) !== fmt(kind, top / 1.1)) && (
                <text x={PAD.l - 6} y={y(top * f / 1.1) + 3} textAnchor="end" className="fill-slate-500 dark:fill-slate-400" fontSize={10}>
                  {fmt(kind, (top * f) / 1.1)}
                </text>
              )}
            </g>
          ))}
          {limit !== undefined && Number.isFinite(limit) && (
            <g>
              <line x1={PAD.l} x2={W - PAD.r} y1={y(limit)} y2={y(limit)} className="stroke-slate-500 dark:stroke-slate-400" strokeWidth={1} strokeDasharray="4 3" />
              <text x={W - PAD.r} y={y(limit) - 3} textAnchor="end" className="fill-slate-500 dark:fill-slate-400" fontSize={10}>
                {limitLabel ?? t('dashboard.usage.limit')} {fmt(kind, limit)}
              </text>
            </g>
          )}
          {points.length > 1 && <path d={path} fill="none" className="stroke-brand-500 dark:stroke-brand-400" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />}
          {points.length === 1 && <circle cx={x(points[0].t)} cy={y(points[0].v)} r={4} className="fill-brand-500" />}
          <text x={PAD.l} y={H - 4} className="fill-slate-500 dark:fill-slate-400" fontSize={10}>{points.length ? clock(t0) : ''}</text>
          <text x={W - PAD.r} y={H - 4} textAnchor="end" className="fill-slate-500 dark:fill-slate-400" fontSize={10}>{points.length ? clock(t1) : ''}</text>
          {h && (
            <g>
              <line x1={x(h.t)} x2={x(h.t)} y1={PAD.t} y2={H - PAD.b} className="stroke-slate-400 dark:stroke-slate-500" strokeWidth={1} />
              <circle cx={x(h.t)} cy={y(h.v)} r={4} className="fill-brand-500 stroke-white dark:stroke-slate-900" strokeWidth={2} />
            </g>
          )}
        </svg>
      </div>
    </figure>
  );
};

/**
 * CPU and memory charts for a pod or a deployment, with a range picker and
 * the data source spelled out (in-memory history is capped and volatile).
 */
export const UsageHistoryPanel: React.FC<{
  load: (range: string) => Promise<UsageHistory>;
  cpuLimit?: number;
  memLimit?: number;
  /** Label of the dashed line; "limit" by default ("allocatable" for a node). */
  limitLabel?: string;
  reloadKey: unknown;
}> = ({ load, cpuLimit, memLimit, limitLabel, reloadKey }) => {
  const { t } = useTranslation();
  const [range, setRange] = useState('1h');
  const [data, setData] = useState<UsageHistory | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let live = true;
    load(range)
      .then((d) => live && (setData(d), setFailed(false)))
      .catch(() => live && setFailed(true));
    return () => {
      live = false;
    };
    // load is a new closure on every render; range and reloadKey say when to refetch.
  }, [range, reloadKey]);
  const cpu = useMemo(() => (data?.points ?? []).map((p) => ({ t: p.t, v: p.cpu })), [data]);
  const mem = useMemo(() => (data?.points ?? []).map((p) => ({ t: p.t, v: p.memory })), [data]);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div role="group" aria-label={t('dashboard.usage.range')} className="inline-flex rounded-lg border border-slate-200 p-0.5 dark:border-slate-700">
          {(data?.ranges ?? MEMORY_RANGES).map((r) => (
            <button
              key={r}
              type="button"
              aria-pressed={range === r}
              onClick={() => setRange(r)}
              className={`rounded-md px-2.5 py-1 font-mono text-[11px] focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 ${
                range === r
                  ? 'bg-brand-50 text-brand-700 dark:bg-brand-500/15 dark:text-brand-200'
                  : 'text-slate-600 hover:bg-slate-50 dark:text-slate-300 dark:hover:bg-slate-800'
              }`}
            >
              {r}
            </button>
          ))}
        </div>
        <span className="text-[11px] text-slate-500 dark:text-slate-400">
          {data?.note === 'prometheus_unreachable'
            ? t('dashboard.usage.prometheusUnreachable')
            : data?.source === 'prometheus'
              ? 'Prometheus'
              : t('dashboard.usage.sourceMemory')}
        </span>
      </div>
      {failed ? (
        <p className="text-xs text-slate-500 dark:text-slate-400">{t('dashboard.usage.historyFailed')}</p>
      ) : !data ? (
        <Spinner size="sm" />
      ) : !data.points.length ? (
        <p className="text-xs text-slate-500 dark:text-slate-400">{t('dashboard.usage.noHistory')}</p>
      ) : (
        <>
          <LineChart kind="cpu" title="CPU" points={cpu} limit={cpuLimit} limitLabel={limitLabel} />
          <LineChart kind="mem" title={t('dashboard.usage.memory')} points={mem} limit={memLimit} limitLabel={limitLabel} />
        </>
      )}
    </div>
  );
};
