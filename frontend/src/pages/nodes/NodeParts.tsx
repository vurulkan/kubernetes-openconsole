// Pieces shared by the node list and the node drawer.
import React from 'react';
import { AlertTriangle, Ban, CheckCircle2, XCircle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Badge } from '../../components/ui';
import { toneOf } from '../../components/Usage';
import type { NodeRow } from '../../services/api';
import { formatCpu, formatMem } from '../../utils/format';

export const pct = (used: number | undefined, of: number) =>
  used !== undefined && of > 0 ? Math.round((used / of) * 100) : null;

/** 0 ready, 1 pressure, 2 not ready: sorts the troubled nodes last (or first, descending). */
export const nodeRank = (n: Pick<NodeRow, 'ready' | 'pressure'>) => (!n.ready ? 2 : n.pressure.length ? 1 : 0);

/**
 * Search: every space-separated term must match. "key=value" matches a label exactly,
 * "key=" any value of that label; other terms are substrings of the name or a role.
 */
export function matchNode(n: Pick<NodeRow, 'name' | 'roles' | 'labels'>, query: string): boolean {
  return query
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((term) => {
      const eq = term.indexOf('=');
      if (eq > 0) {
        const key = term.slice(0, eq);
        const value = term.slice(eq + 1);
        return Object.entries(n.labels ?? {}).some(([k, v]) => k.toLowerCase() === key && (value === '' || v.toLowerCase() === value));
      }
      return n.name.toLowerCase().includes(term) || n.roles.some((r) => r.toLowerCase().includes(term));
    });
}

/** Ready / NotReady / pressure, and cordoned apart: icon + label, never color alone. */
export const NodeStatus: React.FC<{ node: Pick<NodeRow, 'ready' | 'pressure' | 'unschedulable'> }> = ({ node }) => {
  const { t } = useTranslation();
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {!node.ready ? (
        <Badge variant="error"><XCircle size={12} aria-hidden="true" />{t('overview.node.notReady')}</Badge>
      ) : (
        <Badge variant="success"><CheckCircle2 size={12} aria-hidden="true" />{t('overview.node.ready')}</Badge>
      )}
      {node.pressure.map((p) => (
        <Badge key={p} variant="warning"><AlertTriangle size={12} aria-hidden="true" />{p}</Badge>
      ))}
      {node.unschedulable && (
        <Badge variant="default"><Ban size={12} aria-hidden="true" />{t('overview.node.cordoned')}</Badge>
      )}
    </span>
  );
};

/**
 * A node's CPU or memory against allocatable: usage with a meter (>= 90 % red, >= 70 % amber),
 * then requests and limits as % of allocatable.
 */
export const NodeMeter: React.FC<{
  kind: 'cpu' | 'mem';
  used?: number;
  requests: number;
  limits: number;
  allocatable: number;
  /** Narrow tables: "CPU 45%" and the meter; the rest goes to the title. */
  compact?: boolean;
}> = ({ kind, used, requests, limits, allocatable, compact = false }) => {
  const { t } = useTranslation();
  const fmt = kind === 'cpu' ? formatCpu : formatMem;
  const u = pct(used, allocatable);
  const label = kind === 'cpu' ? 'CPU' : t('dashboard.usage.memory');
  const title = t('nodes.meterTitle', {
    used: used === undefined ? '—' : fmt(used),
    total: fmt(allocatable),
    requests: fmt(requests),
    limits: fmt(limits),
  });
  return (
    <span className={`inline-flex flex-col gap-1 ${compact ? 'min-w-[72px]' : 'min-w-[96px]'}`} title={title}>
      <span className="whitespace-nowrap font-mono text-xs text-slate-700 dark:text-slate-200">
        {compact && <span className="text-slate-500 dark:text-slate-400">{kind === 'cpu' ? 'CPU' : t('nodes.memShort')} </span>}
        {u === null ? '—' : `${u}%`}
        {!compact && used !== undefined && <span className="text-slate-500 dark:text-slate-400"> · {fmt(used)}</span>}
      </span>
      {u !== null && (
        <span
          role="meter"
          aria-label={`${label} ${t('nodes.ofAllocatable')}`}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={Math.min(u, 100)}
          aria-valuetext={`${u}%`}
          className={`block h-1 w-full max-w-[120px] overflow-hidden rounded-full ${toneOf(u).track}`}
        >
          <span className={`block h-full rounded-full ${toneOf(u).fill}`} style={{ width: `${Math.min(u, 100)}%` }} />
        </span>
      )}
      {!compact && (
      <span className="whitespace-nowrap font-mono text-[11px] text-slate-500 dark:text-slate-400">
        {t('nodes.reqLim', { requests: pct(requests, allocatable) ?? '—', limits: pct(limits, allocatable) ?? '—' })}
      </span>
      )}
    </span>
  );
};
