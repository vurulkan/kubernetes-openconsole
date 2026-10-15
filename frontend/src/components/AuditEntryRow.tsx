import React from 'react';
import { useTranslation } from 'react-i18next';
import type { AuditEntry } from '../services/api';
import { Badge } from './ui';

const OUTCOME_VARIANT: Record<string, 'success' | 'warning' | 'error' | 'default'> = {
  success: 'success',
  denied: 'error',
  failed: 'error',
  rate_limited: 'warning',
  locked: 'warning',
};

const formatValue = (v: unknown) => (Array.isArray(v) ? v.join(', ') : String(v));

/** One audit event: who did what to which resource, the outcome, and (on
 *  expand) its details and where the request came from. */
export const AuditEntryRow: React.FC<{ entry: AuditEntry }> = ({ entry }) => {
  const { t: tr } = useTranslation();
  const target = [entry.namespace, entry.resourceName].filter(Boolean).join('/');
  const details = Object.entries(entry.details ?? {});
  const meta: Array<[string, string | undefined]> = [
    [tr('admin.audit.reason'), entry.reason],
    [tr('admin.audit.sourceIp'), entry.sourceIp],
    [tr('admin.audit.authSource'), entry.authSource],
    [tr('admin.audit.requestId'), entry.requestId],
    [tr('admin.audit.userAgent'), entry.userAgent],
  ];
  const rows = [...meta.filter(([, v]) => v), ...details.map(([k, v]) => [k, formatValue(v)] as [string, string])];

  return (
    <div className="rounded-lg border border-slate-100 dark:border-slate-800 bg-white dark:bg-slate-900 px-4 py-3">
      <p className="flex flex-wrap items-center gap-2 text-sm font-semibold text-slate-900 dark:text-slate-100">
        <span>{entry.user || 'unknown'}</span>
        <span className="font-mono font-normal text-slate-600 dark:text-slate-300">{entry.action}</span>
        {entry.outcome && <Badge variant={OUTCOME_VARIANT[entry.outcome] ?? 'default'}>{entry.outcome}</Badge>}
      </p>
      <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{entry.timestampFormatted ?? entry.timestamp}</p>
      <p className="text-xs text-slate-500 dark:text-slate-400">
        {entry.cluster && (
          <span
            className="mr-1.5 rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-600 dark:bg-slate-800 dark:text-slate-300"
            title={tr('admin.audit.cluster')}
          >
            {entry.cluster}
          </span>
        )}
        {entry.resourceType} {target && <span className="font-mono">{target}</span>}
      </p>
      {rows.length > 0 && (
        <details className="mt-1 text-xs text-slate-500 dark:text-slate-400">
          <summary className="cursor-pointer select-none hover:text-slate-700 dark:hover:text-slate-200">
            {tr('admin.audit.details')}
          </summary>
          <dl className="mt-1 grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5">
            {rows.map(([k, v]) => (
              <React.Fragment key={k}>
                <dt className="font-mono text-slate-600 dark:text-slate-300">{k}</dt>
                <dd className="break-all font-mono">{v}</dd>
              </React.Fragment>
            ))}
          </dl>
        </details>
      )}
    </div>
  );
};
