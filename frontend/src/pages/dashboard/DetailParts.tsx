// Building blocks shared by the pod and deployment detail drawers.
import React, { useEffect, useState } from 'react';
import { CheckCircle2, CircleDashed, XCircle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Spinner } from '../../components/ui';
import { ageShort } from '../../utils/age';

export type Item = Record<string, any>;

export const Section: React.FC<{ title: string; aside?: React.ReactNode; children: React.ReactNode }> = ({
  title,
  aside,
  children,
}) => (
  <section className="flex flex-col gap-2">
    <div className="flex items-center justify-between gap-2">
      <h3 className="text-[11px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">{title}</h3>
      {aside}
    </div>
    {children}
  </section>
);

export const Fields: React.FC<{ rows: Array<[string, React.ReactNode]> }> = ({ rows }) => (
  <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-xs">
    {rows.map(([k, v]) => (
      <React.Fragment key={k}>
        <dt className="text-slate-500 dark:text-slate-400">{k}</dt>
        <dd className="min-w-0 break-words font-mono text-slate-800 dark:text-slate-200">{v ?? '—'}</dd>
      </React.Fragment>
    ))}
  </dl>
);

export const Empty: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <p className="text-xs text-slate-500 dark:text-slate-400">{children}</p>
);

type Condition = { type?: string; status?: string; reason?: string; message?: string; lastTransitionTime?: string };

/** okWhenFalse: condition types that are healthy when False (a node's MemoryPressure, DiskPressure, …). */
export const Conditions: React.FC<{ items?: Condition[]; okWhenFalse?: (type?: string) => boolean }> = ({ items, okWhenFalse }) => {
  const { t } = useTranslation();
  if (!items?.length) return <Empty>{t('dashboard.detail.none')}</Empty>;
  return (
    <ul className="flex flex-col gap-1.5 text-xs">
      {items.map((c) => (
        <li key={c.type} className="flex items-start gap-2">
          {c.status === 'True' || c.status === 'False' ? (
            (c.status === 'True') !== Boolean(okWhenFalse?.(c.type)) ? (
              <CheckCircle2 size={14} aria-label={c.status} className="mt-px shrink-0 text-emerald-500" />
            ) : (
              <XCircle size={14} aria-label={c.status} className="mt-px shrink-0 text-rose-500" />
            )
          ) : (
            <CircleDashed size={14} aria-label="Unknown" className="mt-px shrink-0 text-slate-400" />
          )}
          <div className="min-w-0">
            <span className="font-medium text-slate-800 dark:text-slate-200">{c.type}</span>
            {c.reason && <span className="ml-1.5 font-mono text-slate-500 dark:text-slate-400">{c.reason}</span>}
            {c.lastTransitionTime && (
              <span className="ml-1.5 text-slate-500 dark:text-slate-400">· {ageShort(c.lastTransitionTime)}</span>
            )}
            {c.message && <p className="mt-0.5 break-words text-slate-500 dark:text-slate-400">{c.message}</p>}
          </div>
        </li>
      ))}
    </ul>
  );
};

type KubeEvent = { type?: string; reason?: string; message?: string; count?: number; lastTimestamp?: string; eventTime?: string };

/** Events for one object, Warnings first then newest first; refetched when `version` changes. */
export const Events: React.FC<{ load: () => Promise<{ items: Array<Record<string, unknown>> }>; version: unknown }> = ({
  load,
  version,
}) => {
  const { t } = useTranslation();
  const [events, setEvents] = useState<KubeEvent[] | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let live = true;
    load()
      .then((r) => live && (setEvents(r.items as KubeEvent[]), setFailed(false)))
      .catch(() => live && setFailed(true));
    return () => {
      live = false;
    };
    // load is a new closure on every render; version says when to refetch.
  }, [version]);
  if (failed) return <Empty>{t('dashboard.detail.eventsFailed')}</Empty>;
  if (!events) return <Spinner size="sm" />;
  if (!events.length) return <Empty>{t('dashboard.detail.noEvents')}</Empty>;
  const when = (e: KubeEvent) => e.lastTimestamp ?? e.eventTime ?? '';
  const sorted = [...events].sort(
    (a, b) => Number(b.type === 'Warning') - Number(a.type === 'Warning') || when(b).localeCompare(when(a)),
  );
  return (
    <ul className="flex flex-col gap-1.5">
      {sorted.slice(0, 15).map((e, i) => (
        <li
          key={i}
          className={`rounded-md px-2.5 py-1.5 text-xs ${
            e.type === 'Warning'
              ? 'bg-amber-50 text-amber-900 dark:bg-amber-500/10 dark:text-amber-200'
              : 'bg-slate-50 text-slate-700 dark:bg-slate-800/60 dark:text-slate-300'
          }`}
        >
          <div className="flex items-center justify-between gap-2">
            <span className="font-semibold">{e.reason}</span>
            <span className="shrink-0 font-mono text-[10px]">
              {e.count && e.count > 1 ? `×${e.count} · ` : ''}
              {ageShort(when(e) || undefined)}
            </span>
          </div>
          {e.message && <p className="mt-0.5 break-words leading-relaxed">{e.message}</p>}
        </li>
      ))}
    </ul>
  );
};
