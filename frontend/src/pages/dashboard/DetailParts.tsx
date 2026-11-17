// Building blocks shared by the pod and deployment detail drawers.
import React, { useEffect, useRef, useState } from 'react';
import { CheckCircle2, CircleDashed, XCircle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Spinner } from '../../components/ui';
import { ageShort } from '../../utils/age';
import { type KubeEvent, type LiveTarget, upsertEvent, useObjectEventStream } from './useObjectEvents';


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
            <CircleDashed size={14} aria-label={t('common.statusUnknown')} className="mt-px shrink-0 text-slate-400" />
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

/**
 * Events for one object, Warnings first then newest first; read again when `version` changes.
 * With `live` the list also follows the object's events as they happen (the namespace's
 * /ws/events stream), shows "Live", and reads the list again after a dropped socket reconnects.
 */
export const Events: React.FC<{
  load: () => Promise<{ items: Array<Record<string, unknown>> }>;
  version: unknown;
  live?: LiveTarget;
}> = ({ load, version, live }) => {
  const { t } = useTranslation();
  const [events, setEvents] = useState<KubeEvent[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [resync, setResync] = useState(0);
  // Names of events that just came in, highlighted for a moment, and the last one announced.
  const [fresh, setFresh] = useState<string[]>([]);
  const [announce, setAnnounce] = useState('');
  // load is a new closure on every render; version (and a resync) says when to read again.
  const loadRef = useRef(load);
  loadRef.current = load;
  useEffect(() => {
    let current = true;
    loadRef.current()
      .then((r) => current && (setEvents((r.items ?? []) as KubeEvent[]), setFailed(false)))
      .catch(() => current && setFailed(true));
    return () => {
      current = false;
    };
  }, [version, resync]);
  const stream = useObjectEventStream(
    live ?? null,
    (e) => {
      setEvents((prev) => upsertEvent(prev ?? [], e));
      setAnnounce(t('dashboard.detail.eventsNew', { reason: e.reason ?? '' }));
      const name = e.metadata?.name;
      if (!name) return;
      setFresh((f) => [...f.filter((x) => x !== name), name]);
      setTimeout(() => setFresh((f) => f.filter((x) => x !== name)), 3000);
    },
    () => setResync((n) => n + 1),
  );

  const indicator =
    stream === 'off' ? null : (
      <div className="flex items-center gap-1.5 text-[10px] font-medium text-slate-500 dark:text-slate-400">
        <span
          aria-hidden="true"
          className={`h-1.5 w-1.5 rounded-full ${stream === 'live' ? 'bg-emerald-500' : 'bg-slate-400 dark:bg-slate-500'}`}
        />
        {stream === 'live' ? t('dashboard.detail.eventsLive') : t('dashboard.detail.eventsReconnecting')}
      </div>
    );
  const announcer = live ? (
    <p className="sr-only" aria-live="polite">
      {announce}
    </p>
  ) : null;
  const wrap = (body: React.ReactNode) => (
    <div className="flex flex-col gap-1.5">
      {indicator}
      {body}
      {announcer}
    </div>
  );

  if (failed) return wrap(<Empty>{t('dashboard.detail.eventsFailed')}</Empty>);
  if (!events) return wrap(<Spinner size="sm" />);
  if (!events.length) return wrap(<Empty>{t('dashboard.detail.noEvents')}</Empty>);
  const when = (e: KubeEvent) => e.lastTimestamp ?? e.eventTime ?? '';
  const sorted = [...events].sort(
    (a, b) => Number(b.type === 'Warning') - Number(a.type === 'Warning') || when(b).localeCompare(when(a)),
  );
  return wrap(
    <ul className="flex flex-col gap-1.5">
      {sorted.slice(0, 15).map((e, i) => (
        <li
          key={e.metadata?.name ?? i}
          className={`rounded-md px-2.5 py-1.5 text-xs transition-shadow ${
            e.type === 'Warning'
              ? 'bg-amber-50 text-amber-900 dark:bg-amber-500/10 dark:text-amber-200'
              : 'bg-slate-50 text-slate-700 dark:bg-slate-800/60 dark:text-slate-300'
          } ${e.metadata?.name && fresh.includes(e.metadata.name) ? 'ring-2 ring-brand-400/70' : ''}`}
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
    </ul>,
  );
};
