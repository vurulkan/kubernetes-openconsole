import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { AlertTriangle, XCircle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Badge, Spinner } from './ui';
import { getPodEvents } from '../services/api';
import { ageShort } from '../utils/age';
import { exitCodeHint, exitLabel, type ContainerInfo, type ContainerLook, type PodStatus, type Tone } from '../utils/podStatus';

type Props = {
  namespace: string;
  podName: string;
  status: PodStatus;
};

type ParsedEvent = {
  reason: string;
  message: string;
  type: string;
  lastSeen?: string;
  count?: number;
};

const BADGE_VARIANT: Record<Tone, 'success' | 'warning' | 'error' | 'default'> = {
  ok: 'success',
  warn: 'warning',
  error: 'error',
  idle: 'default',
};

/** Status-dot class for the card header, by tone. */
export const STATUS_DOT: Record<Tone, string> = {
  ok: 'status-dot status-dot-success',
  warn: 'status-dot status-dot-warning',
  error: 'status-dot status-dot-error',
  idle: 'status-dot status-dot-idle',
};

/**
 * Pod status chip with kubectl's STATUS text (CrashLoopBackOff, OOMKilled,
 * Init:0/2 …). For unhealthy pods a hover popover lazily fetches the pod's
 * Warning events and shows the latest reason + message. One fetch per badge
 * lifetime — subsequent hovers reuse the cached list.
 *
 * The popover is portaled to document.body with a viewport-anchored
 * position so it escapes card / table-row overflow and the sidebar's
 * stacking context.
 */
export const PodStatusBadge: React.FC<Props> = ({ namespace, podName, status }) => {
  const { t } = useTranslation();
  const anchorRef = useRef<HTMLSpanElement | null>(null);
  const [open, setOpen] = useState(false);
  const [events, setEvents] = useState<ParsedEvent[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const hoverTimer = useRef<number | null>(null);
  const unhealthy = status.tone === 'warn' || status.tone === 'error';

  const scheduleOpen = () => {
    if (!unhealthy) return;
    if (hoverTimer.current !== null) window.clearTimeout(hoverTimer.current);
    hoverTimer.current = window.setTimeout(() => setOpen(true), 120);
  };
  const scheduleClose = () => {
    if (hoverTimer.current !== null) window.clearTimeout(hoverTimer.current);
    hoverTimer.current = window.setTimeout(() => setOpen(false), 120);
  };

  useEffect(() => {
    if (!open) return;
    if (events !== null) return;
    setLoading(true);
    getPodEvents(namespace, podName)
      .then((r) => {
        const raw = (r.items ?? []) as Array<Record<string, unknown>>;
        const parsed: ParsedEvent[] = raw
          .map((e) => ({
            reason: ((e.reason as string) ?? '').toString(),
            message: ((e.message as string) ?? '').toString().trim(),
            type: ((e.type as string) ?? '').toString(),
            lastSeen:
              (e.lastTimestamp as string) ??
              (e.eventTime as string) ??
              undefined,
            count: typeof e.count === 'number' ? (e.count as number) : undefined,
          }))
          .filter((e) => e.type === 'Warning' && e.message);
        parsed.sort((a, b) => {
          const ta = a.lastSeen ? Date.parse(a.lastSeen) : 0;
          const tb = b.lastSeen ? Date.parse(b.lastSeen) : 0;
          return tb - ta;
        });
        setEvents(parsed);
      })
      .catch(() => setEvents([]))
      .finally(() => setLoading(false));
  }, [open, events, namespace, podName]);

  useLayoutEffect(() => {
    if (!open || !anchorRef.current) return;
    const update = () => {
      const rect = anchorRef.current!.getBoundingClientRect();
      setPos({ top: rect.bottom + 6, left: Math.max(8, rect.right - 360) });
    };
    update();
    window.addEventListener('resize', update);
    window.addEventListener('scroll', update, true);
    return () => {
      window.removeEventListener('resize', update);
      window.removeEventListener('scroll', update, true);
    };
  }, [open]);

  // "Running" with containers not ready reads better as "Not ready 1/2".
  const text =
    status.label === 'Running'
      ? status.tone === 'ok'
        ? t('dashboard.status.running')
        : t('dashboard.status.notReady', { ready: status.ready, total: status.total })
      : status.label;

  return (
    <span
      ref={anchorRef}
      onMouseEnter={scheduleOpen}
      onMouseLeave={scheduleClose}
      className="relative inline-flex"
    >
      <Badge variant={BADGE_VARIANT[status.tone]}>
        {status.tone === 'ok' && <span className="h-1.5 w-1.5 animate-live rounded-full bg-emerald-500" />}
        {status.tone === 'warn' && <AlertTriangle size={11} aria-hidden className="text-amber-700 dark:text-amber-300" />}
        {status.tone === 'error' && <XCircle size={11} aria-hidden className="text-rose-600 dark:text-rose-300" />}
        {text}
      </Badge>

      {open && pos &&
        createPortal(
          <div
            onMouseEnter={scheduleOpen}
            onMouseLeave={scheduleClose}
            style={{ top: pos.top, left: pos.left }}
            className="fixed z-[1000] w-[360px] animate-slide-up rounded-xl border border-slate-200 bg-white p-3 text-xs shadow-elevated dark:border-slate-800 dark:bg-slate-900"
          >
            <div className="mb-2 flex items-center justify-between">
              <span className="font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                {t('dashboard.podStatus.warningEvents')}
              </span>
              {loading && <Spinner size="sm" />}
            </div>
            {!loading && events && events.length === 0 && (
              <p className="text-slate-500 dark:text-slate-400">{t('dashboard.podStatus.noWarningEvents')}</p>
            )}
            {!loading && events && events.length > 0 && (
              <ul className="flex flex-col gap-2">
                {events.slice(0, 3).map((e, i) => (
                  <li
                    key={i}
                    className="rounded-md bg-amber-50 p-2 text-amber-900 dark:bg-amber-500/10 dark:text-amber-200"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold">{e.reason || 'Warning'}</span>
                      {e.count && e.count > 1 && (
                        <span className="rounded-full bg-amber-200/60 px-1.5 text-[10px] font-mono text-amber-900 dark:bg-amber-500/20 dark:text-amber-200">
                          ×{e.count}
                        </span>
                      )}
                    </div>
                    <p className="mt-0.5 break-words leading-relaxed">{e.message}</p>
                    {e.lastSeen && (
                      <p className="mt-1 font-mono text-[10px] text-amber-700/80 dark:text-amber-300/70">
                        {e.lastSeen}
                      </p>
                    )}
                  </li>
                ))}
                {events.length > 3 && (
                  <p className="text-[10px] text-slate-500 dark:text-slate-400">
                    {t('dashboard.podStatus.moreWarnings', { count: events.length - 3 })}
                  </p>
                )}
              </ul>
            )}
          </div>,
          document.body
        )}
    </span>
  );
};

/**
 * Restart count. When a container has restarted, hovering it lists every
 * restarted container's last exit code with a plain-language explanation.
 */
export const PodRestarts: React.FC<{ status: PodStatus }> = ({ status }) => {
  const { t } = useTranslation();
  const lines = status.containers
    .filter((c) => c.lastTermination)
    .map((c) => {
      const term = c.lastTermination!;
      const hint = exitCodeHint(term);
      return `${c.name}: ${t('dashboard.detail.lastExit')} ${exitLabel(term)}, ${t('dashboard.podStatus.ago', {
        age: ageShort(term.finishedAt),
      })} · ${t('dashboard.podStatus.restartsN', { count: c.restarts })}\n${t(hint.key, { signal: hint.signal })}`;
    });
  return (
    <span
      className={`whitespace-nowrap font-mono text-xs ${
        status.restarts > 0 ? 'text-amber-700 dark:text-amber-300' : 'text-slate-500 dark:text-slate-400'
      } ${lines.length ? 'cursor-help underline decoration-dotted underline-offset-2' : ''}`}
      title={lines.join('\n\n') || undefined}
    >
      {status.restarts}
    </span>
  );
};

const LOOK: Record<ContainerLook, string> = {
  ok: 'bg-emerald-500',
  restarted: 'bg-emerald-500 ring-1 ring-amber-400/50 ring-offset-2 ring-offset-white dark:ring-offset-slate-900',
  warn: 'bg-amber-400',
  error: 'bg-rose-500',
  done: 'border-2 border-slate-400 dark:border-slate-500',
  failed: 'border-2 border-rose-500',
};

/**
 * One small square per container (Lens style): filled = running or waiting, hollow = exited,
 * a ring = restarted. Hovering shows name, state, start time and restarts; the same text is
 * each square's aria-label. Not tab stops: the pod drawer lists the containers too.
 */
export const ContainerSquares: React.FC<{ containers: ContainerInfo[] }> = ({ containers }) => {
  const { t, i18n } = useTranslation();
  const [tip, setTip] = useState<{ i: number; top?: number; bottom?: number; left: number } | null>(null);
  const lines = (c: ContainerInfo) =>
    [
      c.kind === 'container' ? c.name : `${c.name} · ${t(`dashboard.containers.${c.kind}`)}`,
      c.state,
      c.startedAt &&
        t('dashboard.containers.startedAt', {
          time: new Date(c.startedAt).toLocaleString(i18n.language),
          ago: t('dashboard.podStatus.ago', { age: ageShort(c.startedAt) }),
        }),
      t('dashboard.podStatus.restartsN', { count: c.restarts }),
    ].filter((l): l is string => !!l);
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      {containers.map((c, i) => (
        <span
          key={c.name}
          role="img"
          aria-label={lines(c).join(', ')}
          onMouseEnter={(e) => {
            const r = e.currentTarget.getBoundingClientRect();
            const left = Math.max(8, Math.min(r.left - 8, window.innerWidth - 300));
            // Above the square when the bottom of the viewport is close.
            setTip(r.bottom + 110 < window.innerHeight ? { i, left, top: r.bottom + 6 } : { i, left, bottom: window.innerHeight - r.top + 6 });
          }}
          onMouseLeave={() => setTip(null)}
          className={`inline-block h-2.5 w-2.5 shrink-0 rounded-[2px] ${LOOK[c.look]}`}
        />
      ))}
      {tip &&
        containers[tip.i] &&
        createPortal(
          <div
            aria-hidden
            style={{ top: tip.top, bottom: tip.bottom, left: tip.left }}
            className="pointer-events-none fixed z-[1000] max-w-[292px] rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs text-slate-600 shadow-elevated dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300"
          >
            {lines(containers[tip.i]).map((l, n) => (
              <div key={n} className={n === 0 ? 'font-mono font-semibold text-slate-900 dark:text-slate-100' : n === 1 ? 'font-mono' : ''}>
                {l}
              </div>
            ))}
          </div>,
          document.body,
        )}
    </span>
  );
};

export default PodStatusBadge;
