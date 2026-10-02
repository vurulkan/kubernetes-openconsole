import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { AlertTriangle } from 'lucide-react';
import { Badge, Spinner } from './ui';
import { getPodEvents } from '../services/api';

type Props = {
  namespace: string;
  podName: string;
};

type ParsedEvent = {
  reason: string;
  message: string;
  type: string;
  lastSeen?: string;
  count?: number;
};

/**
 * Status chip for pods that are NOT ready. Includes a triangle-exclamation
 * icon in the same amber tone, plus a hover popover that lazily fetches the
 * pod's Warning events and renders the latest reason + message. One fetch
 * per badge lifetime — subsequent hovers reuse the cached list.
 *
 * The popover is portaled to document.body with a viewport-anchored
 * position so it escapes card / table-row overflow and the sidebar's
 * stacking context.
 */
export const PodNotReadyBadge: React.FC<Props> = ({ namespace, podName }) => {
  const anchorRef = useRef<HTMLSpanElement | null>(null);
  const [open, setOpen] = useState(false);
  const [events, setEvents] = useState<ParsedEvent[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const hoverTimer = useRef<number | null>(null);

  const scheduleOpen = () => {
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

  return (
    <span
      ref={anchorRef}
      onMouseEnter={scheduleOpen}
      onMouseLeave={scheduleClose}
      className="relative inline-flex"
    >
      <Badge variant="warning">
        <AlertTriangle size={11} className="text-amber-600 dark:text-amber-300" />
        Not Ready
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
                Warning events
              </span>
              {loading && <Spinner size="sm" />}
            </div>
            {!loading && events && events.length === 0 && (
              <p className="text-slate-500 dark:text-slate-400">
                No warning events on this pod. The container may still be starting.
              </p>
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
                  <p className="text-[10px] text-slate-400 dark:text-slate-500">
                    +{events.length - 3} more warning event(s) — open Events for the full list.
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

export default PodNotReadyBadge;
