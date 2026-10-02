import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Activity, Pause, Play, Radio, Trash2, X } from 'lucide-react';
import { Button } from './ui';

export type LiveEvent = {
  verb: string;
  kind: string;
  namespace: string;
  name: string;
  at: string;
  reason?: string;
  message?: string;
  type?: string;
  involvedKind?: string;
  involvedName?: string;
};

type Props = {
  namespace: string | null;
  /** When false, panel renders only the floating toggle button. */
  open: boolean;
  onToggle: () => void;
  onClose: () => void;
};

const MAX_EVENTS = 200;

/**
 * Live tail of informer events for the active namespace. The panel keeps the
 * last 200 events; it never scrolls past that so a chatty cluster stays bounded
 * in memory. Pause stops appending without dropping the socket, so unpause
 * resumes with the live stream.
 */
const LiveEventsPanel: React.FC<Props> = ({ namespace, open, onToggle, onClose }) => {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState<'all' | 'events' | 'warnings'>('all');
  const pausedRef = useRef(paused);
  const socketRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  useEffect(() => {
    if (!open) {
      socketRef.current?.close();
      socketRef.current = null;
      setConnected(false);
      return;
    }
    const token = localStorage.getItem('authToken') ?? '';
    if (!token) return;
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const ns = namespace ?? '';
    const url = `${protocol}://${window.location.host}/ws/events?namespace=${encodeURIComponent(ns)}&token=${encodeURIComponent(token)}`;
    const ws = new WebSocket(url);
    socketRef.current = ws;
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onerror = () => setConnected(false);
    ws.onmessage = (msg) => {
      if (pausedRef.current) return;
      try {
        const ev = JSON.parse(msg.data) as LiveEvent;
        setEvents((prev) => {
          const next = [ev, ...prev];
          return next.length > MAX_EVENTS ? next.slice(0, MAX_EVENTS) : next;
        });
      } catch {
        /* ignore malformed */
      }
    };
    return () => {
      ws.close();
      socketRef.current = null;
      setConnected(false);
    };
  }, [open, namespace]);

  const visible = useMemo(() => {
    if (filter === 'all') return events;
    if (filter === 'events') return events.filter((e) => e.verb === 'event');
    return events.filter((e) => e.verb === 'event' && e.type === 'Warning');
  }, [events, filter]);

  if (!open) {
    return (
      <button
        type="button"
        onClick={onToggle}
        className="fixed bottom-6 right-6 z-30 flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2.5 text-xs font-medium text-slate-700 shadow-lg transition hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
        title="Open live events"
      >
        <Radio size={14} className="text-brand-500" />
        Live events
      </button>
    );
  }

  return (
    <aside
      className="fixed right-0 top-0 bottom-0 z-40 flex w-96 flex-col border-l border-slate-200 bg-white shadow-2xl dark:border-slate-800 dark:bg-slate-900"
      aria-label="Live events"
    >
      <header className="flex items-center justify-between border-b border-slate-200 px-4 py-3 dark:border-slate-800">
        <div className="flex items-center gap-2">
          <div className="relative flex h-6 w-6 items-center justify-center rounded-md bg-brand-50 text-brand-600 ring-1 ring-inset ring-brand-100 dark:bg-brand-500/15 dark:text-brand-300">
            <Activity size={14} />
            {connected && (
              <span className="absolute -right-0.5 -top-0.5 inline-block h-2 w-2 animate-pulse rounded-full bg-emerald-500 ring-2 ring-white dark:ring-slate-900" />
            )}
          </div>
          <div>
            <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">Live events</div>
            <div className="text-[11px] text-slate-500 dark:text-slate-400">
              {connected ? 'streaming' : 'disconnected'}
              {namespace ? ` · ns/${namespace}` : ' · all namespaces'}
            </div>
          </div>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="rounded-md p-1 text-slate-400 transition hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
          aria-label="Close"
        >
          <X size={16} />
        </button>
      </header>

      <div className="flex items-center justify-between gap-2 border-b border-slate-100 px-3 py-2 dark:border-slate-800/70">
        <div className="flex items-center gap-1 rounded-lg border border-slate-200 bg-white p-0.5 dark:border-slate-700 dark:bg-slate-800">
          {(['all', 'events', 'warnings'] as const).map((k) => (
            <button
              key={k}
              type="button"
              onClick={() => setFilter(k)}
              className={`rounded-md px-2 py-1 text-[11px] font-medium transition ${
                filter === k
                  ? 'bg-brand-50 text-brand-700 dark:bg-brand-500/15 dark:text-brand-200'
                  : 'text-slate-600 hover:bg-slate-50 dark:text-slate-300 dark:hover:bg-slate-700/60'
              }`}
            >
              {k === 'all' ? 'All' : k === 'events' ? 'K8s events' : 'Warnings'}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setPaused((v) => !v)}
            title={paused ? 'Resume' : 'Pause'}
            className="h-7 px-2"
          >
            {paused ? <Play size={12} /> : <Pause size={12} />}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setEvents([])}
            title="Clear"
            className="h-7 px-2"
          >
            <Trash2 size={12} />
          </Button>
        </div>
      </div>

      <ol className="scrollbar-thin flex-1 overflow-y-auto px-2 py-2">
        {visible.length === 0 && (
          <li className="px-3 py-10 text-center text-xs text-slate-400 dark:text-slate-500">
            {connected ? 'Waiting for events…' : 'Connecting…'}
          </li>
        )}
        {visible.map((e, idx) => (
          <li
            key={`${e.at}-${e.kind}-${e.name}-${idx}`}
            className="group mb-1 rounded-md border border-transparent px-2 py-1.5 transition hover:border-slate-200 hover:bg-slate-50 dark:hover:border-slate-700 dark:hover:bg-slate-800/60"
          >
            <div className="flex items-start justify-between gap-2">
              <div className="flex min-w-0 items-center gap-1.5">
                <VerbBadge verb={e.verb} type={e.type} />
                <span className="truncate text-[11px] font-medium text-slate-900 dark:text-slate-100">
                  {e.verb === 'event' ? e.reason || e.kind : e.kind}
                </span>
              </div>
              <time className="shrink-0 text-[10px] tabular-nums text-slate-400 dark:text-slate-500">
                {formatTime(e.at)}
              </time>
            </div>
            <div className="mt-0.5 truncate text-[11px] text-slate-600 dark:text-slate-300">
              {e.verb === 'event' && e.involvedKind
                ? `${e.involvedKind}/${e.involvedName}`
                : `${e.namespace ? e.namespace + '/' : ''}${e.name}`}
            </div>
            {e.message && (
              <div
                className="mt-0.5 line-clamp-2 text-[11px] text-slate-500 dark:text-slate-400"
                title={e.message}
              >
                {e.message}
              </div>
            )}
          </li>
        ))}
      </ol>
    </aside>
  );
};

const VerbBadge: React.FC<{ verb: string; type?: string }> = ({ verb, type }) => {
  const palette = (() => {
    if (verb === 'event') {
      if (type === 'Warning') return 'bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300';
      return 'bg-sky-100 text-sky-800 dark:bg-sky-500/15 dark:text-sky-300';
    }
    if (verb === 'added') return 'bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-300';
    if (verb === 'deleted') return 'bg-rose-100 text-rose-800 dark:bg-rose-500/15 dark:text-rose-300';
    return 'bg-slate-100 text-slate-700 dark:bg-slate-700/50 dark:text-slate-300';
  })();
  const label = verb === 'event' ? (type || 'event').toLowerCase() : verb;
  return (
    <span className={`inline-flex min-w-10 justify-center rounded px-1 py-px font-mono text-[9px] font-semibold uppercase tracking-wide ${palette}`}>
      {label}
    </span>
  );
};

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    const h = String(d.getHours()).padStart(2, '0');
    const m = String(d.getMinutes()).padStart(2, '0');
    const s = String(d.getSeconds()).padStart(2, '0');
    return `${h}:${m}:${s}`;
  } catch {
    return '';
  }
}

export default LiveEventsPanel;
