import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ChevronDown,
  ChevronUp,
  Copy,
  Download,
  History,
  Pause,
  Play,
  RefreshCw,
  Search,
  WrapText,
} from 'lucide-react';
import { Button, Modal, NativeSelect } from './ui';
import { openLogStream, type LogFrame, type LogStatus } from '../utils/logStream';
import { mainContainer } from '../utils/podStatus';

export type LogTarget = {
  kind: 'pods' | 'deployments' | 'jobs';
  name: string;
  /** Pods: open on this container's instance before the last restart. */
  previous?: string;
};

type PodSpecLike = Parameters<typeof mainContainer>[0] & {
  spec?: { containers?: Array<{ name: string }>; initContainers?: Array<{ name: string }> };
};

type Line = { id: number; p?: string; c?: string; text: string };

export const MAX_LINES = 10000;
// Trim in chunks: a splice of the whole buffer per line would cost more than the line.
const TRIM_CHUNK = 500;
const ROW = 20; // px, text-xs leading-5
const OVERSCAN = 30;
const POD_COLORS = ['text-sky-300', 'text-violet-300', 'text-amber-300', 'text-emerald-300', 'text-pink-300', 'text-cyan-300'];

const podColor = (pod = '') => {
  let h = 0;
  for (let i = 0; i < pod.length; i++) h = (h * 31 + pod.charCodeAt(i)) | 0;
  return POD_COLORS[Math.abs(h) % POD_COLORS.length];
};


function highlight(text: string, q: string): React.ReactNode {
  if (!q) return text;
  const lower = text.toLowerCase();
  const out: React.ReactNode[] = [];
  let i = 0;
  for (let j = lower.indexOf(q); j >= 0; j = lower.indexOf(q, i)) {
    out.push(text.slice(i, j), <mark key={j} className="rounded-sm bg-amber-300 text-slate-950">{text.slice(j, j + q.length)}</mark>);
    i = j + q.length;
  }
  out.push(text.slice(i));
  return out;
}

const LogRow = React.memo(function LogRow({
  line, q, current, multi, wrap,
}: { line: Line; q: string; current: boolean; multi: boolean; wrap: boolean }) {
  return (
    <div
      data-line={line.id}
      className={`px-4 ${wrap ? 'min-h-5 whitespace-pre-wrap break-all [contain-intrinsic-size:auto_20px] [content-visibility:auto]' : 'h-5 whitespace-pre'} ${current ? 'bg-amber-400/20' : ''}`}
    >
      {multi && <span className={podColor(line.p)}>[{line.p}/{line.c}] </span>}
      {highlight(line.text, q)}
    </div>
  );
});

const lineText = (l: Line, multi: boolean) => (multi ? `[${l.p}/${l.c}] ${l.text}` : l.text);

type Props = { namespace: string; target: LogTarget; pod?: PodSpecLike; onClose: () => void };

/** Pod, deployment and job logs. Mounted fresh per target, so a stream never opens with the last target's settings. */
export const LogViewer: React.FC<Omit<Props, 'target'> & { target: LogTarget | null }> = ({ target, ...rest }) =>
  target ? <LogViewerBody key={`${target.kind}/${target.name}/${target.previous ?? ''}`} target={target} {...rest} /> : null;

const LogViewerBody: React.FC<Props> = ({ namespace, target, pod, onClose }) => {
  const { t } = useTranslation();
  const [container, setContainer] = useState(() => target.previous ?? mainContainer(pod ?? {}));
  const [mode, setMode] = useState<'live' | 'previous'>(target.previous ? 'previous' : 'live');
  const [status, setStatus] = useState<LogStatus>({ state: 'connecting' });
  const [streamError, setStreamError] = useState<LogFrame | null>(null);
  const [paused, setPaused] = useState(false);
  const [wrap, setWrap] = useState(false);
  const [query, setQuery] = useState('');
  const [matchPos, setMatchPos] = useState(0);
  const [copied, setCopied] = useState(false);
  const [reconnectKey, setReconnectKey] = useState(0);
  const [version, setVersion] = useState(0);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewHeight, setViewHeight] = useState(600);

  const linesRef = useRef<Line[]>([]);
  const droppedRef = useRef(0);
  const nextId = useRef(0);
  const frameRef = useRef(0);
  const firstOpen = useRef(true);
  const pausedRef = useRef(false);
  const atBottomRef = useRef(true);
  const renderedDropRef = useRef(0);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const searchRef = useRef<HTMLInputElement | null>(null);

  const multi = target.kind !== 'pods';
  const containers = useMemo(
    () => [
      ...(pod?.spec?.initContainers ?? []).map((c) => ({ name: c.name, init: true })),
      ...(pod?.spec?.containers ?? []).map((c) => ({ name: c.name, init: false })),
    ],
    [pod],
  );

  useEffect(() => {
    pausedRef.current = paused;
    if (!paused) setVersion((v) => v + 1);
  }, [paused]);

  useEffect(() => {
    linesRef.current = [];
    droppedRef.current = 0;
    renderedDropRef.current = 0;
    atBottomRef.current = true;
    setStreamError(null);
    setVersion((v) => v + 1);
    const params: Record<string, string> = { tail: '100' };
    if (target.kind === 'pods') {
      if (container) params.container = container;
      if (mode === 'previous') params.previous = 'true';
    }
    let stop = () => {};
    // Flipping container / instance quickly opens only the last choice.
    const timer = setTimeout(() => {
      stop = openLogStream({
        path: `/ws/namespaces/${namespace}/${target.kind}/${target.name}/logs`,
        params,
        live: mode === 'live',
        onStatus: setStatus,
        onStreamError: setStreamError,
        onLine: (f) => {
          const lines = linesRef.current;
          lines.push({ id: nextId.current++, p: f.p, c: f.c, text: f.text ?? '' });
          if (lines.length >= MAX_LINES + TRIM_CHUNK) {
            const n = lines.length - MAX_LINES;
            lines.splice(0, n);
            droppedRef.current += n;
          }
          // Paused: keep buffering, don't render.
          if (pausedRef.current || frameRef.current) return;
          frameRef.current = requestAnimationFrame(() => {
            frameRef.current = 0;
            setVersion((v) => v + 1);
          });
        },
      });
    }, firstOpen.current ? 0 : 250);
    firstOpen.current = false;
    return () => {
      clearTimeout(timer);
      stop();
      cancelAnimationFrame(frameRef.current);
      frameRef.current = 0;
    };
  }, [target, namespace, container, mode, reconnectKey]);

  const q = query.trim().toLowerCase();
  const matches = useMemo(() => {
    if (!q) return [];
    const out: number[] = [];
    linesRef.current.forEach((l, i) => {
      if (l.text.toLowerCase().includes(q)) out.push(i);
    });
    return out;
  }, [q, version]); // version stands for the buffer contents
  const current = matches.length ? matches[Math.min(matchPos, matches.length - 1)] : -1;

  // Follow the tail while the user is at the bottom; keep the view still while they read above.
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const trimmed = droppedRef.current - renderedDropRef.current;
    renderedDropRef.current = droppedRef.current;
    if (atBottomRef.current) {
      el.scrollTop = el.scrollHeight;
    } else if (trimmed > 0 && !wrap) {
      el.scrollTop = Math.max(0, el.scrollTop - trimmed * ROW);
    }
    setScrollTop(el.scrollTop);
    setViewHeight(el.clientHeight || 600);
  }, [version, wrap]);

  const goToMatch = (pos: number) => {
    if (!matches.length) return;
    const next = (pos + matches.length) % matches.length;
    setMatchPos(next);
    atBottomRef.current = false;
    const el = scrollRef.current;
    const idx = matches[next];
    if (!el) return;
    if (wrap) {
      el.querySelector(`[data-line="${linesRef.current[idx].id}"]`)?.scrollIntoView({ block: 'center' });
    } else {
      el.scrollTop = Math.max(0, idx * ROW - el.clientHeight / 2);
    }
  };

  const allText = () => linesRef.current.map((l) => lineText(l, multi)).join('\n');
  const download = () => {
    const url = URL.createObjectURL(new Blob([allText() + '\n'], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `${target.name}${!multi && container ? `-${container}` : ''}${mode === 'previous' ? '-previous' : ''}.log`;
    a.click();
    URL.revokeObjectURL(url);
  };
  const copy = () => {
    void navigator.clipboard?.writeText(allText()).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  // p pause, w wrap, Ctrl/⌘+F our search (the browser's can't see virtualized lines).
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'f') {
        e.preventDefault();
        searchRef.current?.focus();
        searchRef.current?.select();
        return;
      }
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const tgt = e.target as HTMLElement | null;
      if (tgt && (tgt.tagName === 'INPUT' || tgt.tagName === 'TEXTAREA' || tgt.tagName === 'SELECT' || tgt.isContentEditable)) return;
      if (e.key === 'p' || e.key === 'P') {
        e.preventDefault();
        setPaused((v) => !v);
      } else if (e.key === 'w' || e.key === 'W') {
        e.preventDefault();
        setWrap((v) => !v);
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, []);

  const lines = linesRef.current;
  const start = wrap ? 0 : Math.max(0, Math.floor(scrollTop / ROW) - OVERSCAN);
  const end = wrap ? lines.length : Math.min(lines.length, Math.ceil((scrollTop + viewHeight) / ROW) + OVERSCAN);
  const live = mode === 'live';
  const titleKey = target.kind === 'pods' ? 'podLogs' : target.kind === 'deployments' ? 'deploymentLogs' : 'jobLogs';

  const tone =
    status.state === 'error' ? 'text-rose-600 dark:text-rose-400'
    : status.state === 'reconnecting' ? 'text-amber-700 dark:text-amber-400'
    : status.state === 'following' && live ? 'text-emerald-700 dark:text-emerald-400'
    : 'text-slate-600 dark:text-slate-300';
  const statusText = (() => {
    const reason = status.reason ?? '';
    switch (status.state) {
      case 'connecting':
        return t('logs.status.connecting');
      case 'following':
        return live ? t('logs.status.following') : t('logs.status.reading');
      case 'reconnecting':
        return t(`logs.waiting.${reason}`, { defaultValue: t('logs.waiting.interrupted') });
      case 'ended':
        return t(`logs.ended.${reason}`, { defaultValue: t('logs.ended.container_terminated') });
      default:
        return t(`logs.error.${reason}`, { defaultValue: t('logs.error.unavailable') });
    }
  })();
  const restartTime = status.restartedAt
    ? new Date(status.restartedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : '';

  return (
    <Modal open onClose={onClose} title={t(`dashboard.modalTitles.${titleKey}`, { name: target.name })}>
      <div className="flex h-full flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 dark:border-slate-800 dark:bg-slate-900">
          {!multi && containers.length > 1 && (
            <div className="w-48">
              <NativeSelect aria-label={t('logs.container')} value={container} onChange={(e) => setContainer(e.target.value)} className="!py-1.5 text-xs">
                {containers.map((c) => (
                  <option key={c.name} value={c.name}>
                    {c.init ? `${c.name} (init)` : c.name}
                  </option>
                ))}
              </NativeSelect>
            </div>
          )}
          {!multi && (
            <div role="group" aria-label={t('logs.instance')} className="inline-flex rounded-lg border border-slate-300 bg-white p-0.5 dark:border-slate-700 dark:bg-slate-950">
              {(['live', 'previous'] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  aria-pressed={mode === m}
                  onClick={() => setMode(m)}
                  className={`cursor-pointer rounded-md px-2.5 py-1 text-xs font-medium transition-colors duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 ${
                    mode === m
                      ? 'bg-brand-600 text-white'
                      : 'text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800'
                  }`}
                >
                  {t(m === 'live' ? 'logs.live' : 'logs.previous')}
                </button>
              ))}
            </div>
          )}
          <div className="flex items-center gap-1 rounded-lg border border-slate-300 bg-white pl-2 dark:border-slate-700 dark:bg-slate-950">
            <Search size={14} className="text-slate-400" aria-hidden />
            <input
              ref={searchRef}
              type="search"
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setMatchPos(0);
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  goToMatch(matchPos + (e.shiftKey ? -1 : 1));
                }
              }}
              aria-label={t('logs.find')}
              placeholder={t('logs.find')}
              className="w-40 bg-transparent py-1.5 text-xs text-slate-900 placeholder:text-slate-500 focus:outline-none dark:text-slate-100 dark:placeholder:text-slate-400"
            />
            {q && (
              <span className="text-[11px] tabular-nums text-slate-600 dark:text-slate-300" aria-live="polite">
                {matches.length ? `${Math.min(matchPos, matches.length - 1) + 1}/${matches.length}` : t('logs.noMatch')}
              </span>
            )}
            <button type="button" onClick={() => goToMatch(matchPos - 1)} disabled={!matches.length} aria-label={t('logs.prevMatch')} className="cursor-pointer rounded p-1 text-slate-500 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-40 dark:hover:text-slate-100">
              <ChevronUp size={14} />
            </button>
            <button type="button" onClick={() => goToMatch(matchPos + 1)} disabled={!matches.length} aria-label={t('logs.nextMatch')} className="cursor-pointer rounded p-1 text-slate-500 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-40 dark:hover:text-slate-100">
              <ChevronDown size={14} />
            </button>
          </div>
          <div className="ml-auto flex items-center gap-1.5">
            {/* Toggles look pressed while on. */}
            <Button variant={paused ? 'primary' : 'outline'} size="sm" onClick={() => setPaused((v) => !v)} aria-pressed={paused}>
              {paused ? <Play size={14} /> : <Pause size={14} />}
              {paused ? t('logs.resume') : t('logs.pause')}
            </Button>
            <Button variant={wrap ? 'primary' : 'outline'} size="sm" onClick={() => setWrap((v) => !v)} aria-pressed={wrap}>
              <WrapText size={14} />
              {t('logs.wrap')}
            </Button>
            <Button variant="outline" size="sm" onClick={copy}>
              <Copy size={14} />
              {copied ? t('logs.copied') : t('logs.copy')}
            </Button>
            <Button variant="outline" size="sm" onClick={download}>
              <Download size={14} />
              {t('logs.download')}
            </Button>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs" role="status">
          <span className={`inline-flex items-center gap-1.5 font-medium ${tone}`}>
            {status.state === 'following' && live && <span className="h-1.5 w-1.5 animate-live rounded-full bg-emerald-500" aria-hidden />}
            {statusText}
          </span>
          {status.msg && <span className="break-all font-mono text-[11px] text-slate-500 dark:text-slate-400">{status.msg}</span>}
          {live && status.restartedAt && status.state === 'following' && (
            <span className="inline-flex items-center gap-2 text-amber-700 dark:text-amber-400">
              {t('logs.restartedAt', { time: restartTime })}
              {!multi && (
                <button type="button" onClick={() => setMode('previous')} className="inline-flex cursor-pointer items-center gap-1 rounded text-brand-700 underline-offset-2 hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 dark:text-brand-300">
                  <History size={12} />
                  {t('logs.openPrevious')}
                </button>
              )}
            </span>
          )}
          {paused && <span className="text-slate-600 dark:text-slate-300">{t('logs.pausedNote')}</span>}
          {droppedRef.current > 0 && (
            <span className="text-slate-600 dark:text-slate-300">{t('logs.dropped', { count: droppedRef.current, max: MAX_LINES.toLocaleString() })}</span>
          )}
          {streamError && (
            <span className="text-amber-700 dark:text-amber-400">
              {streamError.p}/{streamError.c}: {t(`logs.error.${streamError.reason}`, { defaultValue: t('logs.error.unavailable') })}
            </span>
          )}
          {(status.state === 'ended' || status.state === 'error') && (
            <Button variant="outline" size="sm" onClick={() => setReconnectKey((k) => k + 1)}>
              <RefreshCw size={14} />
              {t('logs.reconnect')}
            </Button>
          )}
        </div>

        <div
          ref={scrollRef}
          role="log"
          aria-label={t('logs.output')}
          tabIndex={0}
          onScroll={(e) => {
            const el = e.currentTarget;
            atBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < ROW * 2;
            setScrollTop(el.scrollTop);
            setViewHeight(el.clientHeight);
          }}
          className="min-h-0 flex-1 overflow-auto rounded-lg border border-slate-800 bg-slate-950 py-2 font-mono text-xs leading-5 text-slate-100 shadow-inner focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60"
        >
          {lines.length === 0 ? (
            <div className="px-4 text-slate-400">{status.state === 'connecting' || status.state === 'following' ? t('logs.empty') : ''}</div>
          ) : (
            <>
              <div style={{ height: start * ROW }} />
              {lines.slice(start, end).map((l, i) => (
                <LogRow key={l.id} line={l} q={q} current={start + i === current} multi={multi} wrap={wrap} />
              ))}
              <div style={{ height: (lines.length - end) * ROW }} />
            </>
          )}
        </div>
      </div>
    </Modal>
  );
};
