import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import 'xterm/css/xterm.css';
import { RefreshCw, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Button, NativeSelect, Spinner } from './ui';
import { useTheme } from './ThemeProvider';

type Props = {
  open: boolean;
  onClose: () => void;
  namespace: string;
  pod: string;
  containers?: string[];
};

const SHELLS: Array<{ value: string; label: string }> = [
  { value: 'auto', label: 'Auto (bash → ash → sh)' },
  { value: '/bin/bash', label: '/bin/bash' },
  { value: '/bin/ash', label: '/bin/ash' },
  { value: '/bin/sh', label: '/bin/sh' },
];

const lightTheme = {
  background: '#0f172a',
  foreground: '#e2e8f0',
  cursor: '#a5b4fc',
  selectionBackground: 'rgba(99,102,241,0.35)',
};
const darkTheme = {
  background: '#050810',
  foreground: '#e2e8f0',
  cursor: '#a5b4fc',
  selectionBackground: 'rgba(99,102,241,0.35)',
};

const PodExecModal: React.FC<Props> = ({ open, onClose, namespace, pod, containers = [] }) => {
  const { t } = useTranslation();
  const terminalRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const containerSetRef = useRef<string>('');

  const [status, setStatus] = useState<'idle' | 'connecting' | 'open' | 'closed' | 'error'>('idle');
  const [container, setContainer] = useState<string>(containers[0] ?? '');
  const [shell, setShell] = useState<string>('auto');
  const [note, setNote] = useState<string | null>(null);
  const { effective } = useTheme();

  const theme = effective === 'dark' ? darkTheme : lightTheme;

  const connect = useCallback(() => {
    if (!terminalRef.current) return;
    if (socketRef.current) {
      socketRef.current.close();
      socketRef.current = null;
    }
    setNote(null);
    setStatus('connecting');

    if (!termRef.current) {
      const term = new Terminal({
        fontFamily: '"Fira Code", ui-monospace, SFMono-Regular, Menlo, monospace',
        fontSize: 13,
        cursorBlink: true,
        theme,
        cols: 80,
        rows: 24,
      });
      const fit = new FitAddon();
      term.loadAddon(fit);
      term.open(terminalRef.current);
      // Fit after a paint tick so the container has reflown to its final size.
      // Calling fit() synchronously after open() often computes 0×0 and bash
      // then prints nothing because its PTY has no visible rows.
      requestAnimationFrame(() => {
        try { fit.fit(); } catch (err) { /* ignore */ }
      });
      termRef.current = term;
      fitRef.current = fit;
    } else {
      termRef.current.options.theme = theme;
      termRef.current.clear();
      requestAnimationFrame(() => {
        try { fitRef.current?.fit(); } catch (err) { /* ignore */ }
      });
    }

    const token = localStorage.getItem('authToken') ?? '';
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const params = new URLSearchParams();
    if (container) params.set('container', container);
    if (shell) params.set('command', shell);
    params.set('token', token);
    const url = `${protocol}://${window.location.host}/ws/namespaces/${namespace}/pods/${pod}/exec?${params.toString()}`;
    const socket = new WebSocket(url);
    socket.binaryType = 'arraybuffer';
    socketRef.current = socket;
    containerSetRef.current = container;

    socket.onopen = () => {
      setStatus('open');
      // Give xterm one paint cycle so term.cols / term.rows are real values
      // when we send the first SIGWINCH; otherwise bash sees a 0×0 TTY and
      // prints nothing (the "Connected but blank" bug).
      requestAnimationFrame(() => {
        try { fitRef.current?.fit(); } catch (err) { /* ignore */ }
        sendResize();
        // Nudge the shell to redraw its prompt on connect. Many shells only
        // print their first prompt on stdin activity after a terminal resize.
        termRef.current?.focus();
        if (socket.readyState === WebSocket.OPEN) {
          socket.send(new TextEncoder().encode('\n'));
        }
      });
    };

    socket.onmessage = (event) => {
      const term = termRef.current;
      if (!term) return;
      if (event.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(event.data));
      } else if (typeof event.data === 'string') {
        try {
          const parsed = JSON.parse(event.data);
          if (parsed?.type === 'error' && typeof parsed.message === 'string') {
            term.writeln(`\x1b[31m${parsed.message}\x1b[0m`);
            return;
          }
        } catch (err) {
          /* fall through */
        }
        term.write(event.data);
      }
    };

    socket.onerror = () => {
      setStatus('error');
      setNote('Connection error.');
    };

    socket.onclose = (event) => {
      setStatus('closed');
      if (event.code !== 1000) {
        setNote(`Session closed (${event.code}).`);
      }
    };
  }, [namespace, pod, container, shell, theme]);

  const sendResize = useCallback(() => {
    const socket = socketRef.current;
    const term = termRef.current;
    if (!socket || !term) return;
    if (socket.readyState !== WebSocket.OPEN) return;
    // Fall back to a sane terminal size when xterm hasn't computed one yet.
    // A 0×0 PTY makes shells like bash emit nothing until a valid SIGWINCH
    // arrives, which was the "Connected but blank" symptom.
    const cols = Math.max(term.cols || 0, 80);
    const rows = Math.max(term.rows || 0, 24);
    socket.send(JSON.stringify({ type: 'resize', cols, rows }));
  }, []);

  // ESC closes
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, onClose]);

  // Open: initialize + connect. We wait two animation frames so the modal
  // DOM is painted and the terminal container has a non-zero size before
  // xterm reads it — otherwise fit() computes 0×0 cols/rows and the terminal
  // appears as a solid dark background with no visible cursor.
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    const run = () => {
      if (cancelled) return;
      if (!terminalRef.current || terminalRef.current.clientHeight === 0) {
        requestAnimationFrame(run);
        return;
      }
      connect();
    };
    const raf = requestAnimationFrame(() => requestAnimationFrame(run));
    return () => {
      cancelled = true;
      cancelAnimationFrame(raf);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  // When container/shell changes while modal is open, reconnect
  useEffect(() => {
    if (!open || status === 'idle') return;
    if (containerSetRef.current === container) return;
    connect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [container]);

  // Wire xterm data → WS
  useEffect(() => {
    const term = termRef.current;
    if (!term) return;
    const sub = term.onData((data) => {
      const socket = socketRef.current;
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(new TextEncoder().encode(data));
      }
    });
    const resizeSub = term.onResize(() => sendResize());
    return () => {
      sub.dispose();
      resizeSub.dispose();
    };
  }, [sendResize, status]);

  // ResizeObserver to refit on container size change
  useEffect(() => {
    if (!open || !terminalRef.current) return;
    const observer = new ResizeObserver(() => {
      try {
        fitRef.current?.fit();
      } catch (err) {
        /* ignore */
      }
    });
    observer.observe(terminalRef.current);
    return () => observer.disconnect();
  }, [open]);

  // Cleanup on close
  useEffect(() => {
    if (open) return;
    socketRef.current?.close();
    socketRef.current = null;
    termRef.current?.dispose();
    termRef.current = null;
    fitRef.current = null;
    setStatus('idle');
    setNote(null);
  }, [open]);

  // IMPORTANT: this useMemo must stay above the `if (!open) return null`
  // early return. React requires the same hook count every render and will
  // crash with "Rendered more hooks than during the previous render"
  // (error #310) otherwise.
  const statusLabel = useMemo(() => {
    switch (status) {
      case 'open':
        return (
          <span className="inline-flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-300">
            <span className="h-1.5 w-1.5 animate-live rounded-full bg-emerald-500" />
            Connected
          </span>
        );
      case 'connecting':
        return (
          <span className="inline-flex items-center gap-1.5 text-xs text-brand-600 dark:text-brand-300">
            <Spinner size="sm" /> Connecting…
          </span>
        );
      case 'error':
        return <span className="text-xs text-rose-600 dark:text-rose-300">{t('common.error')}</span>;
      case 'closed':
        return <span className="text-xs text-slate-500 dark:text-slate-400">{t('common.closed')}</span>;
      default:
        return <span className="text-xs text-slate-500 dark:text-slate-400">{t('common.idle')}</span>;
    }
  }, [status, t]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex animate-fade-in items-center justify-center p-4">
      <div
        className="absolute inset-0 bg-slate-900/60 backdrop-blur-sm"
        onClick={status === 'open' ? undefined : onClose}
      />
      <div
        className="relative z-10 flex animate-slide-up flex-col overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-elevated dark:border-slate-800 dark:bg-slate-950"
        style={{ width: '95vw', height: '90vh' }}
      >
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 bg-slate-50/60 px-5 py-3 dark:border-slate-800 dark:bg-slate-900/60">
          <div className="flex min-w-0 items-center gap-2">
            <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Shell · {pod}
            </span>
            <span className="truncate font-mono text-[11px] text-slate-500 dark:text-slate-400">
              {namespace}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {containers.length > 1 && (
              <NativeSelect
                value={container}
                onChange={(e) => setContainer(e.target.value)}
                className="h-8 py-1 text-xs"
              >
                {containers.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </NativeSelect>
            )}
            <NativeSelect
              value={shell}
              onChange={(e) => setShell(e.target.value)}
              className="h-8 py-1 text-xs"
            >
              {SHELLS.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </NativeSelect>
            {statusLabel}
            <Button
              variant="outline"
              size="sm"
              onClick={() => connect()}
              disabled={status === 'connecting'}
            >
              <RefreshCw size={13} />
              Reconnect
            </Button>
            <button
              onClick={onClose}
              className="rounded-lg p-1.5 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-100"
              aria-label="Close"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 bg-amber-50 px-5 py-2 text-[11px] text-amber-800 dark:border-slate-800 dark:bg-amber-500/10 dark:text-amber-200">
          Audit active: session start, end, outcome and duration are recorded
          (keystrokes and output are not). Idle sessions close after 5 minutes.
          {note && (
            <span className="ml-auto font-medium text-rose-600 dark:text-rose-300">{note}</span>
          )}
        </div>

        <div
          ref={terminalRef}
          className="flex-1 overflow-hidden bg-slate-950 p-2"
          style={{ minHeight: 0 }}
        />
      </div>
    </div>
  );
};

export default PodExecModal;
