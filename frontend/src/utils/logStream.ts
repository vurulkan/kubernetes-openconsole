import { wsUrl } from '../services/api';

// Frames the backend log sockets send (backend/internal/api/logs.go).
export type LogFrame = {
  t: 'line' | 'end' | 'error';
  ts?: string;
  p?: string;
  c?: string;
  text?: string;
  reason?: string;
  msg?: string;
  retry?: boolean;
};

export type LogStatus = {
  state: 'connecting' | 'following' | 'reconnecting' | 'ended' | 'error';
  reason?: string;
  /** The server's own words, e.g. the kubelet's "unable to retrieve container logs …". */
  msg?: string;
  /** When a followed container exited; set until the next restart. */
  restartedAt?: number;
};

export const MAX_BACKOFF_MS = 15000;

type Connect = (path: string, params: URLSearchParams) => Promise<WebSocket>;

const ticketConnect: Connect = async (path, params) => new WebSocket(await wsUrl(path, params));

/**
 * Opens a log socket and keeps it going: a live view that drops (network, proxy timeout,
 * container restart) reconnects with backoff from the last line's timestamp, so nothing is
 * lost or repeated. Only the current socket may report; a replaced one stays silent.
 * Returns the function that stops it.
 */
export function openLogStream(opts: {
  path: string;
  params: Record<string, string>;
  live: boolean;
  onLine: (f: LogFrame) => void;
  onStatus: (s: LogStatus) => void;
  /** One stream of a multi-pod view failed; the others go on. */
  onStreamError?: (f: LogFrame) => void;
  connect?: Connect;
}): () => void {
  const { path, params, live, onLine, onStatus, onStreamError, connect = ticketConnect } = opts;
  let socket: WebSocket | null = null;
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let attempt = 0;
  let lastTs = '';
  let sameTs = 0;
  let waitingRestart = false;
  let restartedAt: number | undefined;

  const retry = (reason?: string) => {
    onStatus({ state: 'reconnecting', reason, restartedAt });
    timer = setTimeout(open, Math.min(1000 * 2 ** attempt, MAX_BACKOFF_MS));
    attempt++;
  };

  const open = async () => {
    const q = new URLSearchParams(params);
    if (lastTs) {
      q.delete('tail');
      q.set('sinceTime', lastTs);
      q.set('skip', String(sameTs));
      q.set('resume', 'true');
    }
    let ws: WebSocket;
    try {
      ws = await connect(path, q);
    } catch {
      if (stopped) return;
      if (live) retry('unavailable');
      else onStatus({ state: 'error', reason: 'unavailable' });
      return;
    }
    if (stopped) {
      ws.close(1000);
      return;
    }
    socket = ws;
    let final = false;
    const mine = () => socket === ws && !stopped;
    ws.onopen = () => {
      if (mine() && !waitingRestart) onStatus({ state: 'following', restartedAt });
    };
    ws.onmessage = (event) => {
      if (!mine()) return;
      let f: LogFrame;
      try {
        f = JSON.parse(String(event.data));
      } catch {
        return;
      }
      if (f.t === 'line') {
        if (f.ts && f.ts > lastTs) {
          lastTs = f.ts;
          sameTs = 1;
        } else if (f.ts && f.ts === lastTs) {
          sameTs++;
        }
        if (attempt > 0 || waitingRestart) {
          attempt = 0;
          waitingRestart = false;
          onStatus({ state: 'following', restartedAt });
        }
        onLine(f);
      } else if (f.t === 'error' && f.p) {
        onStreamError?.(f);
      } else {
        final = true;
        // The server only asks for a retry where one helps (never after a previous instance's end).
        if (f.retry) {
          if (f.reason === 'container_terminated' && !waitingRestart) {
            waitingRestart = true;
            restartedAt = Date.now();
          }
          retry(f.reason);
        } else {
          onStatus({ state: f.t === 'end' ? 'ended' : 'error', reason: f.reason, ...(f.msg ? { msg: f.msg } : {}) });
        }
      }
    };
    ws.onclose = () => {
      if (!mine() || final) return;
      if (live) retry('interrupted');
      else onStatus({ state: 'error', reason: 'interrupted' });
    };
  };

  onStatus({ state: 'connecting' });
  void open();
  return () => {
    stopped = true;
    clearTimeout(timer);
    socket?.close(1000);
    socket = null;
  };
}
