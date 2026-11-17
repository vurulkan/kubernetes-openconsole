import { useEffect, useRef, useState } from 'react';
import { wsUrl } from '../../services/api';

/** A Kubernetes event as the detail views show it (REST items and live frames both fit). */
export type KubeEvent = {
  metadata?: { name?: string };
  type?: string;
  reason?: string;
  message?: string;
  count?: number;
  lastTimestamp?: string;
  eventTime?: string;
};

/** The object whose events are followed live: its namespace, Kind ("Pod", "Deployment", …) and name. */
export type LiveTarget = { namespace: string; kind: string; name: string };

/** A frame of /ws/events (see the OpenAPI description). */
type Frame = {
  verb: string;
  name: string;
  at: string;
  type?: string;
  reason?: string;
  message?: string;
  involvedKind?: string;
  involvedName?: string;
  count?: number;
};

const MAX_BACKOFF_MS = 30_000;

export type StreamState = 'off' | 'live' | 'reconnecting';

/**
 * Follows one object's events on the namespace's /ws/events stream (the one Live
 * events uses). `onEvent` gets each of the object's events as it happens;
 * `onResync` is called after a dropped socket reconnects, so the caller reads the
 * list again and fills the gap. `target` null = off.
 */
export function useObjectEventStream(
  target: LiveTarget | null,
  onEvent: (e: KubeEvent) => void,
  onResync: () => void,
): StreamState {
  const [state, setState] = useState<StreamState>('off');
  const handlers = useRef({ onEvent, onResync });
  handlers.current = { onEvent, onResync };
  const namespace = target?.namespace;
  const kind = target?.kind;
  const name = target?.name;

  useEffect(() => {
    if (!namespace || !kind || !name) {
      setState('off');
      return;
    }
    let ws: WebSocket | null = null;
    let cancelled = false;
    let attempt = 0;
    let opened = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const retry = () => {
      if (cancelled) return;
      setState('reconnecting');
      timer = setTimeout(connect, Math.min(1000 * 2 ** attempt, MAX_BACKOFF_MS));
      attempt++;
    };
    const connect = () => {
      void wsUrl('/ws/events', new URLSearchParams({ namespace }), true)
        .then((url) => {
          if (cancelled) return;
          const socket = new WebSocket(url);
          ws = socket;
          socket.onopen = () => {
            attempt = 0;
            setState('live');
            if (opened) handlers.current.onResync(); // events may have come while it was down
            opened = true;
          };
          socket.onclose = () => {
            if (socket === ws) retry();
          };
          socket.onmessage = (msg) => {
            let f: Frame;
            try {
              f = JSON.parse(msg.data) as Frame;
            } catch {
              return;
            }
            if (f.verb !== 'event' || f.involvedKind !== kind || f.involvedName !== name) return;
            handlers.current.onEvent({
              metadata: { name: f.name },
              type: f.type,
              reason: f.reason,
              message: f.message,
              count: f.count,
              lastTimestamp: f.at,
            });
          };
        })
        .catch(retry);
    };
    connect();
    return () => {
      cancelled = true;
      clearTimeout(timer);
      const socket = ws;
      ws = null;
      socket?.close();
    };
  }, [namespace, kind, name]);

  return target ? state : 'off';
}

/** Puts a live event into the list: the same event (by name) is replaced, a new one is added. */
export function upsertEvent(list: KubeEvent[], e: KubeEvent): KubeEvent[] {
  const name = e.metadata?.name;
  const i = name ? list.findIndex((x) => x.metadata?.name === name) : -1;
  if (i < 0) return [e, ...list];
  const next = [...list];
  next[i] = { ...list[i], ...e };
  return next;
}
