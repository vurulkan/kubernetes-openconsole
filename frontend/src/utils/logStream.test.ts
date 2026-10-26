import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { openLogStream, type LogFrame, type LogStatus } from './logStream';

class FakeSocket {
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  closed = false;
  constructor(public params: URLSearchParams) {}
  close() {
    this.closed = true;
  }
  send(f: LogFrame) {
    this.onmessage?.({ data: JSON.stringify(f) });
  }
}

function setup(live = true) {
  const sockets: FakeSocket[] = [];
  const lines: string[] = [];
  const statuses: LogStatus[] = [];
  const stop = openLogStream({
    path: '/ws/x',
    params: { container: 'app', tail: '100' },
    live,
    onLine: (f) => lines.push(f.text ?? ''),
    onStatus: (s) => statuses.push(s),
    connect: async (_path, params) => {
      const s = new FakeSocket(params);
      sockets.push(s);
      return s as unknown as WebSocket;
    },
  });
  return { sockets, lines, statuses, stop };
}

const last = <T,>(a: T[]) => a[a.length - 1];
const flush = () => vi.advanceTimersByTimeAsync(0);

describe('openLogStream', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('resumes after a drop from the last timestamp, without tail', async () => {
    const { sockets, lines, statuses } = setup();
    await flush();
    sockets[0].onopen?.();
    sockets[0].send({ t: 'line', ts: '2026-01-01T00:00:01.000000000Z', text: 'a' });
    sockets[0].send({ t: 'line', ts: '2026-01-01T00:00:02.000000000Z', text: 'b' });
    sockets[0].send({ t: 'line', ts: '2026-01-01T00:00:02.000000000Z', text: 'c' });
    sockets[0].onclose?.();
    expect(last(statuses)?.state).toBe('reconnecting');
    await vi.advanceTimersByTimeAsync(1000);
    expect(sockets).toHaveLength(2);
    const q = sockets[1].params;
    expect(q.get('sinceTime')).toBe('2026-01-01T00:00:02.000000000Z');
    expect(q.get('skip')).toBe('2');
    expect(q.get('resume')).toBe('true');
    expect(q.has('tail')).toBe(false);
    sockets[1].send({ t: 'line', ts: '2026-01-01T00:00:03.000000000Z', text: 'd' });
    expect(lines).toEqual(['a', 'b', 'c', 'd']);
    expect(last(statuses)?.state).toBe('following');
  });

  it('ignores a socket after it was stopped or replaced', async () => {
    const { sockets, lines, statuses, stop } = setup();
    await flush();
    stop();
    expect(sockets[0].closed).toBe(true);
    const before = statuses.length;
    sockets[0].send({ t: 'line', text: 'late' });
    sockets[0].send({ t: 'error', reason: 'unavailable' });
    sockets[0].onclose?.();
    await vi.advanceTimersByTimeAsync(20000);
    expect(lines).toEqual([]);
    expect(statuses).toHaveLength(before);
    expect(sockets).toHaveLength(1);
  });

  it('stops on a final end, and follows the new instance after a restart', async () => {
    const prev = setup(false);
    await flush();
    prev.sockets[0].send({ t: 'end', reason: 'previous_complete' });
    prev.sockets[0].onclose?.();
    await vi.advanceTimersByTimeAsync(20000);
    expect(prev.sockets).toHaveLength(1);
    expect(last(prev.statuses)).toEqual({ state: 'ended', reason: 'previous_complete' });

    const live = setup();
    await flush();
    live.sockets[0].send({ t: 'line', ts: '2026-01-01T00:00:01.000000000Z', text: 'old' });
    live.sockets[0].send({ t: 'end', reason: 'container_terminated', retry: true });
    const waiting = last(live.statuses)!;
    expect(waiting.state).toBe('reconnecting');
    expect(waiting.restartedAt).toBeDefined();
    await vi.advanceTimersByTimeAsync(1000);
    live.sockets[1].onopen?.();
    expect(last(live.statuses)?.state).toBe('reconnecting'); // still waiting for output
    live.sockets[1].send({ t: 'line', ts: '2026-01-01T00:00:09.000000000Z', text: 'new' });
    expect(last(live.statuses)).toEqual({ state: 'following', restartedAt: waiting.restartedAt });
  });

  it('backs off up to the cap', async () => {
    const { sockets } = setup();
    await flush();
    for (let i = 0; i < 6; i++) {
      last(sockets)!.onclose?.();
      await vi.advanceTimersByTimeAsync(15000);
    }
    last(sockets)!.onclose?.();
    await vi.advanceTimersByTimeAsync(14999);
    expect(sockets).toHaveLength(7);
    await vi.advanceTimersByTimeAsync(1);
    expect(sockets).toHaveLength(8);
  });
});
