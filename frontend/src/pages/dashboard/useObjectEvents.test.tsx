import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen } from '@testing-library/react';
import { Events } from './DetailParts';
import { upsertEvent } from './useObjectEvents';

class FakeWebSocket {
  static all: FakeWebSocket[] = [];
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  constructor(public url: string) {
    FakeWebSocket.all.push(this);
  }
  close() {
    this.onclose?.();
  }
  send(frame: object) {
    this.onmessage?.({ data: JSON.stringify(frame) });
  }
}

const frame = (over: object) => ({
  verb: 'event',
  kind: 'Event',
  namespace: 'shop',
  name: 'web-1.aaa',
  at: new Date().toISOString(),
  type: 'Warning',
  reason: 'BackOff',
  message: 'Back-off restarting failed container',
  involvedKind: 'Pod',
  involvedName: 'web-1',
  count: 1,
  ...over,
});

beforeEach(() => {
  FakeWebSocket.all = [];
  vi.stubGlobal('WebSocket', FakeWebSocket);
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ ticket: 't' }), { status: 200 })));
});
afterEach(() => vi.unstubAllGlobals());

// The detail views follow an object's events live on /ws/events (2.23.4).
describe('Events, live', () => {
  it("adds the object's new events, updates a repeat in place and ignores other objects", async () => {
    const load = vi.fn(async () => ({ items: [{ metadata: { name: 'web-1.old' }, type: 'Normal', reason: 'Pulled' }] }));
    render(<Events load={load} version="1" live={{ namespace: 'shop', kind: 'Pod', name: 'web-1' }} />);
    expect(await screen.findByText('Pulled')).toBeInTheDocument();
    await vi.waitFor(() => expect(FakeWebSocket.all).toHaveLength(1));
    const ws = FakeWebSocket.all[0];
    expect(ws.url).toContain('/ws/events?namespace=shop');
    act(() => ws.onopen?.());
    expect(screen.getByText('Live')).toBeInTheDocument();

    act(() => ws.send(frame({})));
    expect(screen.getByText('BackOff')).toBeInTheDocument();
    expect(screen.getByText('New event: BackOff')).toBeInTheDocument(); // aria-live announcement
    act(() => ws.send(frame({ count: 5 })));
    expect(screen.getAllByText('BackOff')).toHaveLength(1);
    expect(screen.getByText(/×5/)).toBeInTheDocument();
    act(() => ws.send(frame({ name: 'other.bbb', involvedName: 'web-2', reason: 'Elsewhere' })));
    act(() => ws.send({ verb: 'updated', kind: 'Pod', namespace: 'shop', name: 'web-1', at: '' }));
    expect(screen.queryByText('Elsewhere')).toBeNull();
  });

  it('says it is reconnecting after a drop and reads the list again once back', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const load = vi.fn(async () => ({ items: [] }));
    render(<Events load={load} version="1" live={{ namespace: 'shop', kind: 'Deployment', name: 'web' }} />);
    await vi.waitFor(() => expect(FakeWebSocket.all).toHaveLength(1));
    act(() => FakeWebSocket.all[0].onopen?.());
    expect(load).toHaveBeenCalledTimes(1);
    act(() => FakeWebSocket.all[0].close());
    expect(screen.getByText('Reconnecting…')).toBeInTheDocument();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1500);
    });
    await vi.waitFor(() => expect(FakeWebSocket.all).toHaveLength(2));
    act(() => FakeWebSocket.all[1].onopen?.());
    expect(screen.getByText('Live')).toBeInTheDocument();
    await vi.waitFor(() => expect(load).toHaveBeenCalledTimes(2)); // the gap is filled
    vi.useRealTimers();
  });

  it('opens no socket without `live`', async () => {
    render(<Events load={async () => ({ items: [] })} version="1" />);
    expect(await screen.findByText('No events in the last hour.')).toBeInTheDocument();
    expect(FakeWebSocket.all).toHaveLength(0);
    expect(screen.queryByText('Live')).toBeNull();
  });
});

describe('upsertEvent', () => {
  it('replaces an event with the same name and puts a new one first', () => {
    const list = [{ metadata: { name: 'a' }, count: 1 }, { metadata: { name: 'b' } }];
    expect(upsertEvent(list, { metadata: { name: 'a' }, count: 3 })[0]).toEqual({ metadata: { name: 'a' }, count: 3 });
    expect(upsertEvent(list, { metadata: { name: 'c' } }).map((e) => e.metadata?.name)).toEqual(['c', 'a', 'b']);
  });
});
