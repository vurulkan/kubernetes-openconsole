import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render } from '@testing-library/react';

class FakeWebSocket {
  static all: FakeWebSocket[] = [];
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  constructor(public url: string) {
    FakeWebSocket.all.push(this);
  }
  close() {
    this.onclose?.();
  }
}

beforeEach(() => {
  vi.useFakeTimers();
  FakeWebSocket.all = [];
  vi.stubGlobal('WebSocket', FakeWebSocket);
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ ticket: 't' }), { status: 200 })));
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('LiveEventsPanel', () => {
  it('reconnects with backoff when the socket drops, and stops when closed', async () => {
    const { default: LiveEventsPanel } = await import('./LiveEventsPanel');
    const view = render(<LiveEventsPanel namespace="team-a" open onClose={() => {}} />);
    await act(() => vi.advanceTimersByTimeAsync(0));
    expect(FakeWebSocket.all).toHaveLength(1);
    act(() => FakeWebSocket.all[0].onclose?.()); // server restarted, cluster edited
    await act(() => vi.advanceTimersByTimeAsync(1000));
    expect(FakeWebSocket.all).toHaveLength(2);
    view.rerender(<LiveEventsPanel namespace="team-a" open={false} onClose={() => {}} />);
    await act(() => vi.advanceTimersByTimeAsync(20_000));
    expect(FakeWebSocket.all).toHaveLength(2);
  });
});
