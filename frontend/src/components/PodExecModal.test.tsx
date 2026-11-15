import React, { useState } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { expectNoA11yViolations } from '../test/a11y';

// xterm can't draw in jsdom: a stand-in that keeps the key handler PodExecModal installs.
const { terms, FakeTerminal } = vi.hoisted(() => {
  const terms: Array<InstanceType<typeof FakeTerminal>> = [];
  class FakeTerminal {
    cols = 80;
    rows = 24;
    options: Record<string, unknown> = {};
    keyHandler: (ev: KeyboardEvent) => boolean = () => true;
    written: string[] = [];
    textarea: HTMLTextAreaElement | null = null;
    constructor() {
      terms.push(this);
    }
    loadAddon() {}
    attachCustomKeyEventHandler(h: (ev: KeyboardEvent) => boolean) {
      this.keyHandler = h;
    }
    open(el: HTMLElement) {
      const wrap = document.createElement('div');
      wrap.className = 'xterm';
      this.textarea = document.createElement('textarea');
      this.textarea.setAttribute('aria-label', 'Terminal input');
      wrap.appendChild(this.textarea);
      el.appendChild(wrap);
    }
    focus() {
      this.textarea?.focus();
    }
    clear() {}
    write(d: string | Uint8Array) {
      this.written.push(typeof d === 'string' ? d : new TextDecoder().decode(d));
    }
    writeln(d: string) {
      this.written.push(d);
    }
    onData() {
      return { dispose() {} };
    }
    onResize() {
      return { dispose() {} };
    }
    dispose() {}
  }
  return { terms, FakeTerminal };
});
vi.mock('xterm', () => ({ Terminal: FakeTerminal }));
vi.mock('xterm-addon-fit', () => ({ FitAddon: class { fit() {} } }));
vi.mock('xterm/css/xterm.css', () => ({}));
vi.mock('./ThemeProvider', () => ({ useTheme: () => ({ effective: 'light' }) }));
vi.mock('../services/api', () => ({
  wsUrl: async (path: string, params: URLSearchParams) => `ws://test${path}?${params.toString()}`,
}));

const sockets: FakeSocket[] = [];
class FakeSocket {
  static OPEN = 1;
  readyState = 0;
  binaryType = '';
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: unknown }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: ((e: { code: number }) => void) | null = null;
  constructor(public url: string) {
    sockets.push(this);
  }
  send() {}
  close() {
    this.readyState = 3;
  }
}

import PodExecModal from './PodExecModal';

const Opener: React.FC = () => {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Shell
      </button>
      <PodExecModal open={open} onClose={() => setOpen(false)} namespace="shop" pod="web-1" containers={['app', 'sidecar']} />
    </>
  );
};

const flushFrames = () =>
  act(async () => {
    for (let i = 0; i < 6; i++) await new Promise((r) => setTimeout(r, 20));
  });

beforeEach(() => {
  terms.length = 0;
  sockets.length = 0;
  vi.stubGlobal('WebSocket', FakeSocket);
  vi.stubGlobal('ResizeObserver', class { observe() {} disconnect() {} });
  vi.spyOn(HTMLElement.prototype, 'clientHeight', 'get').mockReturnValue(400);
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const openShell = async () => {
  render(<Opener />);
  const opener = screen.getByRole('button', { name: 'Shell' });
  opener.focus();
  fireEvent.click(opener);
  await flushFrames();
  return opener;
};

describe('PodExecModal', () => {
  it('names its controls, says how to leave the terminal, and passes axe', async () => {
    await openShell();
    const dialog = screen.getByRole('dialog', { name: 'Shell · web-1' });
    expect(screen.getByRole('combobox', { name: 'Container' })).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Shell' })).toBeInTheDocument();
    expect(dialog).toHaveTextContent('Ctrl+] leaves the terminal, then Esc closes.');
    // Focus starts inside the dialog.
    expect(dialog.contains(document.activeElement)).toBe(true);
    await expectNoA11yViolations(document.body);
  });

  it('leaves the terminal with Ctrl+], keeps Esc for the shell, and Esc outside closes back to the opener', async () => {
    const opener = await openShell();
    const term = terms[0];
    term.focus();
    // Esc typed in the terminal goes to the shell (vim), the dialog stays.
    fireEvent.keyDown(term.textarea!, { key: 'Escape' });
    expect(screen.getByRole('dialog')).toBeInTheDocument();

    const ev = new KeyboardEvent('keydown', { key: ']', code: 'BracketRight', ctrlKey: true });
    let passed = true;
    act(() => {
      passed = term.keyHandler(ev);
    });
    expect(passed).toBe(false);
    expect(document.activeElement).toBe(screen.getByRole('combobox', { name: 'Container' }));

    fireEvent.keyDown(document.activeElement!, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.activeElement).toBe(opener);
  });

  it('reconnects when the shell changes', async () => {
    await openShell();
    expect(sockets).toHaveLength(1);
    expect(sockets[0].url).toContain('command=auto');
    fireEvent.change(screen.getByRole('combobox', { name: 'Shell' }), { target: { value: '/bin/sh' } });
    await flushFrames();
    expect(sockets).toHaveLength(2);
    expect(sockets[1].url).toContain('command=%2Fbin%2Fsh');
  });

  it('does not let the replaced session report its close on the new one', async () => {
    await openShell();
    const old = sockets[0];
    act(() => {
      old.readyState = 1;
      old.onopen?.();
    });
    fireEvent.click(screen.getByRole('button', { name: /Reconnect/ }));
    await flushFrames();
    expect(sockets).toHaveLength(2);
    // The old socket's close arrives after the new session started.
    act(() => {
      old.onclose?.({ code: 1005 });
    });
    expect(screen.queryByText(/Session closed/)).toBeNull();
  });
});
