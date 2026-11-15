import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

vi.mock('../components/Layout', () => ({ default: ({ children }: { children: React.ReactNode }) => <main>{children}</main> }));
vi.mock('../components/ThemeProvider', () => ({ useTheme: () => ({ theme: 'light', resolvedTheme: 'light', mode: 'light', setMode: () => {} }) }));
import DashboardPage from './DashboardPage';
import { mockFetch } from '../test/fetchMock';
import type { User } from '../services/api';

const user = { id: 1, username: 'ops', isAdmin: false, isActive: true } as User;
const pod = (name: string) => ({
  metadata: { name, namespace: 'x', uid: `uid-${name}`, creationTimestamp: '2026-11-15T10:00:00Z' },
  spec: { containers: [{ name: 'app' }] },
  status: { phase: 'Running', containerStatuses: [{ name: 'app', ready: true, restartCount: 0, state: { running: {} } }] },
});
const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });

// Last in every route list: "GET /api/namespaces" would also match the pod lists.
const base: Array<[string, (url: string) => unknown]> = [
  ['GET /api/auth/me', () => ({ user: { ...user, mustChangePassword: false }, namespaces: ['shop', 'blog'], permissions: [] })],
  ['GET /api/namespaces/shop/permissions', () => ({ resources: { pods: ['list'] } })],
  ['GET /api/namespaces/blog/permissions', () => ({ resources: { pods: ['list'] } })],
  ['GET /api/namespaces', () => ({ namespaces: ['shop', 'blog'] })],
];

const renderPage = () =>
  render(
    <MemoryRouter>
      <DashboardPage user={user} />
    </MemoryRouter>,
  );

beforeEach(() => {
  localStorage.setItem('dashboardNamespace', 'shop');
  localStorage.setItem('dashboardResourceTab', 'pods');
  localStorage.setItem('dashboardViewMode', 'list');
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  localStorage.clear();
  window.location.hash = '';
});

describe('DashboardPage views', () => {
  it('renders only the view in use: no hidden cards behind the list, no table behind the cards', async () => {
    mockFetch([['GET /api/namespaces/shop/pods', () => ({ items: [pod('web-1'), pod('web-2')] })], ...base]);
    const { unmount } = renderPage();
    await screen.findByRole('table');
    expect(screen.getAllByText('web-1')).toHaveLength(1);
    unmount();

    localStorage.setItem('dashboardViewMode', 'card');
    renderPage();
    await screen.findAllByText('web-2');
    expect(screen.getAllByText('web-1')).toHaveLength(1);
    expect(screen.queryByRole('table')).toBeNull();
  });
});

describe('DashboardPage permissions', () => {
  it('shows Logs only with pods:logs', async () => {
    mockFetch([['GET /api/namespaces/shop/pods', () => ({ items: [pod('web-1')] })], ...base]);
    const { unmount } = renderPage();
    await screen.findByText('web-1');
    expect(screen.queryByRole('button', { name: 'Logs' })).toBeNull();
    unmount();

    mockFetch([
      ['GET /api/namespaces/shop/permissions', () => ({ resources: { pods: ['list', 'logs'] } })],
      ['GET /api/namespaces/shop/pods', () => ({ items: [pod('web-1')] })],
      ...base,
    ]);
    renderPage();
    expect(await screen.findByRole('button', { name: 'Logs' })).toBeInTheDocument();
  });

  it('shows Logs after switching to a namespace that grants pods:logs', async () => {
    mockFetch([
      ['GET /api/namespaces/blog/permissions', () => ({ resources: { pods: ['list', 'logs'] } })],
      ['GET /api/namespaces/shop/pods', () => ({ items: [pod('web-1')] })],
      ['GET /api/namespaces/blog/pods', () => ({ items: [pod('web-1')] })],
      ...base,
    ]);
    renderPage();
    await screen.findByText('web-1');
    expect(screen.queryByRole('button', { name: 'Logs' })).toBeNull();
    await act(async () => {
      window.location.hash = 'ns:blog';
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    });
    expect(await screen.findByRole('button', { name: 'Logs' })).toBeInTheDocument();
  });
});

describe('DashboardPage loading', () => {
  it('keeps the list when an automatic refresh fails, and clears the error on the next good one', async () => {
    vi.useFakeTimers({ toFake: ['setInterval'] });
    let mode: 'ok' | 'fail' = 'ok';
    mockFetch([
      ['GET /api/namespaces/shop/pods', () => (mode === 'ok' ? { items: [pod('web-1')] } : json({ error: 'cluster_timeout' }, 504))],
      ...base,
    ]);
    renderPage();
    await screen.findAllByText('web-1');

    mode = 'fail';
    await act(async () => {
      vi.advanceTimersByTime(10_000);
    });
    expect(await screen.findByText('The cluster did not answer in time.')).toBeInTheDocument();
    expect(screen.getAllByText('web-1').length).toBeGreaterThan(0);

    mode = 'ok';
    await act(async () => {
      vi.advanceTimersByTime(10_000);
    });
    await vi.waitFor(() => expect(screen.queryByText('The cluster did not answer in time.')).toBeNull());
    expect(screen.getAllByText('web-1').length).toBeGreaterThan(0);
  });

  it('does not poll while the browser tab is hidden', async () => {
    vi.useFakeTimers({ toFake: ['setInterval'] });
    const calls = mockFetch([['GET /api/namespaces/shop/pods', () => ({ items: [pod('web-1')] })], ...base]);
    renderPage();
    await screen.findAllByText('web-1');
    const polls = () => calls.filter((c) => c.url === '/api/namespaces/shop/pods').length;
    const before = polls();
    const hidden = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    await act(async () => {
      vi.advanceTimersByTime(30_000);
    });
    expect(polls()).toBe(before);
    hidden.mockReturnValue('visible');
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'));
    });
    await vi.waitFor(() => expect(polls()).toBe(before + 1));
  });

  it('shows the namespace picked last even when the previous one answers later', async () => {
    let releaseShop: (r: Response) => void = () => {};
    let shopCalls = 0;
    mockFetch([
      [
        'GET /api/namespaces/shop/pods',
        () => {
          shopCalls += 1;
          if (shopCalls === 1) return { items: [pod('web-1')] };
          return new Promise<Response>((resolve) => {
            releaseShop = resolve;
          });
        },
      ],
      ['GET /api/namespaces/blog/pods', () => ({ items: [pod('blog-1')] })],
      ...base,
    ]);
    renderPage();
    await screen.findAllByText('web-1');
    // r reloads shop (slow), then the palette switches to blog before shop answers.
    await act(async () => {
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'r', bubbles: true }));
    });
    await vi.waitFor(() => expect(shopCalls).toBe(2));
    await act(async () => {
      window.location.hash = 'ns:blog';
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    });
    await screen.findAllByText('blog-1');
    await act(async () => {
      releaseShop(json({ items: [pod('stale-1')] }));
      await new Promise((r) => setTimeout(r, 20));
    });
    expect(screen.queryAllByText('stale-1')).toHaveLength(0);
    expect(screen.getAllByText('blog-1').length).toBeGreaterThan(0);
  });
});
