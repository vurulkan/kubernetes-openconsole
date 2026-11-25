import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

vi.mock('../components/Layout', () => ({ default: ({ children }: { children: React.ReactNode }) => <main>{children}</main> }));
vi.mock('../components/ThemeProvider', () => ({ useTheme: () => ({ theme: 'light', resolvedTheme: 'light', mode: 'light', setMode: () => {} }) }));
// The shell itself (xterm, socket) has its own tests; here only which pod and container it opens on.
vi.mock('../components/PodExecModal', () => ({
  default: ({ pod, container }: { pod: string; container?: string }) => <div role="dialog" aria-label={`shell ${pod}/${container}`} />,
}));
import DashboardPage from './DashboardPage';
import { openPod } from '../utils/openDashboard';
import { mockFetch } from '../test/fetchMock';
import { expectNoA11yViolations } from '../test/a11y';
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

describe('DashboardPage keyboard', () => {
  it('opens a pod from the list with the keyboard: its name is a button', async () => {
    mockFetch([['GET /api/namespaces/shop/pods', () => ({ items: [pod('web-1')] })], ...base]);
    renderPage();
    // A button is in the Tab order and Enter clicks it.
    expect(await screen.findByRole('button', { name: 'web-1' })).toBeInTheDocument();
  });

  it("opens the pod's YAML from its drawer", async () => {
    const calls = mockFetch([
      ['GET /api/namespaces/shop/pods/web-1/yaml', () => ({ yaml: 'kind: Pod' })],
      ['GET /api/namespaces/shop/pods/web-1/', () => ({ items: [], points: [] })],
      ['/metrics/', () => ({ source: 'memory', points: [], available: false, items: [] })],
      ['GET /api/namespaces/shop/pods', () => ({ items: [pod('web-1')] })],
      ...base,
    ]);
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: 'web-1' }));
    fireEvent.click(await screen.findByRole('button', { name: 'YAML' }));
    expect(await screen.findByRole('dialog', { name: /Pod/ })).toBeInTheDocument();
    await vi.waitFor(() => expect(calls.some((c) => c.url === '/api/namespaces/shop/pods/web-1/yaml')).toBe(true));
  });
});

describe('DashboardPage staged by the palette', () => {
  // ⌘K on an open Dashboard: another namespace's pod opens with its drawer and the search set
  // (the namespace switch, which closes drawers, must not close this one).
  it('opens a pod of another namespace with its drawer', async () => {
    mockFetch([
      ['GET /api/namespaces/blog/pods/api-1/', () => ({ items: [], points: [] })],
      ['/metrics/', () => ({ source: 'memory', points: [], available: false, items: [] })],
      ['GET /api/namespaces/shop/pods', () => ({ items: [pod('web-1')] })],
      ['GET /api/namespaces/blog/pods', () => ({ items: [pod('api-1'), pod('api-2')] })],
      ...base,
    ]);
    renderPage();
    await screen.findByRole('button', { name: 'web-1' });
    await act(async () => {
      openPod(() => {}, 'blog', 'api-1');
    });
    expect(await screen.findByRole('dialog', { name: /api-1/ })).toBeInTheDocument();
    expect(screen.getByDisplayValue('api-1')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'api-2' })).toBeNull();
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

  it('draws Logs and Shell with different icons', async () => {
    // Both were a terminal (>_) up to 2.23.2.
    mockFetch([
      ['GET /api/namespaces/shop/permissions', () => ({ resources: { pods: ['list', 'logs', 'exec'] } })],
      ['GET /api/namespaces/shop/pods', () => ({ items: [pod('web-1')] })],
      ...base,
    ]);
    renderPage();
    const icon = (name: string) => screen.getByRole('button', { name }).querySelector('svg')?.getAttribute('class') ?? '';
    await screen.findByRole('button', { name: 'Logs' });
    expect(icon('Logs')).toMatch(/lucide-scroll-text/);
    expect(icon('Shell')).toMatch(/lucide-terminal/);
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

  it('marks the poll as automatic (not audited); a load the user asks for is not', async () => {
    vi.useFakeTimers({ toFake: ['setInterval'] });
    const calls = mockFetch([['GET /api/namespaces/shop/pods', () => ({ items: [pod('web-1')] })], ...base]);
    renderPage();
    await screen.findAllByText('web-1');
    const refresh = () =>
      calls.filter((c) => c.url === '/api/namespaces/shop/pods').map((c) => c.headers.get('X-OpenConsole-Refresh'));
    expect(refresh()).toEqual([null]);
    await act(async () => {
      vi.advanceTimersByTime(10_000);
    });
    await vi.waitFor(() => expect(refresh()).toEqual([null, 'auto']));
    await act(async () => {
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'r', bubbles: true }));
    });
    await vi.waitFor(() => expect(refresh()).toEqual([null, 'auto', null]));
  });

  it('empties the list when a load the user asked for fails', async () => {
    let mode: 'ok' | 'fail' = 'ok';
    mockFetch([
      ['GET /api/namespaces/shop/pods', () => (mode === 'ok' ? { items: [pod('web-1')] } : json({ error: 'cluster_timeout' }, 504))],
      ...base,
    ]);
    renderPage();
    await screen.findAllByText('web-1');
    mode = 'fail';
    await act(async () => {
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'r', bubbles: true }));
    });
    expect(await screen.findByText('The cluster did not answer in time.')).toBeInTheDocument();
    expect(screen.queryByText('web-1')).toBeNull();
  });

  it('polls only the Pods and Deployments tabs', async () => {
    vi.useFakeTimers({ toFake: ['setInterval'] });
    localStorage.setItem('dashboardResourceTab', 'services');
    const calls = mockFetch([
      ['GET /api/namespaces/shop/permissions', () => ({ resources: { services: ['list'] } })],
      ['GET /api/namespaces/shop/services', () => ({ items: [{ metadata: { name: 'svc-1' }, spec: { type: 'ClusterIP' } }] })],
      ...base,
    ]);
    renderPage();
    await screen.findAllByText('svc-1');
    await act(async () => {
      vi.advanceTimersByTime(30_000);
    });
    expect(calls.filter((c) => c.url === '/api/namespaces/shop/services')).toHaveLength(1);
  });

  it('hides pods a Job owns on the Pods tab', async () => {
    const jobPod = { ...pod('job-1'), metadata: { ...pod('job-1').metadata, ownerReferences: [{ kind: 'Job', name: 'j' }] } };
    mockFetch([['GET /api/namespaces/shop/pods', () => ({ items: [pod('web-1'), jobPod] })], ...base]);
    renderPage();
    await screen.findAllByText('web-1');
    expect(screen.queryByText('job-1')).toBeNull();
  });

  it("flags a workload's failing pods from an automatic read of the namespace's pods", async () => {
    localStorage.setItem('dashboardResourceTab', 'deployments');
    const crashing = {
      metadata: {
        name: 'web-abc-1',
        labels: { 'pod-template-hash': 'abc' },
        ownerReferences: [{ kind: 'ReplicaSet', name: 'web-abc', controller: true }],
      },
      spec: { containers: [{ name: 'app' }] },
      status: { phase: 'Running', containerStatuses: [{ name: 'app', restartCount: 3, state: { waiting: { reason: 'CrashLoopBackOff' } } }] },
    };
    const calls = mockFetch([
      ['GET /api/namespaces/shop/permissions', () => ({ resources: { deployments: ['list'] } })],
      ['GET /api/namespaces/shop/deployments', () => ({ items: [deployment('web', 1, 0)] })],
      ['GET /api/namespaces/shop/pods', () => ({ items: [crashing] })],
      ...base,
    ]);
    renderPage();
    expect(await screen.findByText('1 pod failing')).toBeInTheDocument();
    const podReads = calls.filter((c) => c.url === '/api/namespaces/shop/pods');
    expect(podReads.map((c) => c.headers.get('X-OpenConsole-Refresh'))).toEqual(['auto']);
  });
});

const deployment = (name: string, replicas: number, ready: number) => ({
  metadata: { name, uid: `uid-${name}`, creationTimestamp: '2026-11-15T10:00:00Z' },
  spec: { replicas, template: { spec: { containers: [{ name: 'app' }] } } },
  status: { replicas, readyReplicas: ready, availableReplicas: ready },
});

describe('DashboardPage events and data modal', () => {
  it("shows a pod's events, refreshes them and closes", async () => {
    const calls = mockFetch([
      ['GET /api/namespaces/shop/pods/web-1/events', () => ({ items: [{ reason: 'Pulled' }] })],
      ['GET /api/namespaces/shop/pods', () => ({ items: [pod('web-1')] })],
      ...base,
    ]);
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: 'Events' }));
    const dialog = await screen.findByRole('dialog', { name: 'Pod Events · web-1' });
    // A list like the drawers' (raw JSON up to 2.23.3).
    expect(await within(dialog).findByText('Pulled')).toBeInTheDocument();
    const reads = () => calls.filter((c) => c.url === '/api/namespaces/shop/pods/web-1/events').length;
    expect(reads()).toBe(1);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Refresh' }));
    await vi.waitFor(() => expect(reads()).toBe(2));
    fireEvent.click(within(dialog).getAllByRole('button', { name: 'Close' }).slice(-1)[0]);
    await vi.waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it("shows a deployment's events", async () => {
    localStorage.setItem('dashboardResourceTab', 'deployments');
    mockFetch([
      ['GET /api/namespaces/shop/permissions', () => ({ resources: { deployments: ['list'] } })],
      ['GET /api/namespaces/shop/deployments/web/events', () => ({ items: [{ reason: 'ScalingReplicaSet' }] })],
      ['GET /api/namespaces/shop/deployments', () => ({ items: [deployment('web', 1, 1)] })],
      ['GET /api/namespaces/shop/pods', () => ({ items: [] })],
      ...base,
    ]);
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: 'Events' }));
    const dialog = await screen.findByRole('dialog', { name: 'Deployment Events · web' });
    expect(await within(dialog).findByText(/ScalingReplicaSet/)).toBeInTheDocument();
  });

  it("shows a ConfigMap's data, and the error text when the read fails", async () => {
    localStorage.setItem('dashboardResourceTab', 'configmaps');
    let fail = false;
    mockFetch([
      ['GET /api/namespaces/shop/permissions', () => ({ resources: { configmaps: ['list'] } })],
      ['GET /api/namespaces/shop/configmaps/cfg/data', () => (fail ? json({ error: 'nope' }, 500) : { data: { mode: 'fast' } })],
      ['GET /api/namespaces/shop/configmaps', () => ({ items: [{ metadata: { name: 'cfg' }, data: { mode: 'fast' } }] })],
      ...base,
    ]);
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: 'Data' }));
    const dialog = await screen.findByRole('dialog', { name: 'ConfigMap Data · cfg' });
    expect(await within(dialog).findByText(/"mode": "fast"/)).toBeInTheDocument();
    fail = true;
    fireEvent.click(within(dialog).getByRole('button', { name: 'Refresh' }));
    expect(await within(dialog).findByText('nope')).toBeInTheDocument();
  });
});

describe('DashboardPage scale, restart and YAML', () => {
  const deploymentRoutes = (actions: string[]): Array<[string, (url: string) => unknown]> => [
    ['GET /api/namespaces/shop/permissions', () => ({ resources: { deployments: actions } })],
    ['GET /api/namespaces/shop/deployments', () => ({ items: [deployment('web', 2, 2)] })],
    ['GET /api/namespaces/shop/pods', () => ({ items: [] })],
  ];
  beforeEach(() => localStorage.setItem('dashboardResourceTab', 'deployments'));

  it('scales a deployment, says so and reloads the list', async () => {
    const calls = mockFetch([
      ['POST /api/namespaces/shop/deployments/web/scale', () => ({ status: 'ok', previous: 2, replicas: 3 })],
      ...deploymentRoutes(['list', 'scale']),
      ...base,
    ]);
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: 'Scale' }));
    const dialog = await screen.findByRole('dialog', { name: 'Scale web' });
    const apply = within(dialog).getByRole('button', { name: 'Apply' });
    expect(apply).toBeDisabled();
    // The − / + buttons and the number field have names (WCAG 4.1.2).
    within(dialog).getByRole('button', { name: 'Decrease replicas' });
    within(dialog).getByRole('button', { name: 'Increase replicas' });
    await expectNoA11yViolations(dialog);
    const input = within(dialog).getByRole('spinbutton', { name: 'Target replicas' });
    expect(input).toHaveValue(2);
    fireEvent.change(input, { target: { value: '0' } });
    expect(within(dialog).getByText(/stops all pods/)).toBeInTheDocument();
    fireEvent.change(input, { target: { value: '3' } });
    fireEvent.click(apply);
    expect(await screen.findByText('Scaled web: 2 → 3 replicas.')).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({ replicas: 3 });
    await vi.waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(calls.filter((c) => c.url === '/api/namespaces/shop/deployments')).toHaveLength(2);
  });

  it('keeps the scale dialog open and shows the error when scaling fails', async () => {
    mockFetch([
      ['POST /api/namespaces/shop/deployments/web/scale', () => json({ error: 'nope' }, 500)],
      ...deploymentRoutes(['list', 'scale']),
      ...base,
    ]);
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: 'Scale' }));
    const dialog = await screen.findByRole('dialog', { name: 'Scale web' });
    fireEvent.change(within(dialog).getByRole('spinbutton'), { target: { value: '5' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Apply' }));
    expect(await screen.findByText('nope')).toBeInTheDocument();
    expect(screen.getByRole('dialog', { name: 'Scale web' })).toBeInTheDocument();
  });

  it('scales a StatefulSet through its own endpoint', async () => {
    localStorage.setItem('dashboardResourceTab', 'statefulsets');
    const calls = mockFetch([
      ['POST /api/namespaces/shop/statefulsets/db/scale', () => ({ status: 'ok', previous: 2, replicas: 1 })],
      ['GET /api/namespaces/shop/permissions', () => ({ resources: { statefulsets: ['list', 'scale'] } })],
      ['GET /api/namespaces/shop/statefulsets', () => ({ items: [deployment('db', 2, 2)] })],
      ['GET /api/namespaces/shop/pods', () => ({ items: [] })],
      ...base,
    ]);
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: 'Scale' }));
    const dialog = await screen.findByRole('dialog', { name: 'Scale db' });
    fireEvent.change(within(dialog).getByRole('spinbutton'), { target: { value: '1' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Apply' }));
    expect(await screen.findByText('Scaled db: 2 → 1 replicas.')).toBeInTheDocument();
    expect(calls.filter((c) => c.method === 'POST').map((c) => c.url)).toEqual(['/api/namespaces/shop/statefulsets/db/scale']);
  });

  it('restarts a deployment after the confirmation', async () => {
    const calls = mockFetch([
      ['POST /api/namespaces/shop/deployments/web/restart', () => ({ status: 'ok', restartedAt: 'now' })],
      ...deploymentRoutes(['list', 'restart']),
      ...base,
    ]);
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: 'Restart' }));
    const dialog = await screen.findByRole('dialog', { name: 'Restart deployment "web"?' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Restart' }));
    expect(await screen.findByText('Restart triggered for web.')).toBeInTheDocument();
    expect(calls.filter((c) => c.method === 'POST')).toHaveLength(1);
    await vi.waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('opens YAML from the list, editable only with the edit permission', async () => {
    mockFetch([
      ['GET /api/namespaces/shop/deployments/web/yaml', () => ({ yaml: 'kind: Deployment' })],
      ...deploymentRoutes(['list']),
      ...base,
    ]);
    const { unmount } = renderPage();
    fireEvent.click(await screen.findByRole('button', { name: 'YAML' }));
    let dialog = await screen.findByRole('dialog', { name: /Deployment/ });
    expect(within(dialog).queryByRole('button', { name: 'Edit' })).toBeNull();
    unmount();

    mockFetch([
      ['GET /api/namespaces/shop/deployments/web/yaml', () => ({ yaml: 'kind: Deployment' })],
      ...deploymentRoutes(['list', 'edit']),
      ...base,
    ]);
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: 'YAML' }));
    dialog = await screen.findByRole('dialog', { name: /Deployment/ });
    expect(await within(dialog).findByRole('button', { name: 'Edit' })).toBeInTheDocument();
  });

  it("opens YAML with the new namespace's edit permission after a switch", async () => {
    localStorage.setItem('dashboardResourceTab', 'configmaps');
    const cm = { metadata: { name: 'cfg' }, data: {} };
    mockFetch([
      ['GET /api/namespaces/shop/permissions', () => ({ resources: { configmaps: ['list', 'edit'] } })],
      ['GET /api/namespaces/blog/permissions', () => ({ resources: { configmaps: ['list'] } })],
      ['GET /api/namespaces/blog/configmaps/cfg/yaml', () => ({ yaml: 'kind: ConfigMap' })],
      ['GET /api/namespaces/shop/configmaps', () => ({ items: [cm] })],
      ['GET /api/namespaces/blog/configmaps', () => ({ items: [cm] })],
      ...base,
    ]);
    renderPage();
    await screen.findByRole('button', { name: 'YAML' });
    await act(async () => {
      window.location.hash = 'ns:blog';
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    });
    await vi.waitFor(() => expect(screen.getAllByText('blog').length).toBeGreaterThan(0));
    await act(async () => {
      await new Promise((r) => setTimeout(r, 20));
    });
    fireEvent.click(screen.getByRole('button', { name: 'YAML' }));
    const dialog = await screen.findByRole('dialog', { name: /ConfigMap/ });
    expect(within(dialog).queryByRole('button', { name: 'Edit' })).toBeNull();
  });
});

describe('DashboardPage shell', () => {
  const twoContainers = {
    ...pod('web-1'),
    spec: { containers: [{ name: 'proxy' }, { name: 'app' }] },
    status: {
      phase: 'Running',
      containerStatuses: ['proxy', 'app'].map((name) => ({ name, ready: true, restartCount: 0, state: { running: {} } })),
    },
  };

  it('opens a one-container pod at once', async () => {
    mockFetch([
      ['GET /api/namespaces/shop/permissions', () => ({ resources: { pods: ['list', 'exec'] } })],
      ['GET /api/namespaces/shop/pods', () => ({ items: [pod('web-1')] })],
      ...base,
    ]);
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: 'Shell' }));
    expect(await screen.findByRole('dialog', { name: 'shell web-1/app' })).toBeInTheDocument();
  });

  it('asks which container first for a pod with sidecars', async () => {
    mockFetch([
      ['GET /api/namespaces/shop/permissions', () => ({ resources: { pods: ['list', 'exec'] } })],
      ['GET /api/namespaces/shop/pods', () => ({ items: [twoContainers] })],
      ...base,
    ]);
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: 'Shell' }));
    fireEvent.click(await screen.findByRole('menuitem', { name: /proxy/ }));
    expect(await screen.findByRole('dialog', { name: 'shell web-1/proxy' })).toBeInTheDocument();
    expect(screen.queryByRole('menu')).toBeNull();
  });
});
