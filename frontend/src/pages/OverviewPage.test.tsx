import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import OverviewPage from './OverviewPage';

// The shell (header, theme, cluster switcher) is not what this test is about.
vi.mock('../components/Layout', () => ({ default: ({ children }: { children: React.ReactNode }) => <main>{children}</main> }));
import { mockFetch } from '../test/fetchMock';
import { expectNoA11yViolations } from '../test/a11y';
import type { Overview, User } from '../services/api';

const NodesSearch = () => <p>nodes:{useLocation().search}</p>;

const pod = (name: string, status: Record<string, unknown>) => ({ metadata: { name, namespace: 'shop' }, status });

const overview: Overview = {
  generatedAt: new Date().toISOString(),
  cluster: { name: 'prod-eu', version: 'v1.31.2', nodes: 1 },
  metricsSource: 'memory',
  pods: { running: 40, total: 43 },
  deployments: { ready: 9, total: 10 },
  attention: [
    pod('api-1', { phase: 'Running', containerStatuses: [{ name: 'app', state: { waiting: { reason: 'CrashLoopBackOff' } },
      lastState: { terminated: { exitCode: 137, reason: 'OOMKilled', finishedAt: '2026-01-01T00:00:00Z' } } }] }),
    pod('web-1', { phase: 'Pending' }),
    // A candidate the UI's own status logic calls healthy-idle: not counted.
    pod('job-1', { phase: 'Running', containerStatuses: [{ name: 'job', state: { terminated: { exitCode: 0, reason: 'Completed' } } }] }),
  ],
  attentionTotal: 3,
  counts: [
    { t: 1, podsRunning: 39, pods: 43, podsAttention: 4, deploysReady: 9, deploys: 10 },
    { t: 2, podsRunning: 40, pods: 43, podsAttention: 3, deploysReady: 9, deploys: 10 },
  ],
  usage: { cpu: 1500, memory: 2 ** 30, cpuAllocatable: 4000, memoryAllocatable: 8 * 2 ** 30 },
  restarts24h: 6,
  restartsHourly: [...Array(23).fill(0), 6],
  hourStart: 0,
  topRestarts: [{ namespace: 'shop', owner: 'Deployment/api', restarts: 6, exitCode: 137, reason: 'OOMKilled', share: 5 }],
  namespaces: [{ name: 'shop', cpu: 900, memory: 2 ** 29, pods: 12, nearLimit: 2 }],
  warnings: [{ namespace: 'shop', kind: 'Pod', name: 'api-1', reason: 'BackOff', message: 'Back-off restarting', at: new Date().toISOString(), count: 3 }],
  warningsTotal: 1,
  nodes: [{ name: 'n1', ready: true, pressure: ['MemoryPressure'], cpu: 1800, memory: 2 ** 31, cpuAllocatable: 4000, memoryAllocatable: 8 * 2 ** 30 }],
};

describe('OverviewPage', () => {
  it('shows the cluster at a glance, classifying pods with the UI status logic', async () => {
    mockFetch([
      ['GET /api/admin/overview/history', () => ({ source: 'prometheus', points: [{ t: 1, cpu: 1000, memory: 2 ** 29 }, { t: 2, cpu: 1500, memory: 2 ** 30 }] })],
      ['GET /api/admin/overview', () => overview],
    ]);
    const user = { id: 1, username: 'root', isAdmin: true } as User;
    render(
      <MemoryRouter initialEntries={['/overview']}>
        <Routes>
          <Route path="/overview" element={<OverviewPage user={user} />} />
          <Route path="/nodes" element={<NodesSearch />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByRole('heading', { name: 'prod-eu' })).toBeInTheDocument();

    const kpi = screen.getByRole('button', { name: /Pods needing attention/ });
    expect(within(kpi).getByText('2')).toBeInTheDocument();
    expect(kpi).toHaveTextContent('1 failing');
    expect(kpi).toHaveTextContent('1 warning');
    expect(screen.getAllByRole('button', { name: /^CPU/ })[0]).toHaveTextContent('38%');

    const problems = screen.getByRole('region', { name: 'Pods needing attention' });
    expect(within(problems).getByText('api-1')).toBeInTheDocument();
    expect(within(problems).queryByText('job-1')).not.toBeInTheDocument();
    expect(within(problems).getByText('137 (OOMKilled)')).toBeInTheDocument();
    expect(screen.getByText('5× 137 (OOMKilled)')).toBeInTheDocument();
    expect(screen.getByText('2 pods near their limit')).toBeInTheDocument();
    expect(screen.getByText('MemoryPressure')).toBeInTheDocument();
    // The history arrives on its own.
    expect(await screen.findByRole('img', { name: /^CPU: now 1.5/ })).toBeInTheDocument();

    // Live events open here, for the whole cluster, on warnings.
    fireEvent.click(screen.getByRole('button', { name: 'Open Live Events' }));
    const panel = screen.getByRole('complementary', { name: 'Live events' });
    expect(panel).toHaveTextContent('all namespaces');
    expect(within(panel).getByRole('button', { name: 'Warnings' })).toHaveAttribute('aria-pressed', 'true');

    await expectNoA11yViolations(document.body);

    // A node in the strip opens its drawer on the Nodes screen.
    fireEvent.click(within(screen.getByRole('region', { name: 'Nodes' })).getByRole('button', { name: /n1/ }));
    expect(await screen.findByText('nodes:?node=n1')).toBeInTheDocument();
  });
});
