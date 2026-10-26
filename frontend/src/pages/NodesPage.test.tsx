import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import NodesPage from './NodesPage';
import { matchNode } from './nodes/NodeParts';

vi.mock('../components/Layout', () => ({ default: ({ children }: { children: React.ReactNode }) => <main>{children}</main> }));
import { mockFetch } from '../test/fetchMock';
import { expectNoA11yViolations } from '../test/a11y';
import type { NodeDetail, NodeList, NodeRow, User } from '../services/api';

const row = (name: string, over: Partial<NodeRow> = {}): NodeRow => ({
  name, ready: true, pressure: [], cpuAllocatable: 4000, memoryAllocatable: 8 * 2 ** 30,
  cpu: 1000, memory: 2 ** 30, cpuRequests: 2000, cpuLimits: 6000, memoryRequests: 2 ** 31, memoryLimits: 2 ** 32,
  roles: [], kubeletVersion: 'v1.31.2', os: 'linux', arch: 'amd64', created: '2026-01-01T00:00:00Z',
  labels: { 'kubernetes.io/os': 'linux' }, pods: 12, podCapacity: 110, ...over,
});

const list: NodeList = {
  generatedAt: new Date().toISOString(),
  nodes: [
    row('cp-1', { roles: ['control-plane'], labels: { zone: 'a' } }),
    // 3800 / 4000 = 95 %: red meter; memory pressure and cordoned shown apart.
    row('pool-1', { cpu: 3800, pressure: ['MemoryPressure'], unschedulable: true, labels: { zone: 'b' } }),
    row('pool-2', { ready: false, cpu: undefined, memory: undefined }),
  ],
};

const pod = (name: string, cpu: number, status: Record<string, unknown>) => ({
  metadata: { name, namespace: 'shop' }, status, cpuRequests: 100, memoryRequests: 2 ** 27, usage: { cpu, memory: 2 ** 28 },
});

const detail: NodeDetail = {
  summary: list.nodes[1],
  node: {
    metadata: { name: 'pool-1', labels: { zone: 'b' }, annotations: {} },
    spec: { unschedulable: true, taints: [{ key: 'node.kubernetes.io/unschedulable', effect: 'NoSchedule' }] },
    status: {
      capacity: { cpu: '4', memory: '8Gi', pods: '110', 'ephemeral-storage': '100Gi' },
      allocatable: { cpu: '4', memory: '8Gi', pods: '110' },
      addresses: [{ type: 'InternalIP', address: '10.0.0.5' }],
      nodeInfo: { kubeletVersion: 'v1.31.2', operatingSystem: 'linux', architecture: 'amd64', containerRuntimeVersion: 'containerd://1.7' },
      conditions: [{ type: 'Ready', status: 'True' }, { type: 'MemoryPressure', status: 'True', reason: 'KubeletHasInsufficientMemory' }],
    },
  },
  pods: [
    pod('api-1', 300, { phase: 'Running', containerStatuses: [{ name: 'app', ready: false, restartCount: 4, state: { waiting: { reason: 'CrashLoopBackOff' } } }] }),
    pod('web-1', 900, { phase: 'Running', containerStatuses: [{ name: 'app', ready: true, state: { running: {} } }] }),
  ],
  events: [{ type: 'Warning', reason: 'EvictionThresholdMet', message: 'Attempting to reclaim memory' }],
};

afterEach(() => vi.unstubAllGlobals());

describe('matchNode', () => {
  const n = { name: 'aks-pool-1', roles: ['agent'], labels: { 'topology.kubernetes.io/zone': 'westeurope-1', spot: 'true' } };
  it('matches names, roles and labels, every term', () => {
    expect(matchNode(n, '')).toBe(true);
    expect(matchNode(n, 'POOL')).toBe(true);
    expect(matchNode(n, 'agent')).toBe(true);
    expect(matchNode(n, 'topology.kubernetes.io/zone=westeurope-1')).toBe(true);
    expect(matchNode(n, 'spot=')).toBe(true);
    expect(matchNode(n, 'spot=false')).toBe(false);
    expect(matchNode(n, 'pool spot=true')).toBe(true);
    expect(matchNode(n, 'pool gpu')).toBe(false);
  });
});

describe('NodesPage', () => {
  it('lists nodes with status and usage, searches, and opens a node from the URL', async () => {
    const calls = mockFetch([
      ['GET /api/admin/nodes/pool-1/metrics/history', () => ({ source: 'memory', points: [{ t: 1, cpu: 3000, memory: 2 ** 30 }, { t: 31, cpu: 3800, memory: 2 ** 30 }] })],
      ['GET /api/admin/nodes/pool-1', () => detail],
      ['GET /api/admin/nodes', () => list],
    ]);
    const user = { id: 1, username: 'root', isAdmin: true } as User;
    render(
      <MemoryRouter initialEntries={['/nodes']}>
        <Routes>
          <Route path="/nodes" element={<NodesPage user={user} />} />
          <Route path="/" element={<p>dashboard</p>} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText('cp-1')).toBeInTheDocument();
    expect(screen.getByText('3 nodes · 1 not ready')).toBeInTheDocument();
    const pool = screen.getByText('pool-1').closest('tr')!;
    expect(within(pool).getByText('MemoryPressure')).toBeInTheDocument();
    expect(within(pool).getByText('cordoned')).toBeInTheDocument();
    expect(within(pool).getByRole('meter', { name: /^CPU/ })).toHaveAttribute('aria-valuenow', '95');
    expect(within(pool).getByText('req 50% · lim 150%')).toBeInTheDocument();
    expect(within(screen.getByText('pool-2').closest('tr')!).getByText('Not ready')).toBeInTheDocument();
    await expectNoA11yViolations(document.body);

    fireEvent.change(screen.getByRole('searchbox', { name: /Search name/ }), { target: { value: 'zone=b' } });
    expect(screen.queryByText('cp-1')).not.toBeInTheDocument();

    fireEvent.click(screen.getByText('pool-1'));
    const drawer = await screen.findByRole('dialog', { name: 'pool-1' });
    expect(await within(drawer).findByText('10.0.0.5')).toBeInTheDocument();
    expect(within(drawer).getByText('node.kubernetes.io/unschedulable:NoSchedule')).toBeInTheDocument();
    expect(within(drawer).getByText('EvictionThresholdMet')).toBeInTheDocument();
    // Top pods by CPU: web-1 first.
    const top = within(drawer).getByRole('heading', { name: 'Top pods' }).closest('section')!;
    expect(within(top).getAllByRole('button').filter((b) => /-1/.test(b.textContent ?? ''))[0]).toHaveTextContent('web-1');
    // Pods needing attention only.
    fireEvent.click(within(drawer).getByRole('button', { name: 'Needing attention' }));
    const podsSection = within(drawer).getByRole('heading', { name: /Pods on this node/ }).closest('section')!;
    expect(within(podsSection).getByText('api-1')).toBeInTheDocument();
    expect(within(podsSection).queryByText('web-1')).not.toBeInTheDocument();
    expect(await within(drawer).findByRole('img', { name: /^CPU: now 3.8/ })).toBeInTheDocument();
    // The first detail read is audited, the list's own refreshes are not.
    expect(calls.filter((c) => c.url.endsWith('/api/admin/nodes/pool-1')).length).toBeGreaterThan(0);
    await expectNoA11yViolations(document.body);

    // A pod opens on the Dashboard.
    fireEvent.click(within(podsSection).getByText('api-1'));
    expect(localStorage.getItem('dashboardPendingPod')).toBe('api-1');
    expect(await screen.findByText('dashboard')).toBeInTheDocument();
  });
});
