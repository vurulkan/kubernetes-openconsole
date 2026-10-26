import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { PodDrawer } from './PodDrawer';
import { WorkloadDrawer } from './WorkloadDrawer';
import { mockFetch } from '../../test/fetchMock';
import { expectNoA11yViolations } from '../../test/a11y';

const pod = {
  metadata: {
    name: 'web-7d4f-abcde',
    namespace: 'team-a',
    resourceVersion: '1',
    labels: { 'pod-template-hash': '7d4f' },
    ownerReferences: [{ kind: 'ReplicaSet', name: 'web-7d4f' }],
  },
  spec: { nodeName: 'node-1', containers: [{ name: 'app', image: 'web:1.2', resources: { limits: { memory: '64Mi' } } }] },
  status: {
    phase: 'Running',
    containerStatuses: [
      {
        name: 'app',
        restartCount: 3,
        state: { waiting: { reason: 'CrashLoopBackOff' } },
        lastState: { terminated: { exitCode: 137, reason: 'OOMKilled', finishedAt: '2026-10-26T08:00:00Z' } },
      },
    ],
  },
};

const deployment = {
  metadata: { name: 'web', namespace: 'team-a', resourceVersion: '5', annotations: { 'deployment.kubernetes.io/revision': '2' } },
  spec: { replicas: 1, template: { spec: { containers: [{ image: 'web:1.2' }] } } },
  status: { replicas: 1, readyReplicas: 0, updatedReplicas: 1 },
};

afterEach(() => vi.unstubAllGlobals());

describe('PodDrawer', () => {
  it('explains the last exit and links to the owning deployment', async () => {
    mockFetch([
      ['GET /api/namespaces/team-a/pods/web-7d4f-abcde/events', () => ({ items: [] })],
      [
        'GET /api/namespaces/team-a/pods/web-7d4f-abcde/restarts',
        () => ({
          items: [
            {
              namespace: 'team-a', pod: 'web-7d4f-abcde', container: 'app', exitCode: 137, reason: 'OOMKilled', count: 3,
              firstAt: new Date(Date.now() - 600_000).toISOString(), lastAt: new Date(Date.now() - 60_000).toISOString(),
            },
          ],
        }),
      ],
      [
        'GET /api/namespaces/team-a/metrics/pods/web-7d4f-abcde?range=1h',
        () => ({ source: 'memory', points: [{ t: 1, cpu: 50, memory: 40 << 20 }, { t: 31, cpu: 60, memory: 48 << 20 }] }),
      ],
    ]);
    const onOpenOwner = vi.fn();
    const onOpenNode = vi.fn();
    const onLogs = vi.fn();
    render(
      <PodDrawer
        pod={pod}
        namespace="team-a"
        canExec={false}
        onClose={() => {}}
        onLogs={onLogs}
        onShell={() => {}}
        onYaml={() => {}}
        onOpenOwner={onOpenOwner}
        onOpenNode={onOpenNode}
        metrics={{
          available: true,
          updatedAt: '2026-10-26T08:00:00Z',
          items: [{ name: 'web-7d4f-abcde', cpu: 60, memory: 48 << 20, containers: { app: { cpu: 60, memory: 48 << 20 } } }],
        }}
      />,
    );
    expect(screen.getByText('Last exit code: 137 (OOMKilled)')).toBeInTheDocument();
    expect(screen.getByText(/exceeding its memory limit/)).toBeInTheDocument();
    expect(await screen.findByText(/No events/)).toBeInTheDocument();
    // Usage against the container's 64Mi limit, and the history charts.
    expect(screen.getByRole('meter', { name: /Memory of limit/ })).toHaveAttribute('aria-valuenow', '75');
    expect(await screen.findByRole('img', { name: /^CPU: now 60m, peak 60m$/ })).toBeInTheDocument();
    expect(screen.getByText(/OpenConsole memory/)).toBeInTheDocument();
    expect(await screen.findByText('Last 24 hours: 3 restarts. Exit codes: 3× 137 (OOMKilled).')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Deployment/web' }));
    expect(onOpenOwner).toHaveBeenCalledWith('deployments', 'web');
    // Admins get the node as a link to its drawer on the Nodes screen.
    fireEvent.click(screen.getByRole('button', { name: 'node-1' }));
    expect(onOpenNode).toHaveBeenCalledWith('node-1');
    fireEvent.click(screen.getByRole('button', { name: /Previous logs/ }));
    expect(onLogs).toHaveBeenCalledWith('web-7d4f-abcde', 'app');
    expect(screen.queryByRole('button', { name: /Shell/ })).not.toBeInTheDocument();
    await expectNoA11yViolations(document.body);
  });
});

describe('DeploymentDrawer', () => {
  it('lists its own pods and revisions, and flags failing pods', async () => {
    mockFetch([
      ['GET /api/namespaces/team-a/pods', () => ({ items: [pod, { ...pod, metadata: { ...pod.metadata, name: 'other-1', labels: {}, ownerReferences: [] } }] })],
      [
        'GET /api/namespaces/team-a/deployments/web/replicasets',
        () => ({
          items: [
            { name: 'web-7d4f', revision: '2', podTemplateHash: '7d4f', images: ['web:1.2'], replicas: 1, readyReplicas: 0, createdAt: '2026-10-26T07:00:00Z' },
            { name: 'web-1a2b', revision: '1', podTemplateHash: '1a2b', images: ['web:1.1'], replicas: 0, readyReplicas: 0, createdAt: '2026-10-20T07:00:00Z' },
          ],
        }),
      ],
      ['GET /api/namespaces/team-a/deployments/web/events', () => ({ items: [] })],
      ['GET /api/namespaces/team-a/metrics/deployments/web', () => ({ source: 'memory', points: [] })],
      ['GET /api/namespaces/team-a/deployments/web/restarts', () => ({ items: [] })],
    ]);
    const onOpenPod = vi.fn();
    render(
      <WorkloadDrawer
        kind="deployments"
        workload={deployment}
        namespace="team-a"
        canRestart={false}
        canScale={false}
        onClose={() => {}}
        onOpenPod={onOpenPod}
        onLogs={() => {}}
        onYaml={() => {}}
        onRestart={() => {}}
        onScale={() => {}}
        metrics={{ available: false, reason: 'metrics_server_missing', items: [] }}
      />,
    );
    expect(await screen.findByText('1 pod failing')).toBeInTheDocument();
    expect(screen.queryByText('other-1')).not.toBeInTheDocument();
    expect(await screen.findByText('web:1.1')).toBeInTheDocument();
    expect(screen.getByText('#2')).toBeInTheDocument();
    expect(screen.getByText(/metrics-server was not found/)).toBeInTheDocument();
    expect(await screen.findByText(/No samples yet/)).toBeInTheDocument();
    expect(await screen.findByText('No restarts recorded.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Restart/ })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /web-7d4f-abcde/ }));
    expect(onOpenPod).toHaveBeenCalled();
    await expectNoA11yViolations(document.body);
  });
});

describe('WorkloadDrawer (StatefulSet)', () => {
  it('shows its own pods, no revisions, logs or restart, and scale when allowed', async () => {
    const sts = {
      metadata: { name: 'db', namespace: 'team-a', resourceVersion: '7' },
      spec: { replicas: 2, updateStrategy: { type: 'RollingUpdate' }, template: { spec: { containers: [{ image: 'pg:16' }] } } },
      status: { replicas: 2, readyReplicas: 2, updatedReplicas: 2, availableReplicas: 2, updateRevision: 'db-6d9f' },
    };
    const podOf = (name: string, owner: string) => ({
      metadata: { name, ownerReferences: [{ kind: 'StatefulSet', name: owner, controller: true }] },
      spec: { nodeName: 'n1', containers: [{ name: 'pg' }] },
      status: { phase: 'Running', containerStatuses: [{ name: 'pg', ready: true, restartCount: 0, state: { running: {} } }] },
    });
    mockFetch([
      ['GET /api/namespaces/team-a/pods', () => ({ items: [podOf('db-0', 'db'), podOf('db-1', 'db'), podOf('cache-0', 'cache')] })],
      ['GET /api/namespaces/team-a/statefulsets/db/events', () => ({ items: [] })],
      ['GET /api/namespaces/team-a/statefulsets/db/restarts', () => ({ items: [] })],
      ['GET /api/namespaces/team-a/metrics/statefulsets/db', () => ({ source: 'memory', points: [] })],
    ]);
    const onScale = vi.fn();
    render(
      <WorkloadDrawer
        kind="statefulsets"
        workload={sts}
        namespace="team-a"
        canRestart
        canScale
        onClose={() => {}}
        onOpenPod={() => {}}
        onLogs={() => {}}
        onYaml={() => {}}
        onRestart={() => {}}
        onScale={onScale}
        metrics={null}
      />,
    );
    expect(await screen.findByText('db-1')).toBeInTheDocument();
    expect(screen.queryByText('cache-0')).not.toBeInTheDocument();
    expect(screen.getByText('db-6d9f')).toBeInTheDocument();
    expect(screen.queryByText('Revisions')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Restart|Logs/ })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Scale/ }));
    expect(onScale).toHaveBeenCalledWith('db', 2);
    await expectNoA11yViolations(document.body);
  });
});
