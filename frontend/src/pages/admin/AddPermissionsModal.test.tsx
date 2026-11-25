import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { AddPermissionsModal } from './AddPermissionsModal';
import { mockFetch } from '../../test/fetchMock';
import type { ClusterListItem } from '../../services/api';

afterEach(() => vi.unstubAllGlobals());

describe('AddPermissionsModal', () => {
  it("lists the picked cluster's namespaces, every cluster's for All clusters", async () => {
    const byCluster: Record<string, string[]> = { '1': ['alpha-ns'], '2': ['beta-ns', 'shared'] };
    const calls = mockFetch([
      ['GET /api/namespaces', (_url, init) => ({ namespaces: byCluster[new Headers(init?.headers).get('X-OpenConsole-Cluster') ?? ''] ?? [] })],
    ]);
    const clusters = [
      { id: 1, name: 'alpha', isActive: true },
      { id: 2, name: 'beta', isActive: false },
    ] as ClusterListItem[];
    render(
      <AddPermissionsModal
        seed={{ clusterId: 1, namespaces: [], matrix: {}, mode: 'add' }}
        clusters={clusters}
        namespaces={['tab-ns']}
        existing={new Set()}
        onCancel={() => {}}
        onApply={() => {}}
      />,
    );
    expect(await screen.findByRole('button', { name: 'alpha-ns' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'tab-ns' })).toBeNull();
    fireEvent.change(screen.getByLabelText('Cluster'), { target: { value: '2' } });
    expect(await screen.findByRole('button', { name: 'beta-ns' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'alpha-ns' })).toBeNull();
    fireEvent.change(screen.getByLabelText('Cluster'), { target: { value: '0' } });
    expect(await screen.findByRole('button', { name: 'alpha-ns' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'shared' })).toBeInTheDocument();
    expect(calls.every((c) => c.headers.get('X-OpenConsole-Refresh') === 'auto')).toBe(true);
  });
});
