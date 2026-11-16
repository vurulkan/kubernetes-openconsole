import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { RolePermissionsPanel } from './RolePermissionsPanel';
import { mockFetch } from '../../test/fetchMock';
import { expectNoA11yViolations } from '../../test/a11y';
import type { ClusterListItem } from '../../services/api';

afterEach(() => vi.unstubAllGlobals());

const roles = [{ id: 9, name: 'viewer', description: '' }];
const clusters = [{ id: 7, name: 'prod' }] as ClusterListItem[];

describe('RolePermissionsPanel add permissions', () => {
  it('adds a template on the picked namespaces and skips what the role already has', async () => {
    const calls = mockFetch([
      ['POST /api/admin/roles/9/permissions', () => ({ status: 'ok' })],
      [
        'GET /api/admin/roles/9/permissions',
        () => ({ items: [{ id: 1, roleId: 9, clusterId: 0, namespace: 'web', resource: 'pods', action: 'list' }] }),
      ],
    ]);
    render(<RolePermissionsPanel roles={roles} clusters={clusters} namespaces={['web', 'db']} onError={() => {}} onSwitchClassic={() => {}} />);
    await screen.findByText('pods');
    fireEvent.click(screen.getByRole('button', { name: /Add permissions/ }));
    const dialog = screen.getByRole('dialog', { name: 'Add permissions' });
    expect(within(dialog).getByText('Nothing to add. Pick a namespace and at least one action.')).toBeInTheDocument();

    fireEvent.click(within(dialog).getByRole('button', { name: 'web' }));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Viewer (read-only)' }));
    expect(within(dialog).getByText(/1 already granted, will be skipped/)).toBeInTheDocument();
    await expectNoA11yViolations(dialog);

    const apply = within(dialog).getByRole('button', { name: /^Add \d+ permissions$/ });
    const count = Number(apply.textContent!.match(/\d+/)![0]);
    expect(count).toBeGreaterThan(1);
    fireEvent.click(apply);
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    const posts = calls.filter((c) => c.method === 'POST');
    expect(posts).toHaveLength(count);
    expect(posts.map((c) => c.body)).not.toContainEqual({ clusterId: 0, namespace: 'web', resource: 'pods', action: 'list' });
    expect(posts.map((c) => c.body)).toContainEqual({ clusterId: 0, namespace: 'web', resource: 'pods', action: 'get' });
    expect(posts.map((c) => c.body)).not.toContainEqual(expect.objectContaining({ action: 'logs' }));
  });

  it('edits a card: unticked grants are deleted, new ones added, on the card’s cluster', async () => {
    const calls = mockFetch([
      ['POST /api/admin/roles/9/permissions', () => ({ status: 'ok' })],
      ['DELETE /api/admin/permissions/', () => ({ status: 'ok' })],
      [
        'GET /api/admin/roles/9/permissions',
        () => ({
          items: [
            { id: 1, roleId: 9, clusterId: 7, clusterName: 'prod', namespace: 'web', resource: 'pods', action: 'list' },
            { id: 2, roleId: 9, clusterId: 7, clusterName: 'prod', namespace: 'web', resource: 'pods', action: 'get' },
          ],
        }),
      ],
    ]);
    render(<RolePermissionsPanel roles={roles} clusters={clusters} namespaces={['web', 'db']} onError={() => {}} onSwitchClassic={() => {}} />);
    await screen.findByText('pods');
    fireEvent.click(screen.getByRole('button', { name: 'Card actions' }));
    fireEvent.click(await screen.findByRole('button', { name: /Edit permissions/ }));
    const dialog = screen.getByRole('dialog', { name: 'Edit permissions…' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'db' }));
    expect(within(dialog).getByText('2 grant(s) will be added · 0 will be removed.')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save (2 added, 0 removed)' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(calls.filter((c) => c.method === 'POST').map((c) => c.body)).toEqual([
      { clusterId: 7, namespace: 'db', resource: 'pods', action: 'list' },
      { clusterId: 7, namespace: 'db', resource: 'pods', action: 'get' },
    ]);
    expect(calls.filter((c) => c.method === 'DELETE')).toEqual([]);
  });
});
