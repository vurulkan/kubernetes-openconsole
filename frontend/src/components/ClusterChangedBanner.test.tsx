import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen } from '@testing-library/react';
import { mockFetch } from '../test/fetchMock';
import { expectNoA11yViolations } from '../test/a11y';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
  localStorage.clear();
});

const items = [
  { id: 1, name: 'nonprod', isActive: true, selected: false },
  { id: 2, name: 'prod', isActive: false, selected: true },
];

const setup = async () => {
  localStorage.setItem('authToken', 't');
  mockFetch([
    ['GET /api/clusters/public', () => new Response(JSON.stringify({ items }), { status: 200, headers: { 'X-OpenConsole-Cluster': '2' } })],
  ]);
  const api = await import('../services/api');
  await api.listClustersPublic(); // the tab learns it shows prod (2)
  const { default: Banner } = await import('./ClusterChangedBanner');
  const view = render(<Banner />);
  const pick = async (id: number) => {
    await act(async () => {
      window.dispatchEvent(new StorageEvent('storage', { key: api.CLUSTER_PICK_KEY, newValue: JSON.stringify({ id, name: '', at: 1 }) }));
    });
  };
  return { view, pick };
};

describe('ClusterChangedBanner', () => {
  it('says another tab picked a cluster and this tab stays on its own', async () => {
    const { view, pick } = await setup();
    await pick(1);
    expect(await screen.findByText('nonprod was selected in another tab. This tab still works on prod.')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Switch to nonprod' })).toBeTruthy();
    await expectNoA11yViolations(view.container);
    act(() => screen.getByRole('button', { name: 'Stay on prod' }).click());
    expect(screen.queryByRole('status')).toBeNull();
  });

  it('stays quiet when the other tab picked the cluster this tab shows', async () => {
    const { pick } = await setup();
    await pick(2);
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByRole('status')).toBeNull();
  });
});
