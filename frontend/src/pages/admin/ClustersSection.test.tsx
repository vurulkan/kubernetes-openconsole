import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ClustersSection } from './ClustersSection';
import { mockFetch } from '../../test/fetchMock';
import { expectNoA11yViolations } from '../../test/a11y';

afterEach(() => vi.unstubAllGlobals());

const cluster = (id: number, name: string, isActive = false) => ({ id, name, isActive, description: '', server: '', method: 'token' });

describe('ClustersSection order', () => {
  it('moves a cluster with ↑ / ↓ on its handle, saves at once and says the new place', async () => {
    let fail = false;
    const calls = mockFetch([
      [
        'PUT /api/admin/clusters/order',
        () => (fail ? new Response(JSON.stringify({ error: 'conflict' }), { status: 409 }) : { status: 'ok' }),
      ],
      ['GET /api/admin/clusters', () => ({ items: [cluster(1, 'prod', true), cluster(2, 'staging'), cluster(3, 'dev')] })],
    ]);
    render(<ClustersSection />);
    const handle = await screen.findByRole('button', { name: 'Move dev (position 3 of 3)' });
    await expectNoA11yViolations(document.body);
    fireEvent.keyDown(handle, { key: 'ArrowUp' });
    expect(handle).toHaveAccessibleName('Move dev (position 2 of 3)');
    expect(screen.getByText('dev, position 2 of 3')).toBeInTheDocument(); // aria-live
    await waitFor(() => expect(calls.filter((c) => c.method === 'PUT')).toHaveLength(1));
    expect(calls.find((c) => c.method === 'PUT')?.body).toEqual({ ids: [1, 3, 2] });
    // The default cluster isn't pinned to the top.
    fireEvent.keyDown(screen.getByRole('button', { name: 'Move dev (position 2 of 3)' }), { key: 'ArrowUp' });
    await waitFor(() => expect(calls.filter((c) => c.method === 'PUT')).toHaveLength(2));
    expect(calls.filter((c) => c.method === 'PUT')[1].body).toEqual({ ids: [3, 1, 2] });
    // At the top, ↑ does nothing.
    fireEvent.keyDown(screen.getByRole('button', { name: 'Move dev (position 1 of 3)' }), { key: 'ArrowUp' });

    // A refused save: the error shows and the list goes back to what the server has.
    fail = true;
    fireEvent.keyDown(screen.getByRole('button', { name: 'Move prod (position 2 of 3)' }), { key: 'ArrowDown' });
    expect(await screen.findByText('This conflicts with the current state.')).toBeInTheDocument();
    expect(await screen.findByRole('button', { name: 'Move prod (position 1 of 3)' })).toBeInTheDocument();
    expect(calls.filter((c) => c.method === 'PUT')).toHaveLength(3);
  });
});
