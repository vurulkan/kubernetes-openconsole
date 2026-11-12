import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { ConfirmProvider } from '../../components/ConfirmDialog';
import { ApiKeysSection } from './ApiKeysSection';
import { UserApiAccessField } from './ApiAccessParts';
import { mockFetch } from '../../test/fetchMock';
import { expectNoA11yViolations } from '../../test/a11y';
import type { AdminApiKey } from '../../services/api';

const DAY = 24 * 60 * 60 * 1000;
const iso = (ms: number) => new Date(Date.now() + ms).toISOString();

const key = (over: Partial<AdminApiKey>): AdminApiKey => ({
  id: 1, name: 'k', note: '', prefix: 'oc_ab12cd', adminScope: false, createdAt: iso(-DAY), updatedAt: iso(-DAY),
  expiresAt: iso(20 * DAY), lastUsedAt: null, lastUsedIp: '', revokedAt: null, clusters: [0], allNamespaces: false,
  namespaces: ['team-a'], grants: ['pods:list'], ownerId: 2, owner: 'bob', status: 'active', outsidePolicy: false, ...over,
});

afterEach(() => vi.unstubAllGlobals());

describe('ApiKeysSection', () => {
  it('lists every user\'s keys, filters them and revokes one with a comment', async () => {
    const calls = mockFetch([
      [
        'GET /api/admin/api-keys',
        () => ({
          items: [
            key({ id: 1, name: 'claude-dev', lastUsedAt: iso(-60_000), lastUsedIp: '10.0.0.7' }),
            key({ id: 2, name: 'ci-bot', owner: 'carol', grants: ['pods:list', 'pods:exec'], expiresAt: null, outsidePolicy: true }),
            key({ id: 3, name: 'ops', owner: 'root', adminScope: true }),
            key({ id: 4, name: 'gone', status: 'revoked', revokedAt: iso(-DAY) }),
          ],
        }),
      ],
      ['POST /api/admin/api-keys/1/revoke', () => ({ status: 'revoked' })],
    ]);
    render(
      <ConfirmProvider>
        <ApiKeysSection users={[]} />
      </ConfirmProvider>,
    );
    const dev = (await screen.findByText('claude-dev')).closest('tr')!;
    expect(within(dev).getByText('bob')).toBeInTheDocument();
    expect(within(dev).getByText('oc_ab12cd…')).toBeInTheDocument();
    expect(within(dev).getByText('10.0.0.7')).toBeInTheDocument();
    expect(within(screen.getByText('ci-bot').closest('tr')!).getByText('Outside the expiry policy')).toBeInTheDocument();
    // A revoked key has nothing to revoke.
    expect(within(screen.getByText('gone').closest('tr')!).queryByRole('button')).toBeNull();
    await expectNoA11yViolations(document.body);

    const names = () => screen.getAllByRole('row').slice(1).map((r) => within(r).queryByText(/claude-dev|ci-bot|ops|gone/)?.textContent);
    fireEvent.click(screen.getByLabelText('Includes exec'));
    expect(names()).toEqual(['ci-bot']);
    fireEvent.click(screen.getByLabelText('Includes exec'));
    fireEvent.click(screen.getByLabelText('Admin API'));
    expect(names()).toEqual(['ops']);
    fireEvent.click(screen.getByLabelText('Admin API'));
    fireEvent.change(screen.getByLabelText('Status'), { target: { value: 'revoked' } });
    expect(names()).toEqual(['gone']);
    fireEvent.change(screen.getByLabelText('Status'), { target: { value: '' } });

    fireEvent.click(screen.getByRole('button', { name: 'Revoke claude-dev of bob' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'left the team' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ comment: 'left the team' });
  });
});

describe('UserApiAccessField', () => {
  it('previews an unsaved choice and revokes all keys', async () => {
    const calls = mockFetch([
      ['/api-access?override=off', () => ({ isAdmin: false, refused: true, activeKeys: 3 })],
      [
        '/api-access?override=',
        () => ({
          isAdmin: false, refused: false, activeKeys: 3, clusters: [{ id: 1, name: 'alpha' }],
          namespaces: [
            { clusterId: 1, namespace: 'ns1', level: 'all' },
            { clusterId: 1, namespace: 'ns2', level: 'read' },
          ],
        }),
      ],
      ['POST /api/admin/users/7/revoke-api-keys', () => ({ revoked: 3 })],
    ]);
    const Harness = () => {
      const [v, setV] = React.useState<'' | 'off'>('');
      return (
        <ConfirmProvider>
          <UserApiAccessField userId={7} value={v} onChange={(x) => setV(x as '' | 'off')} />
        </ConfirmProvider>
      );
    };
    render(<Harness />);
    expect(await screen.findByText('ns1: all permissions · ns2: read-only')).toBeInTheDocument();
    expect(screen.getByText('3 active keys')).toBeInTheDocument();
    await expectNoA11yViolations(document.body);

    fireEvent.click(screen.getByRole('button', { name: 'Off' }));
    expect(await screen.findByText('nothing (keys are refused on every call)')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Off' })).toHaveAttribute('aria-pressed', 'true');

    fireEvent.click(screen.getByRole('button', { name: 'Revoke all their keys' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke all their keys' }));
    expect(await screen.findByText('3 keys revoked')).toBeInTheDocument();
    expect(calls.some((c) => c.method === 'POST' && c.url.endsWith('/users/7/revoke-api-keys'))).toBe(true);
  });
});
