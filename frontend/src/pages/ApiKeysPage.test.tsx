import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

vi.mock('../components/Layout', () => ({ default: ({ children }: { children: React.ReactNode }) => <main>{children}</main> }));
import ApiKeysPage from './ApiKeysPage';
import ApiKeyFormPage from './apikeys/ApiKeyFormPage';
import { allowedChoices, classify, defaultChoice, expiryFromChoice, expiryState, scopePairs, templateGrants } from './apikeys/ApiKeyParts';
import { mockFetch } from '../test/fetchMock';
import { expectNoA11yViolations } from '../test/a11y';
import type { ApiKey, ApiKeyCeiling, User } from '../services/api';

const DAY = 24 * 60 * 60 * 1000;
const iso = (ms: number) => new Date(Date.now() + ms).toISOString();

// The server's safe read-only list (rbac.SafeReadGrants), shortened.
const SAFE = ['pods:list', 'pods:get', 'pods:logs', 'deployments:list', 'deployments:get'];

const ceiling: ApiKeyCeiling = {
  isAdmin: false,
  clusters: [{ id: 1, name: 'alpha' }],
  namespaces: [
    { clusterId: 1, namespace: 'team-a', grants: ['pods:list', 'pods:get', 'pods:logs', 'pods:exec', 'secrets:list'], blocked: ['deployments:restart'] },
    { clusterId: 1, namespace: 'team-b', grants: ['pods:list'], blocked: [] },
  ],
  disabled: ['secrets:edit'],
  adminScopeAllowed: false,
  safeRead: SAFE,
  maxDays: 0,
  allowNoExpiry: true,
};

const key = (over: Partial<ApiKey>): ApiKey => ({
  id: 1, name: 'k', note: '', prefix: 'oc_ab12cd', adminScope: false, createdAt: iso(-DAY), updatedAt: iso(-DAY),
  expiresAt: iso(23 * DAY), lastUsedAt: null, lastUsedIp: '', revokedAt: null,
  clusters: [0], allNamespaces: false, namespaces: ['team-a'], grants: ['pods:list'], invalidGrants: [], ...over,
});

const user = { id: 2, username: 'bob', isAdmin: false } as User;

afterEach(() => vi.unstubAllGlobals());

describe('API key helpers', () => {
  it('names templates and fills them from what the owner holds', () => {
    const available = new Set(['pods:list', 'pods:exec', 'secrets:list', 'secrets:reveal', 'configmaps:get']);
    expect(templateGrants('safeRead', available, SAFE)).toEqual(['pods:list']);
    expect(templateGrants('readAll', available, SAFE)).toEqual(['pods:list', 'configmaps:get', 'secrets:list', 'secrets:reveal']);
    expect(classify(['pods:list', 'pods:logs'], SAFE)).toBe('safeRead');
    expect(classify(['pods:list', 'secrets:reveal'], SAFE)).toBe('readAll');
    expect(classify([...available], SAFE, available)).toBe('all');
    expect(classify(['pods:exec'], SAFE, available)).toBe('custom');
  });

  it('tells the expiry state and computes the expiry to send', () => {
    expect(expiryState({ revokedAt: iso(-1), expiresAt: null }).kind).toBe('revoked');
    expect(expiryState({ revokedAt: null, expiresAt: iso(-1000) }).kind).toBe('expired');
    expect(expiryState({ revokedAt: null, expiresAt: null }).kind).toBe('never');
    expect(expiryState({ revokedAt: null, expiresAt: iso(3 * DAY - 1000) })).toEqual({ kind: 'active', days: 3 });
    const now = new Date(2026, 10, 12, 10, 0, 0);
    expect(expiryFromChoice('never', '', 0, now)).toBeNull();
    expect(Date.parse(expiryFromChoice('30', '', 0, now)!)).toBe(now.getTime() + 30 * DAY);
    expect(new Date(expiryFromChoice('custom', '2026-11-20', 0, now)!).getHours()).toBe(23); // end of that day, local
    expect(expiryFromChoice('custom', '2026-11-01', 0, now)).toBeUndefined();
    expect(expiryFromChoice('custom', '', 0, now)).toBeUndefined();
    // A 30-day limit: the last day whose end is within 30 days (Dec 12 10:00 → Dec 11).
    expect(expiryFromChoice('custom', '2026-12-11', 30, now)).toBeDefined();
    expect(expiryFromChoice('custom', '2026-12-12', 30, now)).toBeUndefined();
  });

  it('offers only the expiries the policy allows', () => {
    expect(allowedChoices({ maxDays: 0, allowNoExpiry: true })).toEqual(['7', '30', '60', '90', 'custom', 'never']);
    expect(allowedChoices({ maxDays: 30, allowNoExpiry: false })).toEqual(['7', '30', 'custom']);
    expect(defaultChoice({ maxDays: 20, allowNoExpiry: false })).toBe('7');
    expect(defaultChoice({ maxDays: 3, allowNoExpiry: false })).toBe('custom');
  });

  it('expands a selection to the namespaces it reaches', () => {
    expect(scopePairs(ceiling, [0], true, []).map((p) => p.namespace)).toEqual(['team-a', 'team-b']);
    expect(scopePairs(ceiling, [1], false, ['team-b']).map((p) => p.namespace)).toEqual(['team-b']);
    expect(scopePairs(ceiling, [2], true, [])).toEqual([]);
  });
});

describe('ApiKeysPage', () => {
  it('lists keys with their permissions and expiry, and offers only what fits a dead key', async () => {
    mockFetch([
      ['GET /api/me/api-keys/ceiling', () => ceiling],
      [
        'GET /api/me/api-keys',
        () => ({
          items: [
            key({ id: 1, name: 'claude-dev', note: 'local agent', grants: ['pods:list', 'pods:get', 'pods:logs'], namespaces: ['team-a', 'team-b', 'x'], lastUsedAt: iso(-5 * 60 * 1000) }),
            key({ id: 2, name: 'ci-bot', grants: ['pods:list', 'pods:exec'], allNamespaces: true, namespaces: [], expiresAt: null, invalidGrants: ['pods:exec', 'pods:list'] }),
            key({ id: 3, name: 'soon', expiresAt: iso(2 * DAY) }),
            key({ id: 4, name: 'old', expiresAt: iso(-DAY) }),
            key({ id: 5, name: 'gone', revokedAt: iso(-DAY) }),
          ],
        }),
      ],
    ]);
    render(
      <MemoryRouter initialEntries={['/account/api-keys']}>
        <Routes>
          <Route path="/account/api-keys" element={<ApiKeysPage user={user} />} />
          <Route path="/account/api-keys/:id" element={<p>edit page</p>} />
        </Routes>
      </MemoryRouter>,
    );
    const dev = (await screen.findByText('claude-dev')).closest('tr')!;
    expect(within(dev).getByText('Read-only (safe)')).toBeInTheDocument();
    expect(within(dev).getByText('· 3 namespaces')).toBeInTheDocument();
    expect(within(dev).getByText('23 days left')).toBeInTheDocument();
    expect(within(dev).getByText('oc_ab12cd…')).toBeInTheDocument();
    const bot = screen.getByText('ci-bot').closest('tr')!;
    expect(within(bot).getByText('exec')).toBeInTheDocument();
    expect(within(bot).getByText('No expiry')).toBeInTheDocument();
    expect(within(bot).getByText('2 permissions not valid now')).toBeInTheDocument();
    expect(within(screen.getByText('soon').closest('tr')!).getByText('2 days left').closest('span[class*="amber"]')).not.toBeNull();
    expect(within(screen.getByText('old').closest('tr')!).getByText('Expired')).toBeInTheDocument();
    expect(within(screen.getByText('gone').closest('tr')!).getByText('Revoked')).toBeInTheDocument();
    await expectNoA11yViolations(document.body);

    // The menu: arrow keys move, Esc closes and focus returns to its button.
    const more = screen.getByRole('button', { name: 'Actions for claude-dev' });
    fireEvent.click(more);
    const menu = screen.getByRole('menu', { name: 'Actions for claude-dev' });
    expect(within(menu).getAllByRole('menuitem').map((b) => b.textContent)).toEqual(['Edit', 'Regenerate', 'Revoke', 'Delete']);
    expect(document.activeElement).toHaveTextContent('Edit');
    fireEvent.keyDown(menu, { key: 'ArrowDown' });
    expect(document.activeElement).toHaveTextContent('Regenerate');
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    expect(document.activeElement).toBe(more);

    fireEvent.click(screen.getByRole('button', { name: 'Actions for old' }));
    expect(within(screen.getByRole('menu')).getAllByRole('menuitem').map((b) => b.textContent)).toEqual(['Regenerate', 'Delete']);
    fireEvent.keyDown(document, { key: 'Escape' });

    // Regenerate asks for a new expiry, then shows the new secret once.
    fireEvent.click(screen.getByRole('button', { name: 'Actions for claude-dev' }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Regenerate' }));
    const dialog = await screen.findByRole('dialog', { name: 'Regenerate "claude-dev"' });
    expect(within(dialog).getByText(/stops working at once/)).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'No expiry' }));
    expect(within(dialog).getByText(/stays valid until you revoke it/)).toBeInTheDocument();
    mockFetch([
      ['POST /api/me/api-keys/1/regenerate', () => ({ key: key({}), secret: 'oc_NEWSECRET' })],
      ['GET /api/me/api-keys/ceiling', () => ceiling],
      ['GET /api/me/api-keys', () => ({ items: [] })],
    ]);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Regenerate' }));
    expect(await screen.findByText('oc_NEWSECRET')).toBeInTheDocument();
    expect(screen.getByText(/You will not see this key again/)).toBeInTheDocument();
  });

  it('shows the empty state', async () => {
    mockFetch([
      ['GET /api/me/api-keys/ceiling', () => ceiling],
      ['GET /api/me/api-keys', () => ({ items: [] })],
    ]);
    render(
      <MemoryRouter>
        <ApiKeysPage user={user} />
      </MemoryRouter>,
    );
    expect(await screen.findByRole('button', { name: 'Create your first key' })).toBeInTheDocument();
  });
});

describe('ApiKeyFormPage', () => {
  it('starts from the safe template, closes cells outside the ceiling, marks partial ones and creates the key', async () => {
    const calls = mockFetch([
      ['GET /api/me/api-keys/ceiling', () => ceiling],
      ['POST /api/me/api-keys', () => ({ key: key({}), secret: 'oc_SECRET123' })],
    ]);
    render(
      <MemoryRouter initialEntries={['/account/api-keys/new']}>
        <Routes>
          <Route path="/account/api-keys/:id" element={<ApiKeyFormPage user={user} />} />
        </Routes>
      </MemoryRouter>,
    );
    const pressed = (name: RegExp) => screen.getByRole('button', { name }).getAttribute('aria-pressed');
    await screen.findByRole('button', { name: 'Read-only (safe)' });
    expect(pressed(/^Read-only \(safe\)$/)).toBe('true');
    expect(pressed(/^pods list/)).toBe('true');
    expect(pressed(/^pods exec/)).toBe('false');
    expect(pressed(/^secrets list/)).toBe('false'); // no Secrets in the safe template
    expect(screen.getByRole('button', { name: /^deployments list/ })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'deployments list — You do not have this permission' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'secrets edit — Switched off by the operator' })).toBeDisabled();
    expect(screen.getByRole('button', { name: "deployments restart — The admin's API access policy does not allow it" })).toBeDisabled();
    // pods:get is in team-a only: partial over the two namespaces.
    expect(screen.getByRole('button', { name: 'pods get — Only in 1 of 2 namespaces' })).toHaveTextContent('1/2');
    await expectNoA11yViolations(document.body);

    // A hand-picked cell makes it custom.
    fireEvent.click(screen.getByRole('button', { name: /^pods exec/ }));
    expect(pressed(/^Custom$/)).toBe('true');
    expect(screen.getByText(/includes exec/)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'claude-dev' } });
    const create = screen.getByRole('button', { name: 'Create' });
    expect(create).toBeDisabled(); // no namespace yet
    fireEvent.click(screen.getByRole('button', { name: 'All my namespaces' }));
    await waitFor(() => expect(create).toBeEnabled());
    fireEvent.click(create);
    expect(await screen.findByText('oc_SECRET123')).toBeInTheDocument();
    const body = calls.find((c) => c.method === 'POST')!.body as Record<string, unknown>;
    expect(body).toMatchObject({ name: 'claude-dev', clusters: [0], allNamespaces: true, namespaces: [], adminScope: false });
    expect(body.grants).toEqual(['pods:list', 'pods:get', 'pods:logs', 'pods:exec']);
    expect(typeof body.expiresAt).toBe('string');
    expect(screen.getByText(/X-OpenConsole-Cluster: alpha/)).toBeInTheDocument();
    await expectNoA11yViolations(document.body);
  });

  it('keeps to the expiry policy and the Admin API policy', async () => {
    mockFetch([['GET /api/me/api-keys/ceiling', () => ({ ...ceiling, isAdmin: true, maxDays: 30, allowNoExpiry: false })]]);
    render(
      <MemoryRouter initialEntries={['/account/api-keys/new']}>
        <Routes>
          <Route path="/account/api-keys/:id" element={<ApiKeyFormPage user={{ ...user, isAdmin: true }} />} />
        </Routes>
      </MemoryRouter>,
    );
    const expiry = (await screen.findByRole('group', { name: 'Expiry' })) as HTMLElement;
    expect(within(expiry).getAllByRole('button').map((b) => b.textContent)).toEqual(['7 days', '30 days', 'Custom date']);
    expect(within(expiry).getByText('At most 30 days (admin policy)')).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: /admin endpoints/ })).toBeDisabled();
    expect(screen.getByText(/does not allow the Admin API/)).toBeInTheDocument();
    await expectNoA11yViolations(document.body);
  });

  it('keeps a cell the policy blocks when editing a key that has it', async () => {
    const blocked: ApiKeyCeiling = {
      ...ceiling,
      namespaces: [{ clusterId: 1, namespace: 'team-a', grants: ['pods:list'], blocked: ['pods:exec'] }],
    };
    const calls = mockFetch([
      ['GET /api/me/api-keys/ceiling', () => blocked],
      ['PUT /api/me/api-keys/9', () => ({ key: key({}) })],
      ['GET /api/me/api-keys', () => ({ items: [key({ id: 9, name: 'shell', grants: ['pods:list', 'pods:exec'] })] })],
    ]);
    render(
      <MemoryRouter initialEntries={['/account/api-keys/9']}>
        <Routes>
          <Route path="/account/api-keys/:id" element={<ApiKeyFormPage user={user} />} />
          <Route path="/account/api-keys" element={<p>list</p>} />
        </Routes>
      </MemoryRouter>,
    );
    const exec = await screen.findByRole('button', { name: "pods exec — The admin's API access policy does not allow it" });
    expect(exec).toHaveAttribute('aria-pressed', 'true');
    expect(screen.queryByText(/will be removed when you save/)).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await screen.findByText('list');
    expect((calls.find((c) => c.method === 'PUT')!.body as { grants: string[] }).grants).toEqual(['pods:list', 'pods:exec']);
  });
});
