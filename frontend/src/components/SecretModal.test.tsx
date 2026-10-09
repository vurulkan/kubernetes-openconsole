import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import SecretModal from './SecretModal';
import { mockFetch } from '../test/fetchMock';
import { expectNoA11yViolations } from '../test/a11y';

const secret = {
  metadata: { name: 'db', namespace: 'team-a', uid: 'u', creationTimestamp: '2026-01-01T00:00:00Z', labels: { app: 'api' } },
  type: 'Opaque',
  immutable: false,
  keys: [
    { name: 'password', size: 12 },
    { name: 'user', size: 3 },
  ],
};

afterEach(() => vi.unstubAllGlobals());

describe('SecretModal', () => {
  it('shows key names and sizes but never fetches values without reveal', async () => {
    const calls = mockFetch([['GET /api/namespaces/team-a/secrets/db', () => secret]]);
    render(<SecretModal open namespace="team-a" name="db" canReveal={false} onClose={() => {}} />);
    expect(await screen.findByText('password')).toBeInTheDocument();
    expect(screen.getByText('12 B')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /show/i })).not.toBeInTheDocument();
    expect(calls.some((c) => c.url.includes('/reveal'))).toBe(false);
    await expectNoA11yViolations(document.body);
  });

  it('reveals one key on demand through the audited endpoint', async () => {
    const calls = mockFetch([
      ['GET /api/namespaces/team-a/secrets/db', () => secret],
      ['POST /api/namespaces/team-a/secrets/db/reveal', () => ({ key: 'password', value: 'hunter2', encoding: 'text' })],
    ]);
    render(<SecretModal open namespace="team-a" name="db" canReveal onClose={() => {}} />);
    await screen.findByText('password');
    fireEvent.click(screen.getAllByRole('button', { name: /show/i })[0]);
    expect(await screen.findByText('hunter2')).toBeInTheDocument();
    const reveal = calls.filter((c) => c.url.includes('/reveal'));
    expect(reveal).toHaveLength(1);
    expect(reveal[0].body).toEqual({ key: 'password' });
    // Only the revealed key has a value on screen.
    fireEvent.click(screen.getByRole('button', { name: /hide/i }));
    expect(screen.queryByText('hunter2')).not.toBeInTheDocument();
  });
});
