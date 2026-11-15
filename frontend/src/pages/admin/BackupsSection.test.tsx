import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { ConfirmProvider } from '../../components/ConfirmDialog';
import { BackupsSection } from './BackupsSection';
import { mockFetch } from '../../test/fetchMock';
import { expectNoA11yViolations } from '../../test/a11y';

afterEach(() => vi.unstubAllGlobals());

describe('BackupsSection', () => {
  it('lists backups, asks before allowing downloads, then offers them', async () => {
    let allow = false;
    const calls = mockFetch([
      [
        'GET /api/admin/backups',
        () => ({
          items: [{ name: 'app-20261115-020000.db', sizeBytes: 2_500_000, createdAt: '2026-11-15T02:00:00Z' }],
          dir: '/data/backups',
          keep: 7,
          intervalSeconds: 86400,
          allowDownload: allow,
          keyExternal: false,
        }),
      ],
      ['PUT /api/admin/backups/settings', () => { allow = true; return { allowDownload: true }; }],
    ]);
    render(
      <ConfirmProvider>
        <BackupsSection />
      </ConfirmProvider>,
    );
    const row = (await screen.findByText('app-20261115-020000.db')).closest('tr')!;
    expect(within(row).getByText('2.4 MB')).toBeInTheDocument();
    expect(within(row).queryByRole('button')).toBeNull();
    expect(screen.getByText(/also holds the key that decrypts/)).toBeInTheDocument();
    await expectNoA11yViolations(document.body);

    fireEvent.click(screen.getByLabelText('Allow downloading backups'));
    fireEvent.click(await screen.findByRole('button', { name: 'Allow' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT' && (c.body as { allowDownload?: boolean })?.allowDownload)).toBe(true));
    const after = (await screen.findByText('app-20261115-020000.db')).closest('tr')!;
    await waitFor(() => expect(within(after).getByRole('button', { name: 'Download app-20261115-020000.db' })).toBeInTheDocument());
  });
});
