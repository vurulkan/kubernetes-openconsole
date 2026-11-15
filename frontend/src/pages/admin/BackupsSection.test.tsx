import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import { BackupsSection } from './BackupsSection';
import { mockFetch } from '../../test/fetchMock';
import { expectNoA11yViolations } from '../../test/a11y';

afterEach(() => vi.unstubAllGlobals());

const list = (allowDownload: boolean) => ({
  items: [{ name: 'app-20261115-020000.db', sizeBytes: 2_500_000, createdAt: '2026-11-15T02:00:00Z' }],
  dir: '/data/backups',
  keep: 7,
  intervalSeconds: 86400,
  allowDownload,
  keyExternal: false,
});

describe('BackupsSection', () => {
  it('lists backups and says how to allow downloads while they are off', async () => {
    mockFetch([['GET /api/admin/backups', () => list(false)]]);
    render(<BackupsSection />);
    const row = (await screen.findByText('app-20261115-020000.db')).closest('tr')!;
    expect(within(row).getByText('2.4 MB')).toBeInTheDocument();
    expect(within(row).queryByRole('button')).toBeNull();
    expect(screen.getByText(/set BACKUP_ALLOW_DOWNLOAD=true on the Deployment/)).toBeInTheDocument();
    expect(screen.getByText(/also holds the key that decrypts/)).toBeInTheDocument();
    await expectNoA11yViolations(document.body);
  });

  it('offers a download when BACKUP_ALLOW_DOWNLOAD is on', async () => {
    mockFetch([['GET /api/admin/backups', () => list(true)]]);
    render(<BackupsSection />);
    const row = (await screen.findByText('app-20261115-020000.db')).closest('tr')!;
    expect(within(row).getByRole('button', { name: 'Download app-20261115-020000.db' })).toBeInTheDocument();
    await expectNoA11yViolations(document.body);
  });
});
