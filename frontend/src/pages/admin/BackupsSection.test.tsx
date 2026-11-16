import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, within } from '@testing-library/react';
import i18n from '../../i18n';
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

const created = new Date(2026, 10, 16, 23, 37, 51); // local time
const answer = (intervalSeconds: number) => ({
  dir: '/data/backups',
  intervalSeconds,
  keep: 7,
  allowDownload: false,
  keyExternal: true,
  items: [{ name: 'app-20261116-203751-manual.db', sizeBytes: 327680, createdAt: created.toISOString() }],
});

describe('Admin → Backups in Turkish', () => {
  afterEach(async () => {
    await act(() => i18n.changeLanguage('en'));
  });

  // Up to 2.23.1: "11/16/2026, 11:37:51 PM" and "Her 24h 0m bir yedek".
  it('shows ISO times and says the schedule in words', async () => {
    await act(() => i18n.changeLanguage('tr'));
    mockFetch([['GET /api/admin/backups', () => answer(86400)]]);
    render(<BackupsSection />);
    expect(await screen.findByText('2026-11-16 23:37:51')).toBeInTheDocument();
    expect(screen.getByText(/^24 saatte bir yedek alınır; en yeni 7 tanesi \/data\/backups içinde tutulur\.$/)).toBeInTheDocument();
  });

  it('says an hourly or minute schedule naturally, in both languages', async () => {
    await act(() => i18n.changeLanguage('tr'));
    mockFetch([['GET /api/admin/backups', () => answer(3600)]]);
    const { unmount } = render(<BackupsSection />);
    expect(await screen.findByText(/^Saatte bir yedek alınır;/)).toBeInTheDocument();
    unmount();
    await act(() => i18n.changeLanguage('en'));
    mockFetch([['GET /api/admin/backups', () => answer(1800)]]);
    render(<BackupsSection />);
    expect(await screen.findByText(/^A backup every 30 minutes; the newest 7/)).toBeInTheDocument();
  });
});
