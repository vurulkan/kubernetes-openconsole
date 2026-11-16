import React, { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { AuditSection, AUDIT_DEBOUNCE_MS, emptyAuditFilters, type AuditFilters } from './AuditSection';
import { mockFetch } from '../../test/fetchMock';
import { expectNoA11yViolations } from '../../test/a11y';

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const facets = { actions: [], users: ['alice', 'bob'], namespaces: [], verbs: [], resourceTypes: [], clusters: [], apiKeys: [] };
const entry = (id: number, username: string) => ({
  id,
  createdAt: '2026-11-15T10:00:00Z',
  user: username,
  action: 'pod.list',
  verb: 'list',
  resourceType: 'pod',
  outcome: 'success',
});

const Harness: React.FC = () => {
  const [filters, setFilters] = useState<AuditFilters>(emptyAuditFilters);
  return <AuditSection filters={filters} onChange={setFilters} />;
};

const auditCalls = (calls: Array<{ url: string }>) => calls.filter((c) => c.url.startsWith('/api/admin/audit-logs?'));

describe('AuditSection', () => {
  it('asks the server once after typing stops, not once per key', async () => {
    vi.useFakeTimers();
    const calls = mockFetch([
      ['GET /api/admin/audit-logs/facets', () => facets],
      ['GET /api/admin/audit-logs?', () => ({ items: [], total: 0, limit: 50, offset: 0 })],
    ]);
    render(<Harness />);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(AUDIT_DEBOUNCE_MS);
    });
    expect(auditCalls(calls)).toHaveLength(1);

    const input = screen.getByRole('combobox', { name: 'User' });
    for (const v of ['a', 'al', 'ali', 'alic', 'alice']) {
      fireEvent.change(input, { target: { value: v } });
      await act(async () => {
        await vi.advanceTimersByTimeAsync(50);
      });
    }
    await act(async () => {
      await vi.advanceTimersByTimeAsync(AUDIT_DEBOUNCE_MS);
    });
    const after = auditCalls(calls).slice(1);
    expect(after).toHaveLength(1);
    expect(after[0].url).toContain('user=alice');
  });

  it('never shows the answer of an older filter over a newer one', async () => {
    let releaseOld: (r: Response) => void = () => {};
    mockFetch([
      ['GET /api/admin/audit-logs/facets', () => facets],
      [
        'GET /api/admin/audit-logs?',
        (url) => {
          if (url.includes('outcome=denied')) {
            // The older filter answers last.
            return new Promise<Response>((resolve) => {
              releaseOld = resolve;
            });
          }
          const who = url.includes('outcome=failed') ? 'newer' : 'first';
          return { items: [entry(2, who)], total: 1, limit: 50, offset: 0 };
        },
      ],
    ]);
    render(<Harness />);
    await screen.findByText('first');
    const outcome = screen.getByLabelText('Outcome');
    fireEvent.change(outcome, { target: { value: 'denied' } });
    await new Promise((r) => setTimeout(r, AUDIT_DEBOUNCE_MS + 50));
    fireEvent.change(outcome, { target: { value: 'failed' } });
    await screen.findByText('newer');
    await act(async () => {
      releaseOld(
        new Response(JSON.stringify({ items: [entry(1, 'older')], total: 1, limit: 50, offset: 0 }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
      await new Promise((r) => setTimeout(r, 20));
    });
    expect(screen.queryByText('older')).toBeNull();
    expect(screen.getByText('newer')).toBeInTheDocument();
    await expectNoA11yViolations(document.body);
  });
});
