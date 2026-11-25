import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

vi.mock('./ThemeProvider', () => ({ useTheme: () => ({ setMode: () => {} }) }));
import CommandPalette from './CommandPalette';
import { mockFetch } from '../test/fetchMock';
import { expectNoA11yViolations } from '../test/a11y';
import type { User } from '../services/api';

afterEach(() => vi.unstubAllGlobals());

describe('CommandPalette', () => {
  it('opens on the search box and gives focus back where it was', async () => {
    mockFetch([['GET /api/features', () => ({ features: {} })]]);
    render(
      <MemoryRouter>
        <button type="button">page</button>
        <CommandPalette user={{ id: 1, username: 'ops', isAdmin: false } as User} namespaces={['shop']} />
      </MemoryRouter>,
    );
    const page = screen.getByRole('button', { name: 'page' });
    page.focus();
    await act(async () => {
      fireEvent.keyDown(document, { key: 'k', ctrlKey: true });
    });
    expect(document.activeElement).toBe(screen.getByPlaceholderText('Type a command, namespace, resource or IP…'));
    await expectNoA11yViolations(document.body);
    fireEvent.keyDown(document.activeElement!, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.activeElement).toBe(page);
  });

  const openPalette = async (isAdmin = false) => {
    render(
      <MemoryRouter>
        <CommandPalette user={{ id: 7, username: 'ops', isAdmin } as User} namespaces={['shop']} />
      </MemoryRouter>,
    );
    await act(async () => {
      fireEvent.keyDown(document, { key: 'k', ctrlKey: true });
    });
    return screen.getByPlaceholderText('Type a command, namespace, resource or IP…') as HTMLInputElement;
  };
  const web = { kind: 'pods', namespace: 'shop', name: 'web-7f9c', pod: { status: { phase: 'Running', containerStatuses: [{ name: 'a', ready: true, state: { running: {} } }] } } };

  it('finds resources with a kind chip, opens one on Enter and lists it as recently opened', async () => {
    localStorage.clear();
    const calls = mockFetch([
      ['GET /api/features', () => ({ features: {} })],
      ['GET /api/search', () => ({ items: [web] })],
    ]);
    const box = await openPalette();
    expect(screen.getByText('Narrow down: po · deploy · svc · ns:… · or type an IP')).toBeInTheDocument();
    fireEvent.change(box, { target: { value: 'po ns:shop web' } });
    expect(box.value).toBe('web');
    expect(screen.getByText('Pod')).toBeInTheDocument();
    expect(screen.getByText('ns: shop')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText('web-7f9c')).toBeInTheDocument());
    const search = calls.find((c) => c.url.includes('/api/search'))!;
    expect(search.url).toContain('q=web&kind=pods&ns=shop');
    expect(search.headers.get('X-OpenConsole-Refresh')).toBe('auto');
    expect(screen.getByText('shop · Running')).toBeInTheDocument();
    await expectNoA11yViolations(document.body);

    // Backspace in the empty box takes the last chip off, × the other one.
    fireEvent.change(box, { target: { value: '' } });
    fireEvent.keyDown(box, { key: 'Backspace' });
    expect(screen.queryByText('ns: shop')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Remove filter Pod' }));
    expect(screen.queryByText('Pod')).toBeNull();

    fireEvent.change(box, { target: { value: 'web' } });
    await waitFor(() => expect(screen.getByText('web-7f9c')).toBeInTheDocument());
    fireEvent.keyDown(box, { key: 'Enter' });
    expect(localStorage.getItem('dashboardPendingDetail')).toBe('web-7f9c');
    expect(localStorage.getItem('dashboardNamespace')).toBe('shop');
    expect(JSON.parse(localStorage.getItem('palette:recent:7:0')!)).toEqual([{ kind: 'pods', namespace: 'shop', name: 'web-7f9c' }]);

    await act(async () => {
      fireEvent.keyDown(document, { key: 'k', ctrlKey: true });
    });
    expect(screen.getByText('Recently opened')).toBeInTheDocument();
    expect(screen.getByText('web-7f9c')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    expect(screen.queryByText('Recently opened')).toBeNull();
    expect(JSON.parse(localStorage.getItem('palette:recent:7:0')!)).toEqual([]);
  });

  it('a recent resource that is gone leaves the list', async () => {
    localStorage.clear();
    localStorage.setItem('palette:recent:7:0', JSON.stringify([{ kind: 'pods', namespace: 'shop', name: 'old-1' }]));
    mockFetch([
      ['GET /api/features', () => ({ features: {} })],
      ['GET /api/search', () => ({ items: [] })],
    ]);
    const box = await openPalette();
    fireEvent.keyDown(box, { key: 'Enter' });
    await waitFor(() => expect(JSON.parse(localStorage.getItem('palette:recent:7:0')!)).toEqual([]));
  });

  it('one letter and a bare number do not search; no node filter for non-admins', async () => {
    const calls = mockFetch([['GET /api/features', () => ({ features: {} })]]);
    const box = await openPalette();
    fireEvent.change(box, { target: { value: 'w' } });
    fireEvent.change(box, { target: { value: 'no node-a' } });
    expect(box.value).toBe('no node-a');
    await new Promise((r) => setTimeout(r, 250));
    expect(calls.filter((c) => c.url.includes('/api/search')).map((c) => c.url)).toEqual(['/api/search?q=no+node-a']);
  });
});
