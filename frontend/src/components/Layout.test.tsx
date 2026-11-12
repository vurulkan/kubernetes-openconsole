import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { mockFetch } from '../test/fetchMock';
import { expectNoA11yViolations } from '../test/a11y';
import type { User } from '../services/api';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
});

// getFeatures caches per module, so each case loads a fresh Layout.
const renderLayout = async (user: Partial<User>, features: Record<string, boolean> = {}) => {
  vi.stubGlobal('matchMedia', (query: string) => ({ matches: false, media: query, addEventListener: () => {}, removeEventListener: () => {} }));
  mockFetch([
    ['GET /api/version', () => ({ version: 'test' })],
    ['GET /api/features', () => ({ features })],
    ['GET /api/clusters/public', () => ({ items: [] })],
  ]);
  const { default: Layout } = await import('./Layout');
  const { ThemeProvider } = await import('./ThemeProvider');
  render(
    <ThemeProvider>
    <MemoryRouter initialEntries={['/']}>
      <Routes>
        <Route path="/" element={<Layout user={{ id: 1, username: 'bob', isAdmin: false, authSource: 'local', ...user } as User}><p>home</p></Layout>} />
        <Route path="/account/api-keys" element={<p>keys page</p>} />
      </Routes>
    </MemoryRouter>
    </ThemeProvider>,
  );
};

describe('Layout account menu', () => {
  it('opens from the avatar, moves with the arrow keys, closes on Esc and goes to API keys', async () => {
    await renderLayout({});
    const button = screen.getByRole('button', { name: 'Account menu of bob' });
    fireEvent.click(button);
    const menu = screen.getByRole('menu', { name: 'Account menu of bob' });
    expect(within(menu).getAllByRole('menuitem').map((b) => b.textContent)).toEqual(['API keys', 'Change password']);
    expect(document.activeElement).toHaveTextContent('API keys');
    fireEvent.keyDown(menu, { key: 'ArrowDown' });
    expect(document.activeElement).toHaveTextContent('Change password');
    await expectNoA11yViolations(document.body);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    expect(document.activeElement).toBe(button);

    fireEvent.click(button);
    fireEvent.click(screen.getByRole('menuitem', { name: 'API keys' }));
    expect(await screen.findByText('keys page')).toBeInTheDocument();
  });

  it('leaves out the password for directory users and API keys when the operator turned them off', async () => {
    await renderLayout({ authSource: 'ldap' }, { api_keys: false });
    await waitFor(() => expect(screen.getByRole('button', { name: 'Account menu of bob' })).toBeDisabled());
    expect(screen.queryByRole('button', { name: 'API keys' })).not.toBeInTheDocument(); // drawer item
  });
});
