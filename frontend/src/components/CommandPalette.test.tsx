import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
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
    expect(document.activeElement).toBe(screen.getByPlaceholderText('Type a command or namespace…'));
    await expectNoA11yViolations(document.body);
    fireEvent.keyDown(document.activeElement!, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.activeElement).toBe(page);
  });
});
