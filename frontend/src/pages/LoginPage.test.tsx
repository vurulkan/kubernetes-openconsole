import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import LoginPage from './LoginPage';
import { mockFetch } from '../test/fetchMock';

// The brand panel is dark in both themes, and its text is white. An opaque
// light background there (bg-white without an opacity) hid the logo and the
// three card values in the light theme up to 2.23.1. axe can't measure
// contrast over the panel's gradient, so this checks the classes.
describe('LoginPage brand panel', () => {
  it('keeps its white text on translucent backgrounds', async () => {
    mockFetch([['GET /api/auth/providers', () => ({ local: true })]]);
    render(
      <MemoryRouter>
        <LoginPage onLogin={async () => {}} />
      </MemoryRouter>,
    );
    const value = await screen.findByText('Scoped');
    const panel = value.closest('.bg-gradient-to-br') as HTMLElement;
    for (const el of panel.querySelectorAll<HTMLElement>('[class*="bg-white"]')) {
      expect(el.className).not.toMatch(/(^|\s)bg-white(\s|$)/);
    }
    expect(panel.querySelectorAll('[class*="bg-white/"]').length).toBeGreaterThanOrEqual(4);
  });
});
