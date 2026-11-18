import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import LoginPage from './LoginPage';
import TwoFactorEnroll from './account/TwoFactorEnroll';
import TwoFactorPage from './TwoFactorPage';
import { mockFetch } from '../test/fetchMock';
import { expectNoA11yViolations } from '../test/a11y';
import type { User } from '../services/api';

vi.mock('../components/Layout', () => ({ default: ({ children }: { children: React.ReactNode }) => <main>{children}</main> }));

afterEach(() => localStorage.clear());

const problem = (status: number, error: string) =>
  new Response(JSON.stringify({ type: 'about:blank', title: '', status, error }), { status });

const signIn = () => {
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'tina' } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'pw' } });
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
};

describe('LoginPage code step', () => {
  it('asks for the code after the password, and a recovery code on request', async () => {
    let codes = 0;
    const calls = mockFetch([
      ['GET /api/auth/providers', () => ({ azureAdEnabled: false })],
      ['POST /api/auth/login', () => ({ twoFactor: 'verify', challenge: 'ch-1' })],
      ['POST /api/auth/2fa/verify', () => (++codes === 1 ? problem(401, 'two_factor_invalid') : { token: 'jwt', user: { id: 1, username: 'tina', isAdmin: false } })],
      ['GET /api/auth/me', () => ({ user: { id: 1, username: 'tina' } })],
    ]);
    const { container } = render(
      <MemoryRouter>
        <LoginPage onLogin={async () => {}} />
      </MemoryRouter>,
    );
    signIn();
    const input = await screen.findByLabelText('Code');
    expect(input).toHaveAttribute('autocomplete', 'one-time-code');
    expect(localStorage.getItem('authToken')).toBeNull();
    await expectNoA11yViolations(container);
    fireEvent.change(input, { target: { value: '000000' } });
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('The code is wrong or was used already.');
    fireEvent.click(screen.getByRole('button', { name: 'Use a recovery code' }));
    fireEvent.change(screen.getByLabelText('Recovery code'), { target: { value: 'abcde-fghij' } });
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(localStorage.getItem('authToken')).toBe('jwt'));
    const sent = calls.filter((c) => c.url.includes('/2fa/verify')).map((c) => c.body);
    expect(sent).toEqual([{ challenge: 'ch-1', code: '000000' }, { challenge: 'ch-1', code: 'abcde-fghij' }]);
  });

  it('goes back to the password when the code step expired', async () => {
    mockFetch([
      ['GET /api/auth/providers', () => ({ azureAdEnabled: false })],
      ['POST /api/auth/login', () => ({ twoFactor: 'verify', challenge: 'ch-1' })],
      ['POST /api/auth/2fa/verify', () => problem(401, 'two_factor_challenge_expired')],
    ]);
    render(
      <MemoryRouter>
        <LoginPage onLogin={async () => {}} />
      </MemoryRouter>,
    );
    signIn();
    fireEvent.change(await screen.findByLabelText('Code'), { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('The sign-in took too long.');
    expect(screen.getByLabelText('Password')).toHaveValue('');
  });

  it('explains a refused Azure AD sign-in', async () => {
    mockFetch([['GET /api/auth/providers', () => ({ azureAdEnabled: true })]]);
    render(
      <MemoryRouter initialEntries={['/login?error=azure_mfa_required']}>
        <LoginPage onLogin={async () => {}} />
      </MemoryRouter>,
    );
    expect(await screen.findByRole('alert')).toHaveTextContent('Multi-factor authentication wasn\'t done in your Microsoft sign-in.');
  });
});

describe('TwoFactorEnroll', () => {
  it('blocks until set up: Escape does not close it, Sign out is the way out', async () => {
    const calls = mockFetch([
      ['POST /api/me/2fa/setup', () => ({ secret: 'JBSWY3DPEHPK3PXP', uri: 'otpauth://totp/x', qr: 'data:image/png;base64,AAAA' })],
      ['POST /api/me/2fa/confirm', () => ({ recoveryCodes: ['aaaaa-bbbbb', 'ccccc-ddddd'], token: 'new-jwt', user: {} })],
    ]);
    let done = false;
    const { baseElement } = render(<TwoFactorEnroll onDone={() => (done = true)} />);
    const dialog = await screen.findByRole('dialog', { name: 'Set up two-factor authentication' });
    expect(await screen.findByRole('img', { name: 'QR code for the authenticator app' })).toBeInTheDocument();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(dialog).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Close' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument();
    await expectNoA11yViolations(baseElement);
    fireEvent.change(screen.getByLabelText('Code'), { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Turn on' }));
    expect(await screen.findByText(/aaaaa-bbbbb/)).toBeInTheDocument();
    expect(localStorage.getItem('authToken')).toBe('new-jwt');
    expect(calls.find((c) => c.url.includes('/confirm'))?.body).toEqual({ code: '123456' });
    fireEvent.click(screen.getByRole('button', { name: 'I saved them' }));
    expect(done).toBe(true);
  });
});

describe('TwoFactorPage', () => {
  const user = (twoFactor: User['twoFactor']): User => ({
    id: 1, username: 'tina', isAdmin: false, isActive: true, mustChangePassword: false, authSource: 'local', twoFactor,
  });

  it('can\'t be turned off when the policy requires it; new codes take a code', async () => {
    const calls = mockFetch([
      ['POST /api/me/2fa/recovery-codes', () => ({ recoveryCodes: ['zzzzz-yyyyy'] })],
    ]);
    const { container } = render(
      <MemoryRouter>
        <TwoFactorPage user={user({ policy: 'all', enabled: true, required: true, enroll: false, recoveryCodesLeft: 1 })} onChanged={async () => {}} />
      </MemoryRouter>,
    );
    expect(screen.getByText('On')).toBeInTheDocument();
    expect(screen.getByText('Only 1 recovery codes left: make new ones.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Turn off' })).toBeNull();
    await expectNoA11yViolations(container);
    fireEvent.click(screen.getByRole('button', { name: 'New recovery codes' }));
    fireEvent.change(screen.getByLabelText('Code'), { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'New recovery codes' }));
    expect(await screen.findByText(/zzzzz-yyyyy/)).toBeInTheDocument();
    expect(calls.find((c) => c.url.includes('/recovery-codes'))?.body).toEqual({ code: '123456' });
  });
});
