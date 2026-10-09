import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { UsersSection } from './UsersSection';
import { User } from '../../services/api';
import { mockFetch } from '../../test/fetchMock';
import { expectNoA11yViolations } from '../../test/a11y';

const users: User[] = [
  { id: 1, username: 'admin', mustChangePassword: false, isActive: true, isAdmin: true, authSource: 'local' },
  { id: 2, username: 'jdoe', mustChangePassword: false, isActive: true, isAdmin: false, authSource: 'ldap' },
  { id: 3, username: 'jane@example.com', mustChangePassword: false, isActive: false, isAdmin: false, authSource: 'azure' },
];

afterEach(() => vi.unstubAllGlobals());

function renderSection() {
  return render(
    <UsersSection
      users={users}
      groups={[]}
      userGroups={{}}
      filter=""
      onFilter={() => {}}
      onNew={() => {}}
      onEdit={() => {}}
      onDelete={() => {}}
    />,
  );
}

describe('UsersSection', () => {
  it('shows each source and offers password reset only for local users', async () => {
    renderSection();
    const row = (name: string) => screen.getByText(name).closest('tr') as HTMLElement;
    expect(within(row('admin')).getByText('Local')).toBeInTheDocument();
    expect(within(row('jdoe')).getByText('LDAP')).toBeInTheDocument();
    expect(within(row('jane@example.com')).getByText('Azure AD')).toBeInTheDocument();
    expect(within(row('admin')).queryByTitle('Reset password')).toBeInTheDocument();
    expect(within(row('jdoe')).queryByTitle('Reset password')).not.toBeInTheDocument();
    expect(within(row('jane@example.com')).queryByTitle('Reset password')).not.toBeInTheDocument();
    await expectNoA11yViolations(document.body);
  });

  it('validates and submits a reset', async () => {
    const calls = mockFetch([['POST /api/admin/users/1/reset-password', () => ({ status: 'ok', mustChangePassword: true })]]);
    renderSection();
    fireEvent.click(within(screen.getByText('admin').closest('tr') as HTMLElement).getByTitle('Reset password'));
    const dialog = await screen.findByRole('dialog');
    await expectNoA11yViolations(document.body);
    const [pw, confirmPw] = within(dialog).getAllByLabelText(/new password/i);
    fireEvent.change(pw, { target: { value: 'short' } });
    fireEvent.change(confirmPw, { target: { value: 'short' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Reset password' }));
    expect(await screen.findByText(/at least 8/)).toBeInTheDocument();
    expect(calls).toHaveLength(0);

    fireEvent.change(pw, { target: { value: 'Long-enough-1' } });
    fireEvent.change(confirmPw, { target: { value: 'Long-enough-1' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Reset password' }));
    expect(await screen.findByText(/was reset/)).toBeInTheDocument();
    expect(calls[0].body).toEqual({ password: 'Long-enough-1', mustChange: true });
  });
});
