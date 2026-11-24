import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { AzureImport, LdapImport } from './DirectoryImportPanel';
import { mockFetch } from '../test/fetchMock';
import { expectNoA11yViolations } from '../test/a11y';

afterEach(() => vi.unstubAllGlobals());

const ldapUsers: Record<string, Array<{ username: string; dn: string; exists?: boolean }>> = {
  ahmet: [
    { username: 'ahmet.k', dn: 'uid=ahmet.k,ou=people' },
    { username: 'ahmet.y', dn: 'uid=ahmet.y,ou=people' },
    { username: 'ahmet.old', dn: 'uid=ahmet.old,ou=people', exists: true },
  ],
  mehmet: [{ username: 'mehmet.a', dn: 'uid=mehmet.a,ou=people' }],
};

const search = (q: string) => {
  fireEvent.change(screen.getByLabelText('Search Query'), { target: { value: q } });
  fireEvent.click(screen.getByRole('button', { name: 'Search' }));
};

describe('DirectoryImportPanel', () => {
  it('keeps picked people across searches and reports each one after the import', async () => {
    const calls = mockFetch([
      ['POST /api/admin/ldap/users/search', (_u, init) => ({ items: ldapUsers[JSON.parse(String(init?.body)).query] ?? [] })],
      [
        'POST /api/admin/ldap/users/import',
        () => ({
          created: 2,
          createdUsers: ['ahmet.k', 'mehmet.a'],
          results: [
            { username: 'ahmet.k', status: 'created' },
            { username: 'mehmet.a', status: 'created' },
            { username: 'ahmet.y', status: 'skipped', reason: 'exists' },
          ],
        }),
      ],
    ]);
    const imported = vi.fn();
    render(<LdapImport groups={[{ id: 4, name: 'devs' }]} onImported={imported} />);
    search('ahmet');
    expect(await screen.findByRole('checkbox', { name: /ahmet\.old/ })).toBeDisabled(); // already an account
    fireEvent.click(screen.getByRole('checkbox', { name: /ahmet\.k/ }));
    fireEvent.click(screen.getByRole('checkbox', { name: /ahmet\.y/ }));
    search('mehmet');
    fireEvent.click(await screen.findByRole('checkbox', { name: /mehmet\.a/ }));
    // The basket survived the second search.
    const basket = screen.getByRole('list', { name: 'Selected (3)' });
    expect(within(basket).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['ahmet.k', 'ahmet.y', 'mehmet.a']);
    await expectNoA11yViolations(document.body);
    fireEvent.click(within(basket).getByRole('button', { name: 'Remove ahmet.y' }));
    fireEvent.click(within(screen.getByRole('list', { name: 'Selected (2)' })).getByRole('button', { name: 'Remove ahmet.k' }));
    search('ahmet');
    fireEvent.click(await screen.findByRole('checkbox', { name: /ahmet\.k/ }));
    fireEvent.click(screen.getByRole('checkbox', { name: /ahmet\.y/ }));

    fireEvent.click(screen.getByRole('button', { name: 'Import 3 users' }));
    await waitFor(() => expect(imported).toHaveBeenCalledWith(['ahmet.k', 'mehmet.a']));
    expect(calls.find((c) => c.url.endsWith('/import'))?.body).toEqual({ usernames: ['mehmet.a', 'ahmet.k', 'ahmet.y'], groupIds: [] });
    expect(document.body).toHaveTextContent('ahmet.k: added');
    expect(document.body).toHaveTextContent('ahmet.y: skipped (Already in OpenConsole)');
    expect(screen.getByText('Selected (0)')).toBeInTheDocument();
    // Imported people can't be picked again.
    expect(screen.getByRole('checkbox', { name: /ahmet\.k/ })).toBeDisabled();
  });

  it('Azure AD: a Graph error offers the typed-name form', async () => {
    mockFetch([
      [
        'POST /api/admin/azure-ad/users/search',
        () => new Response(JSON.stringify({ error: 'graph_forbidden', detail: 'Authorization_RequestDenied' }), { status: 502 }),
      ],
    ]);
    const manual = vi.fn();
    render(<AzureImport groups={[]} onImported={() => {}} onManual={manual} />);
    search('ahmet');
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Microsoft Graph could not be used: The app registration lacks the Microsoft Graph permission');
    fireEvent.click(within(alert).getByRole('button', { name: 'enter the user name by hand' }));
    expect(manual).toHaveBeenCalled();
  });
});
