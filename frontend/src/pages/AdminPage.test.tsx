import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

vi.mock('../components/Layout', () => ({ default: ({ children }: { children: React.ReactNode }) => <main>{children}</main> }));
import AdminPage from './AdminPage';
import { mockFetch } from '../test/fetchMock';
import { expectNoA11yViolations } from '../test/a11y';
import type { User } from '../services/api';

const admin = { id: 1, username: 'root', isAdmin: true, isActive: true } as User;
const x509 = { type: 'about:blank', title: 'Bad Request', status: 400, error: 'cluster_invalid', detail: 'x509: certificate signed by unknown authority' };

afterEach(() => {
  vi.unstubAllGlobals();
  localStorage.clear();
});

describe('AdminPage clusters', () => {
  it('shows a failed edit inside the dialog and sends an empty CA as "keep the stored one"', async () => {
    localStorage.setItem('adminActiveTab', 'clusters');
    const calls = mockFetch([
      ['GET /api/admin/clusters', () => ({ items: [{ id: 7, name: 'prod', method: 'token', server: 'https://k8s:6443', isActive: true }] })],
      ['PUT /api/admin/clusters/7', () => new Response(JSON.stringify(x509), { status: 400 })],
    ]);
    render(
      <MemoryRouter>
        <AdminPage user={admin} />
      </MemoryRouter>,
    );
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    const dialog = screen.getByRole('dialog', { name: 'Edit cluster · prod' });
    fireEvent.click(within(dialog).getByRole('checkbox', { name: /Replace credentials/ }));
    fireEvent.change(within(dialog).getByLabelText('Token'), { target: { value: 'new-token' } });
    expect(within(dialog).getByText('Leave empty to keep the stored CA.')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save changes' }));

    expect(await within(dialog).findByRole('alert')).toHaveTextContent('x509: certificate signed by unknown authority');
    const put = calls.find((c) => c.method === 'PUT')!;
    expect(put.body).toMatchObject({ token: 'new-token', replaceSecrets: true, removeCaCert: false });
    expect((put.body as { caCertBase64?: string }).caCertBase64).toBeUndefined();
  });

  it('keeps what was typed while the save was running when it fails', async () => {
    localStorage.setItem('adminActiveTab', 'clusters');
    let fail: (r: Response) => void = () => {};
    mockFetch([
      ['GET /api/admin/clusters', () => ({ items: [{ id: 7, name: 'prod', method: 'token', server: 'https://k8s:6443', isActive: true }] })],
      ['PUT /api/admin/clusters/7', () => new Promise<Response>((resolve) => (fail = resolve))],
    ]);
    render(
      <MemoryRouter>
        <AdminPage user={admin} />
      </MemoryRouter>,
    );
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    const dialog = screen.getByRole('dialog', { name: 'Edit cluster · prod' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save changes' }));
    fireEvent.change(within(dialog).getByLabelText('Description'), { target: { value: 'typed meanwhile' } });
    await act(async () => {
      fail(new Response(JSON.stringify(x509), { status: 400 }));
    });
    expect(await within(dialog).findByRole('alert')).toBeInTheDocument();
    expect(within(dialog).getByLabelText('Description')).toHaveValue('typed meanwhile');
  });
});

describe('AdminPage for a non-admin', () => {
  it('goes back to the dashboard without asking the server for admin data', async () => {
    localStorage.setItem('adminActiveTab', 'users');
    const calls = mockFetch([]);
    render(
      <MemoryRouter initialEntries={['/admin']}>
        <Routes>
          <Route path="/admin" element={<AdminPage user={{ ...admin, isAdmin: false }} />} />
          <Route path="/" element={<p>dashboard</p>} />
        </Routes>
      </MemoryRouter>,
    );
    expect(await screen.findByText('dashboard')).toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 50));
    expect(calls.map((c) => c.url).filter((u) => u.includes('/api/admin') || u.includes('/api/features'))).toEqual([]);
  });
});

describe('AdminPage memberships', () => {
  it('shows users’ groups and groups’ roles from the two lists, without a request per user or group', async () => {
    localStorage.setItem('adminActiveTab', 'users');
    const calls = mockFetch([
      ['GET /api/admin/users/1/groups', () => ({ groupIds: [5] })],
      ['GET /api/admin/groups/5/roles', () => ({ roleIds: [9] })],
      ['GET /api/admin/users', () => ({ items: [{ ...admin, groupIds: [5] }] })],
      ['GET /api/admin/groups', () => ({ items: [{ id: 5, name: 'ops', roleIds: [9] }] })],
      ['GET /api/admin/roles', () => ({ items: [{ id: 9, name: 'viewer', description: '' }] })],
    ]);
    const view = render(
      <MemoryRouter>
        <AdminPage user={admin} />
      </MemoryRouter>,
    );
    expect(await screen.findByText('ops')).toBeInTheDocument();
    view.unmount();
    localStorage.setItem('adminActiveTab', 'groups');
    render(
      <MemoryRouter>
        <AdminPage user={admin} />
      </MemoryRouter>,
    );
    expect(await screen.findByText('viewer')).toBeInTheDocument();
    expect(calls.filter((c) => /\/api\/admin\/(users\/\d+\/groups|groups\/\d+\/roles)/.test(c.url))).toEqual([]);
  });
});

const renderAdmin = (tab: string) => {
  localStorage.setItem('adminActiveTab', tab);
  return render(
    <MemoryRouter>
      <AdminPage user={admin} />
    </MemoryRouter>,
  );
};
const sent = (calls: ReturnType<typeof mockFetch>, method: string, url: string) =>
  calls.filter((c) => c.method === method && c.url.endsWith(url));

describe('AdminPage tabs', () => {
  // Each tab loads what it shows, nothing else (/api/features is fetched once per app).
  const opens: Record<string, string[]> = {
    users: ['/api/admin/azure-ad', '/api/admin/groups', '/api/admin/ldap', '/api/admin/users'],
    groups: ['/api/admin/groups', '/api/admin/roles', '/api/admin/users'],
    roles: ['/api/admin/clusters', '/api/admin/groups', '/api/admin/roles', '/api/admin/roles/9/permissions', '/api/namespaces'],
    ldap: ['/api/admin/groups', '/api/admin/ldap'],
    'azure-ad': ['/api/admin/azure-ad'],
    session: ['/api/admin/session'],
    clusters: ['/api/admin/clusters'],
    customization: [],
    audit: ['/api/admin/audit-logs', '/api/admin/audit-logs/facets'],
    sessions: ['/api/admin/sessions'],
    'api-keys': ['/api/admin/api-keys', '/api/admin/users'],
    recordings: ['/api/admin/recordings', '/api/admin/recordings/settings'],
    backups: ['/api/admin/backups'],
  };

  it.each(Object.entries(opens))('%s loads only what it shows', async (tab, expected) => {
    const calls = mockFetch([
      ['GET /api/admin/roles/', () => ({ items: [] })],
      ['GET /api/admin/roles', () => ({ items: [{ id: 9, name: 'viewer', description: '' }] })],
      [
        'GET /api/admin/audit-logs/facets',
        () => ({ actions: [], users: [], namespaces: [], verbs: [], resourceTypes: [], clusters: [], apiKeys: [] }),
      ],
      ['GET /api/features', () => ({ features: {} })],
      ['GET /api/admin/', () => ({ items: [], total: 0 })],
      ['GET /api/', () => ({})],
    ]);
    renderAdmin(tab);
    await act(async () => {
      await new Promise((r) => setTimeout(r, 400)); // past the audit filter debounce
    });
    const urls = [...new Set(calls.map((c) => c.url.split('?')[0]))].filter((u) => u !== '/api/features').sort();
    expect(urls).toEqual(expected);
    await expectNoA11yViolations(document.body);
  });
});

describe('AdminPage loading', () => {
  it('shows no "no users" message while the list is still loading', async () => {
    let answer: (r: Response) => void = () => {};
    mockFetch([
      ['GET /api/admin/users', () => new Promise<Response>((resolve) => (answer = resolve))],
      ['GET /api/admin/groups', () => ({ items: [] })],
    ]);
    renderAdmin('users');
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50));
    });
    expect(screen.queryByText(/No users yet/)).toBeNull();
    await act(async () => answer(new Response(JSON.stringify({ items: [] }), { status: 200 })));
    expect(await screen.findByText(/No users yet/)).toBeInTheDocument();
  });
});

describe('AdminPage users', () => {
  it('offers LDAP import and Azure AD users when they are on, and highlights a created user', async () => {
    let users = [admin];
    const calls = mockFetch([
      [
        'POST /api/admin/users',
        () => {
          users = [...users, { id: 2, username: 'jdoe', isAdmin: false, isActive: true } as User];
          return users[1];
        },
      ],
      ['GET /api/admin/users', () => ({ items: users })],
      ['GET /api/admin/groups', () => ({ items: [{ id: 5, name: 'ops' }] })],
      ['GET /api/admin/roles', () => ({ items: [] })],
      ['GET /api/admin/ldap', () => ({ enabled: true })],
      ['GET /api/admin/azure-ad', () => ({ enabled: true })],
    ]);
    renderAdmin('users');
    fireEvent.click(await screen.findByRole('button', { name: 'More ways to add a user' }));
    const menu = screen.getByRole('menu');
    expect(within(menu).getByRole('menuitem', { name: /Import from LDAP/ })).toBeInTheDocument();
    expect(within(menu).getByRole('menuitem', { name: /Azure AD user/ })).toBeInTheDocument();
    fireEvent.click(within(menu).getByRole('menuitem', { name: /Local user/ }));

    const dialog = screen.getByRole('dialog', { name: 'New local user' });
    fireEvent.change(within(dialog).getByLabelText('Username'), { target: { value: 'jdoe' } });
    fireEvent.change(within(dialog).getByLabelText('Password'), { target: { value: 'Long-enough-1' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create user' }));
    const row = (await screen.findByText('jdoe')).closest('tr') as HTMLElement;
    expect(within(row).getByText('New')).toBeInTheDocument();
    expect(sent(calls, 'POST', '/api/admin/users')[0].body).toEqual({
      username: 'jdoe',
      password: 'Long-enough-1',
      isAdmin: false,
      source: 'local',
      groupIds: [],
    });
  });
});

describe('AdminPage roles, classic permissions view', () => {
  it('lists a picked role’s permissions and removes a row', async () => {
    localStorage.setItem('rolePermissionsLayout', 'classic');
    const calls = mockFetch([
      ['DELETE /api/admin/permissions/', () => ({ status: 'ok' })],
      [
        'GET /api/admin/roles/9/permissions',
        () => ({
          items: [
            { id: 1, roleId: 9, clusterId: 0, namespace: 'web', resource: 'pods', action: 'list' },
            { id: 2, roleId: 9, clusterId: 0, namespace: 'web', resource: 'pods', action: 'get' },
          ],
        }),
      ],
      ['GET /api/admin/roles', () => ({ items: [{ id: 9, name: 'viewer', description: '' }] })],
      ['GET /api/admin/groups', () => ({ items: [] })],
      ['GET /api/admin/clusters', () => ({ items: [] })],
      ['GET /api/namespaces', () => ({ namespaces: ['web'] })],
    ]);
    renderAdmin('roles');
    expect(await screen.findByText('Select a role to view its permissions.')).toBeInTheDocument();
    await screen.findByRole('option', { name: 'viewer' });
    fireEvent.change(screen.getByLabelText('Role'), { target: { value: '9' } });
    expect(await screen.findByText('pods:list')).toBeInTheDocument();
    // Each grant's ✕ says which grant it removes.
    expect(screen.getByRole('button', { name: 'Remove pods:get' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Remove row' }));
    await waitFor(() => expect(calls.filter((c) => c.method === 'DELETE').map((c) => c.url).sort()).toEqual(['/api/admin/permissions/1', '/api/admin/permissions/2']));
    // Back to the new view.
    fireEvent.click(screen.getByRole('button', { name: 'Switch to new view' }));
    expect(localStorage.getItem('rolePermissionsLayout')).toBe('new');
  });
});

describe('AdminPage LDAP', () => {
  const stored = {
    enabled: true,
    host: 'dc1.example.com',
    port: 636,
    useSsl: true,
    bindDn: 'cn=svc,dc=example',
    userBaseDn: 'OU=Users,DC=example',
    userBaseDns: [' OU=A,DC=example ', ''],
    userFilter: '(sAMAccountName=%s)',
    usernameAttribute: 'sAMAccountName',
    passwordConfigured: true,
    autoProvision: false,
    autoProvisionGroupIds: [],
  };

  it('saves the form without the stored bind password unless it is replaced', async () => {
    const calls = mockFetch([
      ['PUT /api/admin/ldap', () => ({ status: 'ok' })],
      ['GET /api/admin/ldap', () => stored],
      ['GET /api/admin/groups', () => ({ items: [] })],
    ]);
    renderAdmin('ldap');
    expect(await screen.findByDisplayValue('dc1.example.com')).toBeInTheDocument();
    expect(screen.getByLabelText('Bind Password')).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Save LDAP settings' }));
    await waitFor(() => expect(sent(calls, 'PUT', '/api/admin/ldap')).toHaveLength(1));
    expect(sent(calls, 'PUT', '/api/admin/ldap')[0].body).toEqual({
      enabled: true,
      url: '',
      host: 'dc1.example.com',
      port: 636,
      useSsl: true,
      startTls: false,
      sslSkipVerify: false,
      caCert: '',
      timeoutSeconds: 10,
      bindDn: 'cn=svc,dc=example',
      bindPassword: '',
      userBaseDn: 'OU=Users,DC=example',
      userBaseDns: ['OU=A,DC=example'],
      userFilter: '(sAMAccountName=%s)',
      usernameAttribute: 'sAMAccountName',
      passwordConfigured: true,
      autoProvision: false,
      autoProvisionGroupIds: [],
    });

    // Reloaded after the save; then a new password goes out.
    await waitFor(() => expect(sent(calls, 'GET', '/api/admin/ldap').length).toBeGreaterThan(1));
    fireEvent.click(screen.getByRole('checkbox', { name: 'Update Bind Password' }));
    fireEvent.change(screen.getByLabelText('Bind Password'), { target: { value: 's3cret' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save LDAP settings' }));
    await waitFor(() => expect(sent(calls, 'PUT', '/api/admin/ldap')).toHaveLength(2));
    expect(sent(calls, 'PUT', '/api/admin/ldap')[1].body).toMatchObject({ bindPassword: 's3cret', passwordConfigured: true });
  });

  it('shows a failed connection test', async () => {
    mockFetch([
      ['POST /api/admin/ldap/test', () => new Response(JSON.stringify({ error: 'ldap_unreachable', detail: 'dial tcp: refused' }), { status: 502 })],
      ['GET /api/admin/ldap', () => stored],
      ['GET /api/admin/groups', () => ({ items: [] })],
    ]);
    renderAdmin('ldap');
    await screen.findByDisplayValue('dc1.example.com');
    fireEvent.click(screen.getByRole('button', { name: 'Test connection' }));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
  });

  it('says why a save failed instead of failing silently', async () => {
    const problem = { type: 'about:blank', title: 'Bad Request', status: 400, error: 'invalid_input', detail: 'ldap CA certificate: no PEM certificate found' };
    mockFetch([
      ['PUT /api/admin/ldap', () => new Response(JSON.stringify(problem), { status: 400 })],
      ['GET /api/admin/ldap', () => stored],
      ['GET /api/admin/groups', () => ({ items: [] })],
    ]);
    renderAdmin('ldap');
    await screen.findByDisplayValue('dc1.example.com');
    fireEvent.click(screen.getByRole('button', { name: 'Save LDAP settings' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('(ldap CA certificate: no PEM certificate found)');
    expect(screen.getByDisplayValue('dc1.example.com')).toBeInTheDocument();
  });
});

describe('AdminPage Azure AD', () => {
  it('saves without the stored client secret unless it is replaced', async () => {
    const calls = mockFetch([
      ['PUT /api/admin/azure-ad', () => ({ status: 'ok' })],
      ['GET /api/admin/azure-ad', () => ({ enabled: true, tenantId: 't-1', clientId: 'c-1', redirectUrl: 'https://oc/cb', passwordConfigured: true })],
    ]);
    renderAdmin('azure-ad');
    expect(await screen.findByDisplayValue('t-1')).toBeInTheDocument();
    expect(screen.getByLabelText('Client Secret')).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Save Azure AD settings' }));
    await waitFor(() => expect(sent(calls, 'PUT', '/api/admin/azure-ad')).toHaveLength(1));
    expect(sent(calls, 'PUT', '/api/admin/azure-ad')[0].body).toEqual({
      enabled: true,
      tenantId: 't-1',
      clientId: 'c-1',
      clientSecret: '',
      redirectUrl: 'https://oc/cb',
      passwordConfigured: true,
    });

    await waitFor(() => expect(sent(calls, 'GET', '/api/admin/azure-ad').length).toBeGreaterThan(1));
    fireEvent.click(screen.getByRole('checkbox', { name: 'Update Client Secret' }));
    fireEvent.change(screen.getByLabelText('Client Secret'), { target: { value: 'shh' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save Azure AD settings' }));
    await waitFor(() => expect(sent(calls, 'PUT', '/api/admin/azure-ad')).toHaveLength(2));
    expect(sent(calls, 'PUT', '/api/admin/azure-ad')[1].body).toMatchObject({ clientSecret: 'shh' });
  });
});

describe('AdminPage session settings', () => {
  it('saves the session timeout with the API key expiry policy', async () => {
    const calls = mockFetch([
      ['PUT /api/admin/session', () => ({ status: 'ok' })],
      ['GET /api/admin/session', () => ({ sessionMinutes: 60, apiKeyMaxDays: 90, apiKeyAllowNoExpiry: false })],
      ['GET /api/features', () => ({ features: {} })],
    ]);
    renderAdmin('session');
    const minutes = await screen.findByLabelText('Sign out after inactivity (minutes)');
    await waitFor(() => expect(minutes).toHaveValue(60));
    fireEvent.change(minutes, { target: { value: '30' } });
    fireEvent.click(screen.getAllByRole('button', { name: 'Save' })[0]);
    await waitFor(() => expect(sent(calls, 'PUT', '/api/admin/session')).toHaveLength(1));
    expect(sent(calls, 'PUT', '/api/admin/session')[0].body).toEqual({ sessionMinutes: 30, apiKeyMaxDays: 90, apiKeyAllowNoExpiry: false });
    // A save that worked says so, once, in the card that was saved (2.23.1; before, nothing).
    expect(await screen.findByRole('status')).toHaveTextContent('Saved.');
    expect(screen.getAllByRole('status')).toHaveLength(1);
  });

  it('says why a save failed, in the card whose Save was pressed', async () => {
    const problem = { type: 'about:blank', title: 'Bad Request', status: 400, error: 'invalid_input', detail: 'sessionMinutes must be a positive number' };
    mockFetch([
      ['PUT /api/admin/session', () => new Response(JSON.stringify(problem), { status: 400 })],
      ['GET /api/admin/session', () => ({ sessionMinutes: 60, apiKeyMaxDays: 90, apiKeyAllowNoExpiry: false })],
      ['GET /api/features', () => ({ features: {} })],
    ]);
    renderAdmin('session');
    await screen.findByLabelText('Sign out after inactivity (minutes)');
    fireEvent.click(screen.getAllByRole('button', { name: 'Save' })[0]);
    expect(await screen.findByRole('alert')).toHaveTextContent('A value was not accepted. (sessionMinutes must be a positive number)');
    expect(screen.getAllByRole('alert')).toHaveLength(1);
  });
});

describe('AdminPage customization', () => {
  it('uploads and removes the logo', async () => {
    const calls = mockFetch([
      ['POST /api/admin/customization/logo', () => ({ status: 'ok' })],
      ['DELETE /api/admin/customization/logo', () => ({ status: 'ok' })],
    ]);
    const view = renderAdmin('customization');
    const upload = screen.getByRole('button', { name: 'Upload logo' });
    expect(upload).toBeDisabled();
    const file = new File(['<svg/>'], 'logo.svg', { type: 'image/svg+xml' });
    fireEvent.change(view.container.querySelector('input[type="file"]')!, { target: { files: [file] } });
    expect(screen.getByText('logo.svg')).toBeInTheDocument();
    fireEvent.click(upload);
    expect(await screen.findByText('Logo uploaded successfully.')).toBeInTheDocument();
    const post = sent(calls, 'POST', '/api/admin/customization/logo');
    expect(post).toHaveLength(1);
    expect((post[0].body as FormData).get('file')).toBe(file);
    expect(screen.getByRole('img', { name: 'Organization logo' }).getAttribute('src')).toMatch(/^\/api\/customization\/logo\?ts=\d+$/);

    fireEvent.click(screen.getByRole('button', { name: 'Remove logo' }));
    expect(await screen.findByText('Logo removed successfully.')).toBeInTheDocument();
    expect(sent(calls, 'DELETE', '/api/admin/customization/logo')).toHaveLength(1);
    expect(screen.queryByRole('img', { name: 'Organization logo' })).toBeNull();
  });
});

describe('AdminPage clusters actions', () => {
  it('adds a token cluster and reloads the list', async () => {
    let items: unknown[] = [];
    const calls = mockFetch([
      [
        'POST /api/admin/clusters',
        () => {
          items = [{ id: 3, name: 'staging', method: 'token', server: 'https://s:6443', isActive: false }];
          return { id: 3 };
        },
      ],
      ['GET /api/admin/clusters', () => ({ items })],
    ]);
    renderAdmin('clusters');
    expect(await screen.findByText('No clusters saved yet. Add one below.')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'staging' } });
    fireEvent.change(screen.getByLabelText('Method'), { target: { value: 'token' } });
    fireEvent.change(screen.getByLabelText('API Server'), { target: { value: 'https://s:6443' } });
    fireEvent.change(screen.getByLabelText('Token'), { target: { value: 'tok' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save Cluster' }));
    expect(await screen.findByText('Cluster added.')).toBeInTheDocument();
    expect(sent(calls, 'POST', '/api/admin/clusters')[0].body).toEqual({
      name: 'staging',
      description: '',
      method: 'token',
      token: 'tok',
      server: 'https://s:6443',
    });
    expect(screen.getByText('staging')).toBeInTheDocument();
    expect(screen.getByLabelText('Name')).toHaveValue('');
  });

  it('sets a cluster as the default, and deletes one after confirming', async () => {
    vi.stubGlobal('confirm', () => true);
    let items = [
      { id: 7, name: 'prod', method: 'token', isActive: true },
      { id: 8, name: 'dev', method: 'kubeconfig', isActive: false },
    ];
    const calls = mockFetch([
      [
        'DELETE /api/admin/clusters/8',
        () => {
          items = items.filter((c) => c.id !== 8);
          return { status: 'ok' };
        },
      ],
      ['POST /api/admin/clusters/8/activate', () => ({ status: 'ok', name: 'dev' })],
      ['GET /api/admin/clusters', () => ({ items })],
    ]);
    renderAdmin('clusters');
    const row = (await screen.findByText('dev')).closest('div.rounded-lg') as HTMLElement;
    // The default cluster can't be deleted.
    const prodRow = screen.getByText('prod').closest('div.rounded-lg') as HTMLElement;
    expect(within(prodRow).getByRole('button', { name: 'Delete' })).toBeDisabled();

    fireEvent.click(within(row).getByRole('button', { name: /Set as default/ }));
    expect(await screen.findByText('dev is now the default cluster.')).toBeInTheDocument();
    expect(sent(calls, 'POST', '/api/admin/clusters/8/activate')).toHaveLength(1);

    fireEvent.click(within(row).getByRole('button', { name: /Delete/ }));
    await waitFor(() => expect(screen.queryByText('dev')).toBeNull());
    expect(sent(calls, 'DELETE', '/api/admin/clusters/8')).toHaveLength(1);
  });
});
