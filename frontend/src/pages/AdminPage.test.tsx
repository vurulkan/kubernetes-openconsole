import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

vi.mock('../components/Layout', () => ({ default: ({ children }: { children: React.ReactNode }) => <main>{children}</main> }));
import AdminPage from './AdminPage';
import { mockFetch } from '../test/fetchMock';
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
