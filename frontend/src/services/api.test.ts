import { afterEach, describe, expect, it, vi } from 'vitest';
import { getMe, tokenExpiresAt } from './api';

const jwt = (payload: object) => `h.${btoa(JSON.stringify(payload)).replace(/=+$/, '')}.s`;

describe('session end', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    localStorage.clear();
  });

  const stub = (status: number) => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(status === 200 ? '{}' : '', { status })));
    const assign = vi.fn();
    vi.stubGlobal('location', { ...window.location, pathname: '/', assign });
    return assign;
  };

  it('a 401 drops the token and goes to the sign-in page', async () => {
    localStorage.setItem('authToken', 'old');
    const assign = stub(401);
    await expect(getMe()).rejects.toThrow();
    expect(localStorage.getItem('authToken')).toBeNull();
    expect(assign).toHaveBeenCalledWith('/login?expired=1');
  });

  it('a 403 keeps the session', async () => {
    localStorage.setItem('authToken', 'old');
    const assign = stub(403);
    await expect(getMe()).rejects.toThrow();
    expect(localStorage.getItem('authToken')).toBe('old');
    expect(assign).not.toHaveBeenCalled();
  });

  it('reads the expiry from the token', () => {
    localStorage.setItem('authToken', jwt({ exp: 1700000000 }));
    expect(tokenExpiresAt()).toBe(1700000000000);
    localStorage.setItem('authToken', 'not-a-jwt');
    expect(tokenExpiresAt()).toBeNull();
  });
});

describe('the tab keeps its cluster', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
    localStorage.clear();
  });

  it('sends the cluster the first response named, so another tab switching does not move this one', async () => {
    localStorage.setItem('authToken', 't');
    const sent: Array<string | null> = [];
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => {
      sent.push(new Headers(init?.headers).get('X-OpenConsole-Cluster'));
      return new Response('{}', { status: 200, headers: { 'X-OpenConsole-Cluster': '2' } });
    }));
    const api = await import('./api');
    await api.getMe();
    await api.listNamespaces();
    expect(sent).toEqual([null, '2']);
    expect(api.tabClusterId()).toBe(2);
  });

  it('tells other tabs about a cluster pick', async () => {
    localStorage.setItem('authToken', 't');
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ status: 'ok', clusterId: 3, name: 'prod' }), { status: 200 })));
    const api = await import('./api');
    await api.selectCluster(3);
    expect(JSON.parse(localStorage.getItem(api.CLUSTER_PICK_KEY) ?? '{}')).toMatchObject({ id: 3, name: 'prod' });
  });
});

describe('error messages', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    localStorage.clear();
  });
  const fail = (body: string, status = 403) =>
    vi.stubGlobal('fetch', vi.fn(async () => new Response(body, { status, headers: { 'Content-Type': 'application/json' } })));

  it('shows the reason, not the JSON body', async () => {
    fail('{"error":"forbidden"}');
    await expect(getMe()).rejects.toThrow(/^forbidden$/);
  });

  it('says in words when the cluster refused a read', async () => {
    fail('{"error":"cluster_forbidden"}');
    await expect(getMe()).rejects.toThrow(/ClusterRole/);
  });
});
