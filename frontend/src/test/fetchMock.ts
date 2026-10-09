import { vi } from 'vitest';

type Handler = (url: string, init?: RequestInit) => unknown;

/**
 * Replaces fetch with a router: the first matcher whose pattern is found in
 * "METHOD url" answers with JSON (or throws to simulate an error status).
 */
export function mockFetch(routes: Array<[string, Handler]>) {
  const calls: Array<{ method: string; url: string; body?: unknown }> = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? 'GET').toUpperCase();
    calls.push({ method, url, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    const route = routes.find(([pattern]) => `${method} ${url}`.includes(pattern));
    if (!route) return new Response(JSON.stringify({ error: 'unmocked ' + method + ' ' + url }), { status: 404 });
    const data = route[1](url, init);
    if (data instanceof Response) return data;
    return new Response(JSON.stringify(data), { status: 200, headers: { 'Content-Type': 'application/json' } });
  });
  vi.stubGlobal('fetch', fn);
  return calls;
}
