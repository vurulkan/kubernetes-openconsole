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
