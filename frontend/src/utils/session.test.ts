import { afterEach, describe, expect, it } from 'vitest';
import { isIdle, noteActivity } from './session';

describe('inactivity timeout', () => {
  afterEach(() => localStorage.clear());

  it('is idle only after the timeout without activity', () => {
    const t0 = Date.now() + 60_000; // later than anything noted while the module loaded
    noteActivity(t0);
    expect(isIdle(60, t0 + 59_000)).toBe(false);
    expect(isIdle(60, t0 + 60_000)).toBe(true);
    noteActivity(t0 + 30_000);
    expect(isIdle(60, t0 + 60_000)).toBe(false);
  });

  it('counts activity in another tab (one session for all tabs)', () => {
    const t0 = Date.now() + 120_000;
    noteActivity(t0);
    localStorage.setItem('sessionActivity', String(t0 + 50_000)); // the other tab
    expect(isIdle(60, t0 + 70_000)).toBe(false);
    expect(isIdle(60, t0 + 110_000)).toBe(true);
  });
});
