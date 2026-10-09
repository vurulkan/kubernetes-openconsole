import { describe, expect, it } from 'vitest';
import { formatBytes, formatDuration } from './format';

describe('formatBytes', () => {
  it.each([
    [0, '0 B'],
    [512, '512 B'],
    [1536, '1.5 KB'],
    [10 * 1024, '10 KB'],
    [5 * 1024 * 1024, '5.0 MB'],
    [3 * 1024 ** 3, '3.0 GB'],
    [-1, '—'],
    [Number.NaN, '—'],
  ])('%s → %s', (input, out) => {
    expect(formatBytes(input)).toBe(out);
  });
});

describe('formatDuration', () => {
  it.each([
    [0, '0s'],
    [59_000, '59s'],
    [83_000, '1m 23s'],
    [3_725_000, '1h 2m'],
    [-5, '—'],
  ])('%s ms → %s', (input, out) => {
    expect(formatDuration(input)).toBe(out);
  });
});
