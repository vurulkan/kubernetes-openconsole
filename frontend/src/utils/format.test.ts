import { describe, expect, it } from 'vitest';
import { formatBytes, formatCpu, formatDuration, formatMem, parseCpu, parseMem } from './format';

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

describe('Kubernetes quantities', () => {
  it.each([
    ['500m', 500],
    ['1', 1000],
    ['0.25', 250],
    ['2500000n', 2.5],
    ['', NaN],
  ])('cpu %s → %s', (q, out) => expect(parseCpu(q)).toBe(out));

  it.each([
    ['512Mi', 512 * 2 ** 20],
    ['1Gi', 2 ** 30],
    ['1G', 1e9],
    ['128974848', 128974848],
    ['1e3', 1000],
    ['abc', NaN],
  ])('memory %s → %s', (q, out) => expect(parseMem(q)).toBe(out));

  it.each([
    [120, '120m'],
    [1500, '1.5'],
    [12_000, '12'],
    [-1, '—'],
  ])('formatCpu %s → %s', (m, out) => expect(formatCpu(m)).toBe(out));

  it.each([
    [432013312, '412Mi'],
    [1.5 * 2 ** 30, '1.5Gi'],
    [512, '512B'],
    [NaN, '—'],
  ])('formatMem %s → %s', (b, out) => expect(formatMem(b)).toBe(out));
});
