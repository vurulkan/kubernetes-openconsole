// Human age helpers for Kubernetes-style creation timestamps.
// Both helpers tolerate missing / unparseable input and return a sensible
// fallback instead of throwing — Dashboard renders these inside tight rows
// where crashing on a bad value is far worse than showing a dash.

const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;
const MIN_MS = 60 * 1000;

function compactSuffix(createdAt?: string): string {
  if (!createdAt) return '—';
  const t = Date.parse(createdAt);
  if (Number.isNaN(t)) return '—';
  const diff = Date.now() - t;
  if (diff < MIN_MS) return `${Math.max(0, Math.floor(diff / 1000))}s`;
  if (diff < HOUR_MS) return `${Math.floor(diff / MIN_MS)}m`;
  if (diff < DAY_MS) return `${Math.floor(diff / HOUR_MS)}h`;
  return `${Math.floor(diff / DAY_MS)}d`;
}

/** Full timestamp followed by compact age in parentheses, e.g.
 *  `2026-07-16T17:43:35Z (77d)` — used on card view. */
export function formatAge(createdAt?: string): string {
  if (!createdAt) return 'Created time unknown';
  return `${createdAt} (${compactSuffix(createdAt)})`;
}

/** Compact-only age for dense table/list rows. */
export function ageShort(createdAt?: string): string {
  return compactSuffix(createdAt);
}
