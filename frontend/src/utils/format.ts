// Small display formatters shared by admin tables.

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB'];

/** 1536 → "1.5 KB". Negative / non-finite input renders as a dash. */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '—';
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value >= 10 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${UNITS[unit]}`;
}

/** 83_000 → "1m 23s"; 3_725_000 → "1h 2m". */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '—';
  const total = Math.round(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

// Kubernetes quantities. CPU in millicores, memory in bytes; unparseable → NaN.
const MEM_SUFFIX: Record<string, number> = {
  Ki: 2 ** 10, Mi: 2 ** 20, Gi: 2 ** 30, Ti: 2 ** 40,
  k: 1e3, K: 1e3, M: 1e6, G: 1e9, T: 1e12, m: 1e-3,
};

/** "500m" → 500, "1" → 1000, "0.25" → 250. */
export function parseCpu(q?: string): number {
  if (!q) return NaN;
  if (q.endsWith('m')) return Number(q.slice(0, -1));
  if (q.endsWith('n')) return Number(q.slice(0, -1)) / 1e6;
  return Number(q) * 1000;
}

/** "512Mi" → 536870912, "1G" → 1e9, "1e3" → 1000. */
export function parseMem(q?: string): number {
  if (!q) return NaN;
  const m = /^([0-9.eE+-]+?)([KMGT]i|[kKMGTm])?$/.exec(q);
  if (!m) return NaN;
  return Number(m[1]) * (m[2] ? MEM_SUFFIX[m[2]] : 1);
}

/** 120 → "120m", 1500 → "1.5" (cores, as Kubernetes writes them). */
export function formatCpu(milli: number): string {
  if (!Number.isFinite(milli) || milli < 0) return '—';
  if (milli < 1000) return `${Math.round(milli)}m`;
  return `${+(milli / 1000).toFixed(milli < 10_000 ? 2 : 1)}`;
}

/** Bytes in Kubernetes binary units: 432013312 → "412Mi", 1.5 GiB → "1.5Gi". */
export function formatMem(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '—';
  const units: Array<[string, number]> = [['Gi', 2 ** 30], ['Mi', 2 ** 20], ['Ki', 2 ** 10]];
  for (const [u, size] of units) {
    if (bytes >= size) {
      const v = bytes / size;
      return `${v >= 10 ? Math.round(v) : +v.toFixed(1)}${u}`;
    }
  }
  return `${bytes}B`;
}
