import { describe, expect, it } from 'vitest';

// UI text goes through i18n so a Turkish user never meets English. This scan
// catches the common slips: an English label, title, placeholder or alt in
// JSX, a sentence as JSX text, and an English fallback after || / ?? / ?:.
// Technical strings (names of things, examples) are listed in ALLOWED.

const ALLOWED = new Set([
  'Kubernetes OpenConsole', // product name
  'Kubernetes',
  'Prometheus',
  'Kubelet',
  'CPU',
  'URL',
  'X-Scope-OrgID',
  'Admin API', // the name of a key scope
  'Unnamed', // a Kubernetes object without a name (never happens)
  'Auto (bash → ash → sh)', // a value list of shells
]);

const sources = import.meta.glob<string>(['./**/*.tsx', '!./**/*.test.tsx'], {
  query: '?raw',
  import: 'default',
  eager: true,
});

const prose = (v: string) => /[A-Za-z]{2,}/.test(v) && /^[A-Z]/.test(v) && !ALLOWED.has(v);

const findings = ([path, text]: [string, string]): string[] => {
  const out: string[] = [];
  text
    .split('\n')
    .forEach((line, i) => {
      const at = `${path}:${i + 1}`;
      const code = line.trim();
      if (code.startsWith('//') || code.startsWith('*') || code.startsWith('import')) return;
      for (const m of line.matchAll(/\b(aria-label|title|placeholder|label|alt|noOptionsText)="([^"]+)"/g)) {
        if (prose(m[2])) out.push(`${at} ${m[1]}="${m[2]}"`);
      }
      for (const m of line.matchAll(/(?:\|\||\?\?|\?|:)\s*'([^']+)'/g)) {
        if (prose(m[1]) && /\s/.test(m[1])) out.push(`${at} '${m[1]}'`);
      }
      // A JSX text line: words only, no code (imports end with a comma).
      if (/^[A-Z][A-Za-z'’ ]*[a-z][A-Za-z'’ .…:?!]*$/.test(code) && !ALLOWED.has(code)) out.push(`${at} ${code}`);
      for (const m of line.matchAll(/(?<!=)>\s*([A-Z][a-z]+(?: [A-Za-z'’.…]+)*[.…:?]?)\s*</g)) {
        if (prose(m[1])) out.push(`${at} >${m[1]}<`);
      }
    });
  return out;
};

describe('UI text', () => {
  it('has no hard-coded English in the components', () => {
    expect(Object.keys(sources).length).toBeGreaterThan(50);
    expect(Object.entries(sources).flatMap(findings)).toEqual([]);
  });
});
