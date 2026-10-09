import { describe, expect, it } from 'vitest';
import i18n from './i18n';

type Dict = Record<string, unknown>;

function flatten(obj: Dict, prefix = ''): string[] {
  return Object.entries(obj).flatMap(([k, v]) =>
    v && typeof v === 'object' ? flatten(v as Dict, `${prefix}${k}.`) : [`${prefix}${k}`],
  );
}

const en = i18n.getResourceBundle('en', 'translation') as Dict;
const tr = i18n.getResourceBundle('tr', 'translation') as Dict;

// i18next plural forms: a key used as t('x', {count}) resolves x_one / x_other.
const has = (dict: Dict, key: string) => {
  const get = (k: string) => k.split('.').reduce<unknown>((a, p) => (a as Dict | undefined)?.[p], dict);
  return get(key) !== undefined || get(`${key}_one`) !== undefined || get(`${key}_other`) !== undefined;
};

describe('i18n dictionaries', () => {
  it('EN and TR define exactly the same keys', () => {
    const enKeys = new Set(flatten(en));
    const trKeys = new Set(flatten(tr));
    expect([...enKeys].filter((k) => !trKeys.has(k)), 'missing in TR').toEqual([]);
    expect([...trKeys].filter((k) => !enKeys.has(k)), 'missing in EN').toEqual([]);
  });

  it('every literal key used in the source exists in both languages', () => {
    const files = import.meta.glob(['./**/*.tsx', './**/*.ts', '!./**/*.test.*', '!./i18n.ts'], {
      query: '?raw',
      import: 'default',
      eager: true,
    }) as Record<string, string>;
    const missing: string[] = [];
    for (const [file, src] of Object.entries(files)) {
      for (const m of src.matchAll(/\b(?:t|tr)\(\s*'([a-zA-Z0-9_.]+)'/g)) {
        const key = m[1];
        if (!key.includes('.')) continue; // not an i18n key
        for (const [lang, dict] of [['en', en], ['tr', tr]] as const) {
          if (!has(dict, key)) missing.push(`${lang}: ${key} (${file})`);
        }
      }
    }
    expect(missing).toEqual([]);
  });
});
