import '@testing-library/jest-dom/vitest';
import { afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';

// Node >= 25 defines its own global localStorage getter, which shadows
// jsdom's and returns undefined without --localstorage-file. Install an
// in-memory Storage in that case so app code that calls localStorage
// directly behaves as in a browser (CI's Node 20 never needs this).
if (typeof globalThis.localStorage === 'undefined' || globalThis.localStorage === null) {
  const data = new Map<string, string>();
  const storage: Storage = {
    get length() {
      return data.size;
    },
    clear: () => data.clear(),
    getItem: (k) => (data.has(k) ? (data.get(k) as string) : null),
    key: (i) => Array.from(data.keys())[i] ?? null,
    removeItem: (k) => void data.delete(k),
    setItem: (k, v) => void data.set(k, String(v)),
  };
  Object.defineProperty(globalThis, 'localStorage', { value: storage, configurable: true, writable: true });
}

// jsdom has no canvas; axe-core probes it. Report "unsupported" quietly.
HTMLCanvasElement.prototype.getContext = (() => null) as unknown as HTMLCanvasElement['getContext'];

await import('../i18n');

afterEach(() => {
  cleanup();
  localStorage.clear();
});
