import { describe, expect, it } from 'vitest';
import shortcuts from './shortcuts.json';

// shortcuts.json feeds the cheat sheet (ShortcutsHelp) and the docs site's
// Keyboard shortcuts page (backend/cmd/docgen): every row needs keys and
// both languages.
describe('shortcuts.json', () => {
  it('has keys and EN + TR text on every group and row', () => {
    for (const g of shortcuts) {
      expect(g.id).toBeTruthy();
      expect(g.title.en && g.title.tr).toBeTruthy();
      for (const r of g.rows) {
        expect(r.keys.length).toBeGreaterThan(0);
        expect(r.text.en && r.text.tr, JSON.stringify(r)).toBeTruthy();
        expect(['then', 'or', undefined]).toContain((r as { join?: string }).join);
      }
    }
  });
});
