import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Modal } from './ui';
import { SHORTCUTS_EVENT_NAME, dispatchOpenShortcuts } from '../hooks/useGlobalShortcuts';
import shortcuts from '../shortcuts.json';

// The cheat sheet's rows live in shortcuts.json, with their English and
// Turkish text, so the docs site's Keyboard shortcuts page is generated from
// the same file (backend/cmd/docgen). Rows render as a chord: keys separated
// by "then" (press one, then the next within the chord timeout). When the
// keys are physical-position alternatives — [ matches the same key as ğ on a
// TR layout — `join: 'or'` shows "either key works". The bindings themselves
// live in hooks/useGlobalShortcuts.ts and the components.
type Text = { en: string; tr: string };
type Row = { keys: string[]; text: Text; join?: string };
type Group = { id: string; title: Text; rows: Row[] };

export const SHORTCUT_GROUPS = shortcuts as Group[];

export const openShortcutsHelp = dispatchOpenShortcuts;

export const ShortcutsHelp: React.FC = () => {
  const { t, i18n } = useTranslation();
  const lang: keyof Text = i18n.language.startsWith('tr') ? 'tr' : 'en';
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const handler = () => setOpen(true);
    window.addEventListener(SHORTCUTS_EVENT_NAME, handler as EventListener);
    return () => window.removeEventListener(SHORTCUTS_EVENT_NAME, handler as EventListener);
  }, []);

  const thenLabel = t('shortcuts.then');
  const orLabel = t('shortcuts.or');

  return (
    <Modal
      open={open}
      onClose={() => setOpen(false)}
      title={t('shortcuts.title')}
      size="md"
    >
      <p className="mb-4 text-xs text-slate-500 dark:text-slate-400">
        {t('shortcuts.explain', {
          then: thenLabel,
          or: orLabel,
          g1: 'ğ', g2: '[',
          u1: 'ü', u2: ']',
          d1: '.', d2: '/',
        })}
      </p>

      <div className="flex flex-col gap-5">
        {SHORTCUT_GROUPS.map((group) => (
          <div key={group.id}>
            <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500 dark:text-slate-400">
              {group.title[lang]}
            </h3>
            <ul className="flex flex-col divide-y divide-slate-100 rounded-lg border border-slate-200 bg-slate-50/60 dark:divide-slate-800 dark:border-slate-800 dark:bg-slate-800/40">
              {group.rows.map((row, idx) => (
                <li
                  key={idx}
                  className="flex items-center justify-between gap-4 px-3 py-2"
                >
                  <span className="text-sm text-slate-700 dark:text-slate-200">
                    {row.text[lang]}
                  </span>
                  <span className="flex items-center gap-1">
                    {row.keys.map((k, i) => (
                      <React.Fragment key={i}>
                        {i > 0 && (
                          <span className="text-[10px] text-slate-500 dark:text-slate-400">
                            {row.join === 'or' ? orLabel : thenLabel}
                          </span>
                        )}
                        <kbd className="rounded-md border border-slate-200 bg-white px-1.5 py-0.5 font-mono text-[11px] font-medium text-slate-700 shadow-sm dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200">
                          {k}
                        </kbd>
                      </React.Fragment>
                    ))}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </Modal>
  );
};

export default ShortcutsHelp;
