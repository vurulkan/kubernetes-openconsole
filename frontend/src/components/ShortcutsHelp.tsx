import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Modal } from './ui';
import { SHORTCUTS_EVENT_NAME, dispatchOpenShortcuts } from '../hooks/useGlobalShortcuts';

// Rows normally render as a chord: keys separated by "then" (press one, then
// the next within the chord timeout). When the two keys are physical-position
// alternatives — [ matches the same key as ğ on a TR layout — set
// `join: 'or'` so the separator reflects "either key works".
type Row = { keys: string[]; descKey: string; join?: 'then' | 'or' };
type Group = { titleKey: string; rows: Row[] };

const GROUPS: Group[] = [
  { titleKey: 'global', rows: [
    { keys: ['⌘', 'K'], descKey: 'openPalette' },
    { keys: ['?'], descKey: 'openHelp' },
    { keys: ['Esc'], descKey: 'closeModal' },
  ]},
  { titleKey: 'navigate', rows: [
    { keys: ['g', 'd'], descKey: 'goDashboard' },
    { keys: ['g', 'a'], descKey: 'goAdmin' },
  ]},
  { titleKey: 'theme', rows: [
    { keys: ['t', 'l'], descKey: 'themeLight' },
    { keys: ['t', 'd'], descKey: 'themeDark' },
    { keys: ['t', 's'], descKey: 'themeSystem' },
  ]},
  { titleKey: 'dashboard', rows: [
    { keys: ['[', 'ğ'], join: 'or', descKey: 'prevTab' },
    { keys: [']', 'ü'], join: 'or', descKey: 'nextTab' },
    { keys: ['r'], descKey: 'refresh' },
    { keys: ['/', '.'], join: 'or', descKey: 'focusSearch' },
    { keys: ['n'], descKey: 'focusNamespace' },
    { keys: ['e'], descKey: 'toggleEvents' },
    { keys: ['Esc'], descKey: 'closeEvents' },
    { keys: ['c'], descKey: 'openCluster' },
    { keys: ['v'], descKey: 'openViews' },
  ]},
  { titleKey: 'cluster', rows: [
    { keys: ['1', '9'], join: 'or', descKey: 'pickByIndex' },
    { keys: ['↑', '↓'], join: 'or', descKey: 'moveFocus' },
    { keys: ['↵'], descKey: 'activate' },
    { keys: ['Esc'], descKey: 'closeNoSwitch' },
  ]},
  { titleKey: 'admin', rows: [
    { keys: ['[', 'ğ'], join: 'or', descKey: 'prevSub' },
    { keys: [']', 'ü'], join: 'or', descKey: 'nextSub' },
  ]},
  { titleKey: 'tables', rows: [
    { keys: ['j', 'k'], join: 'or', descKey: 'rowDownUp' },
    { keys: ['↵'], descKey: 'rowOpen' },
    { keys: ['d'], descKey: 'rowDelete' },
    { keys: ['n', 'p'], join: 'or', descKey: 'pageNextPrev' },
  ]},
  { titleKey: 'logs', rows: [
    { keys: ['p'], descKey: 'togglePause' },
    { keys: ['w'], descKey: 'toggleWrap' },
  ]},
  { titleKey: 'scale', rows: [
    { keys: ['↑', '↓'], descKey: 'replPlusMinus' },
    { keys: ['⇧', '↑/↓'], descKey: 'replShift' },
  ]},
  { titleKey: 'palette', rows: [
    { keys: ['↑', '↓'], descKey: 'moveSel' },
    { keys: ['↵'], descKey: 'runSel' },
    { keys: ['Esc'], descKey: 'closeModal' },
  ]},
];

export const openShortcutsHelp = dispatchOpenShortcuts;

export const ShortcutsHelp: React.FC = () => {
  const { t } = useTranslation();
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
        {GROUPS.map((group) => (
          <div key={group.titleKey}>
            <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500 dark:text-slate-400">
              {t(`shortcuts.groups.${group.titleKey}`)}
            </h3>
            <ul className="flex flex-col divide-y divide-slate-100 rounded-lg border border-slate-200 bg-slate-50/60 dark:divide-slate-800 dark:border-slate-800 dark:bg-slate-800/40">
              {group.rows.map((row, idx) => (
                <li
                  key={idx}
                  className="flex items-center justify-between gap-4 px-3 py-2"
                >
                  <span className="text-sm text-slate-700 dark:text-slate-200">
                    {t(`shortcuts.rows.${row.descKey}`)}
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
