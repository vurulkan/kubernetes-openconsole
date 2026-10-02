import React, { useEffect, useState } from 'react';
import { Modal } from './ui';
import { SHORTCUTS_EVENT_NAME, dispatchOpenShortcuts } from '../hooks/useGlobalShortcuts';

// Rows normally render as a chord: keys separated by "then" (press one, then
// the next within the chord timeout). When the two keys are physical-position
// alternatives — [ matches the same key as ğ on a TR layout — set
// `join: 'or'` so the separator reflects "either key works".
type Row = { keys: string[]; description: string; join?: 'then' | 'or' };
type Group = { title: string; rows: Row[] };

const GROUPS: Group[] = [
  {
    title: 'Global',
    rows: [
      { keys: ['⌘', 'K'], description: 'Open command palette' },
      { keys: ['?'], description: 'Open this cheat sheet' },
      { keys: ['Esc'], description: 'Close the active modal / palette' },
    ],
  },
  {
    title: 'Navigate',
    rows: [
      { keys: ['g', 'd'], description: 'Go to Dashboard' },
      { keys: ['g', 'a'], description: 'Go to Admin (admins only)' },
    ],
  },
  {
    title: 'Theme',
    rows: [
      { keys: ['t', 'l'], description: 'Theme → Light' },
      { keys: ['t', 'd'], description: 'Theme → Dark' },
      { keys: ['t', 's'], description: 'Theme → System' },
    ],
  },
  {
    title: 'Dashboard',
    rows: [
      { keys: ['[', 'ğ'], join: 'or', description: 'Previous resource tab' },
      { keys: [']', 'ü'], join: 'or', description: 'Next resource tab' },
      { keys: ['r'], description: 'Refresh the current resource list' },
      { keys: ['/', '.'], join: 'or', description: 'Focus the search box' },
      { keys: ['n'], description: 'Focus the namespace filter' },
      { keys: ['e'], description: 'Toggle Live Events panel' },
      { keys: ['Esc'], description: 'Close Live Events panel (when open)' },
    ],
  },
  {
    title: 'Admin',
    rows: [
      { keys: ['[', 'ğ'], join: 'or', description: 'Previous sub-section' },
      { keys: [']', 'ü'], join: 'or', description: 'Next sub-section' },
    ],
  },
  {
    title: 'Log viewer',
    rows: [
      { keys: ['p'], description: 'Toggle pause' },
      { keys: ['w'], description: 'Toggle word wrap' },
    ],
  },
  {
    title: 'Scale modal',
    rows: [
      { keys: ['↑', '↓'], description: 'Replica ±1 (while input focused)' },
      { keys: ['⇧', '↑/↓'], description: 'Replica ±10 (while input focused)' },
    ],
  },
  {
    title: 'Command palette',
    rows: [
      { keys: ['↑', '↓'], description: 'Move selection' },
      { keys: ['↵'], description: 'Run selected command' },
      { keys: ['Esc'], description: 'Close' },
    ],
  },
];

export const openShortcutsHelp = dispatchOpenShortcuts;

export const ShortcutsHelp: React.FC = () => {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const handler = () => setOpen(true);
    window.addEventListener(SHORTCUTS_EVENT_NAME, handler as EventListener);
    return () => window.removeEventListener(SHORTCUTS_EVENT_NAME, handler as EventListener);
  }, []);

  return (
    <Modal
      open={open}
      onClose={() => setOpen(false)}
      title="Keyboard shortcuts"
      size="md"
    >
      <p className="mb-4 text-xs text-slate-500 dark:text-slate-400">
        Keys joined by <span className="font-medium">then</span> are chord
        sequences — press one, then the next within a second. Keys joined by
        <span className="font-medium"> or </span> are alternatives: either one
        works. The TR layout fallbacks (
        <kbd className="rounded border px-1 text-[10px] mx-0.5">ğ</kbd> for{' '}
        <kbd className="rounded border px-1 text-[10px] mx-0.5">[</kbd>,{' '}
        <kbd className="rounded border px-1 text-[10px] mx-0.5">ü</kbd> for{' '}
        <kbd className="rounded border px-1 text-[10px] mx-0.5">]</kbd>,{' '}
        <kbd className="rounded border px-1 text-[10px] mx-0.5">.</kbd> for{' '}
        <kbd className="rounded border px-1 text-[10px] mx-0.5">/</kbd>) are
        matched by physical key position. Shortcuts never fire while typing in
        an input.
      </p>

      <div className="flex flex-col gap-5">
        {GROUPS.map((group) => (
          <div key={group.title}>
            <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500 dark:text-slate-400">
              {group.title}
            </h3>
            <ul className="flex flex-col divide-y divide-slate-100 rounded-lg border border-slate-200 bg-slate-50/60 dark:divide-slate-800 dark:border-slate-800 dark:bg-slate-800/40">
              {group.rows.map((row, idx) => (
                <li
                  key={idx}
                  className="flex items-center justify-between gap-4 px-3 py-2"
                >
                  <span className="text-sm text-slate-700 dark:text-slate-200">
                    {row.description}
                  </span>
                  <span className="flex items-center gap-1">
                    {row.keys.map((k, i) => (
                      <React.Fragment key={i}>
                        {i > 0 && (
                          <span className="text-[10px] text-slate-400 dark:text-slate-500">
                            {row.join === 'or' ? 'or' : 'then'}
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
