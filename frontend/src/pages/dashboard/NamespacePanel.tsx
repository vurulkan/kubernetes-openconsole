import React from 'react';
import { useTranslation } from 'react-i18next';

/** The Dashboard's side panel: the namespaces the user can see, with a filter box (n focuses it). */
export const NamespacePanel: React.FC<{
  namespaces: string[];
  selected: string | null;
  onSelect: (namespace: string) => void;
  search: string;
  onSearch: (text: string) => void;
}> = ({ namespaces, selected, onSelect, search, onSearch }) => {
  const { t } = useTranslation();
  const filtered = search
    ? namespaces.filter((ns) => ns.toLowerCase().includes(search.trim().toLowerCase()))
    : namespaces;
  return (
    <div className="flex h-full flex-col gap-3 p-3">
      <input
        type="text"
        value={search}
        onChange={(e) => onSearch(e.target.value)}
        placeholder={t('dashboard.namespacesSearch')}
        data-shortcut="namespace-search"
        className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 dark:placeholder:text-slate-500 dark:text-slate-100 focus:border-brand-500 focus:outline-none focus:ring-4 focus:ring-brand-500/15"
      />
      <div className="scrollbar-thin flex flex-col gap-0.5 overflow-auto pr-1">
        {filtered.length === 0 && (
          <p className="rounded-md px-3 py-2 text-xs text-slate-500 dark:text-slate-400">
            {namespaces.length === 0 ? t('dashboard.namespacesEmpty') : t('dashboard.namespacesNoMatch')}
          </p>
        )}
        {filtered.map((ns) => {
          const active = selected === ns;
          return (
            <button
              key={ns}
              onClick={() => onSelect(ns)}
              className={`group flex items-center gap-2 rounded-lg px-3 py-2 text-left text-sm transition-colors ${
                active
                  ? 'bg-brand-50 dark:bg-brand-500/15 font-medium text-brand-700 dark:text-brand-200 ring-1 ring-inset ring-brand-200 dark:ring-brand-500/30'
                  : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 dark:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100 dark:text-slate-100'
              }`}
            >
              <span
                className={`h-1.5 w-1.5 shrink-0 rounded-full transition-colors ${
                  active ? 'bg-emerald-500' : 'bg-slate-300 group-hover:bg-slate-500'
                }`}
              />
              <span className="truncate font-mono text-[12px]">{ns}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
};
