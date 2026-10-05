import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Bookmark, Check, Plus, Trash2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Button } from './ui';
import { SAVED_VIEWS_EVENT_NAME } from '../hooks/useGlobalShortcuts';

export type SavedView = {
  id: string;
  name: string;
  namespace: string | null;
  tab: string;
  search: string;
  viewMode: 'card' | 'list';
};

type Props = {
  current: Omit<SavedView, 'id' | 'name'>;
  onRestore: (view: SavedView) => void;
};

const STORAGE_KEY = 'dashboardSavedViews';

function load(): SavedView[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function save(views: SavedView[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(views));
  } catch {
    /* ignore quota */
  }
}

/**
 * Tiny dropdown that stores Dashboard filter state (ns + tab + search +
 * view mode) under a name. Lets the operator jump between contexts like
 * "prod payments / pods / label:app=api" or "staging / deployments /
 * label:tier=front" without retyping anything.
 */
const SavedViewsMenu: React.FC<Props> = ({ current, onRestore }) => {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [views, setViews] = useState<SavedView[]>(() => load());
  const [naming, setNaming] = useState(false);
  const [draftName, setDraftName] = useState('');
  const [focusedIdx, setFocusedIdx] = useState(0);
  const buttonRef = useRef<HTMLDivElement | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const [pos, setPos] = useState<{ top: number; right: number } | null>(null);

  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => {
      const t = e.target as Node;
      if (buttonRef.current?.contains(t)) return;
      if (menuRef.current?.contains(t)) return;
      setOpen(false);
      setNaming(false);
      setDraftName('');
    };
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, [open]);

  useLayoutEffect(() => {
    if (!open || !buttonRef.current) return;
    const r = buttonRef.current.getBoundingClientRect();
    setPos({ top: r.bottom + 6, right: window.innerWidth - r.right });
  }, [open]);

  // Global 'v' opens the menu. Nothing to do when there are no views yet,
  // except still open the menu so the "Save current view" footer is reachable
  // from the keyboard without a mouse.
  useEffect(() => {
    const handler = () => {
      setOpen(true);
      setFocusedIdx(0);
      setNaming(false);
    };
    window.addEventListener(SAVED_VIEWS_EVENT_NAME, handler as EventListener);
    return () => window.removeEventListener(SAVED_VIEWS_EVENT_NAME, handler as EventListener);
  }, []);

  // In-menu keyboard: 1..9 picks by index, arrows move focus, Enter commits,
  // Esc closes. Suspended while the "name this view" input is open so typing
  // '1' into a view name doesn't restore a view.
  useEffect(() => {
    if (!open || naming) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        setOpen(false);
        return;
      }
      if (views.length === 0) return;
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setFocusedIdx((i) => (i + 1) % views.length);
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        setFocusedIdx((i) => (i - 1 + views.length) % views.length);
        return;
      }
      if (e.key === 'Enter') {
        e.preventDefault();
        const target = views[focusedIdx];
        if (target) {
          onRestore(target);
          setOpen(false);
        }
        return;
      }
      if (/^[1-9]$/.test(e.key)) {
        const idx = Number(e.key) - 1;
        if (idx < views.length) {
          e.preventDefault();
          onRestore(views[idx]);
          setOpen(false);
        }
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, naming, views, focusedIdx, onRestore]);

  const commit = (next: SavedView[]) => {
    setViews(next);
    save(next);
  };

  const handleSave = () => {
    const name = draftName.trim();
    if (!name) return;
    const next: SavedView[] = [
      ...views.filter((v) => v.name !== name),
      {
        id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
        name,
        namespace: current.namespace,
        tab: current.tab,
        search: current.search,
        viewMode: current.viewMode,
      },
    ];
    commit(next);
    setDraftName('');
    setNaming(false);
  };

  const isCurrent = (v: SavedView) =>
    v.namespace === current.namespace &&
    v.tab === current.tab &&
    v.search === current.search &&
    v.viewMode === current.viewMode;

  const activeMatch = useMemo(() => views.find((v) => isCurrent(v))?.id, [views, current]);

  return (
    <>
      <div ref={buttonRef} className="inline-flex">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setOpen((v) => !v)}
          title={t('dashboard.views.title')}
        >
          <Bookmark size={14} />
          {t('dashboard.views.button')}
          {views.length > 0 && (
            <span className="ml-1 rounded bg-slate-100 px-1 text-[10px] font-mono text-slate-500 dark:bg-slate-800 dark:text-slate-400">
              {views.length}
            </span>
          )}
        </Button>
      </div>
      {open && pos && createPortal(
        <div
          ref={menuRef}
          className="fixed z-50 w-72 overflow-hidden rounded-lg border border-slate-200 bg-white shadow-elevated dark:border-slate-800 dark:bg-slate-900"
          style={{ top: pos.top, right: pos.right }}
        >
          <div className="border-b border-slate-100 px-3 py-2 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500 dark:border-slate-800/70 dark:text-slate-400">
            {t('dashboard.views.title')}
          </div>
          <ul className="max-h-72 overflow-auto">
            {views.length === 0 && (
              <li className="px-3 py-3 text-xs text-slate-400 dark:text-slate-500">
                {t('dashboard.views.empty')}
              </li>
            )}
            {views.map((v, idx) => (
              <li
                key={v.id}
                className={`group flex items-center justify-between gap-2 px-2 py-1 ${
                  focusedIdx === idx ? 'bg-slate-100 dark:bg-slate-800/80' : 'hover:bg-slate-50 dark:hover:bg-slate-800/60'
                }`}
                onMouseEnter={() => setFocusedIdx(idx)}
              >
                <button
                  type="button"
                  onClick={() => {
                    onRestore(v);
                    setOpen(false);
                  }}
                  className="flex min-w-0 flex-1 items-center gap-2 rounded px-1 py-1 text-left"
                >
                  <span className="flex h-4 w-4 shrink-0 items-center justify-center">
                    {activeMatch === v.id && <Check size={12} className="text-brand-500" />}
                  </span>
                  {idx < 9 && (
                    <kbd className="shrink-0 rounded border border-slate-200 bg-white px-1 text-[9px] font-mono text-slate-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400">
                      {idx + 1}
                    </kbd>
                  )}
                  <div className="min-w-0">
                    <div className="truncate text-xs font-medium text-slate-800 dark:text-slate-100">
                      {v.name}
                    </div>
                    <div className="truncate text-[10px] text-slate-500 dark:text-slate-400">
                      {v.namespace ? `${v.namespace}/${v.tab}` : v.tab}
                      {v.search ? ` · ${v.search}` : ''}
                    </div>
                  </div>
                </button>
                <button
                  type="button"
                  onClick={() => commit(views.filter((x) => x.id !== v.id))}
                  className="rounded p-1 text-slate-300 opacity-0 transition-opacity hover:text-rose-600 group-hover:opacity-100"
                  aria-label={`Delete view ${v.name}`}
                >
                  <Trash2 size={12} />
                </button>
              </li>
            ))}
          </ul>
          <div className="border-t border-slate-100 p-2 dark:border-slate-800/70">
            {!naming ? (
              <button
                type="button"
                onClick={() => setNaming(true)}
                className="flex w-full items-center gap-1.5 rounded px-2 py-1.5 text-xs text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-800"
              >
                <Plus size={12} />
                {t('dashboard.views.save')}
              </button>
            ) : (
              <form
                className="flex items-center gap-1"
                onSubmit={(e) => {
                  e.preventDefault();
                  handleSave();
                }}
              >
                <input
                  autoFocus
                  value={draftName}
                  onChange={(e) => setDraftName(e.target.value)}
                  placeholder={t('dashboard.views.namePlaceholder')}
                  className="min-w-0 flex-1 rounded-md border border-slate-200 bg-white px-2 py-1 text-xs text-slate-900 placeholder:text-slate-400 focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500/15 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:placeholder:text-slate-500"
                />
                <button
                  type="submit"
                  disabled={!draftName.trim()}
                  className="rounded bg-brand-500 px-2 py-1 text-[11px] font-medium text-white disabled:bg-slate-200 disabled:text-slate-400 dark:disabled:bg-slate-700 dark:disabled:text-slate-500"
                >
                  {t('actions.save')}
                </button>
              </form>
            )}
          </div>
        </div>,
        document.body,
      )}
    </>
  );
};

export default SavedViewsMenu;
