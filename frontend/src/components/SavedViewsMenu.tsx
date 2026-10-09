import React, { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Bookmark, Check, Plus, Share2, Trash2, Users } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Button } from './ui';
import { SAVED_VIEWS_EVENT_NAME } from '../hooks/useGlobalShortcuts';
import { deleteView, getActiveCluster, listViews, saveView, selectCluster, ServerView, shareView } from '../services/api';

export type SavedView = {
  name: string;
  namespace: string | null;
  tab: string;
  search: string;
  viewMode: 'card' | 'list';
};

type Props = {
  current: Omit<SavedView, 'name'>;
  onRestore: (view: SavedView) => void;
};

// Views saved before 2.14.0 lived only in this browser; they are uploaded to
// the server once and then removed from localStorage.
const LEGACY_STORAGE_KEY = 'dashboardSavedViews';

async function migrateLegacyViews(): Promise<void> {
  let legacy: Array<Omit<SavedView, 'namespace'> & { namespace: string | null }> = [];
  try {
    const raw = localStorage.getItem(LEGACY_STORAGE_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw);
    legacy = Array.isArray(parsed) ? parsed : [];
  } catch {
    return;
  }
  for (const v of legacy) {
    try {
      await saveView({ name: v.name, namespace: v.namespace ?? '', tab: v.tab, search: v.search, viewMode: v.viewMode });
    } catch {
      return; // keep the local copy; retry on the next load
    }
  }
  try {
    localStorage.removeItem(LEGACY_STORAGE_KEY);
  } catch {
    /* ignore */
  }
}

/**
 * Dropdown that stores Dashboard filter state (cluster + ns + tab + search +
 * view mode) under a name, on the server, so views follow the user across
 * browsers. Views can be shared with everyone; shared views from others show
 * their owner and are read-only. Restoring a view saved on another cluster
 * switches the user's cluster first.
 */
const SavedViewsMenu: React.FC<Props> = ({ current, onRestore }) => {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [views, setViews] = useState<ServerView[]>([]);
  const [naming, setNaming] = useState(false);
  const [draftName, setDraftName] = useState('');
  const [shareDraft, setShareDraft] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [focusedIdx, setFocusedIdx] = useState(0);
  const buttonRef = useRef<HTMLDivElement | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const [pos, setPos] = useState<{ top: number; right: number } | null>(null);

  const refresh = useCallback(async () => {
    try {
      const res = await listViews();
      setViews(res.items ?? []);
    } catch {
      setViews([]);
    }
  }, []);

  useEffect(() => {
    void migrateLegacyViews().then(refresh);
  }, [refresh]);

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

  const restore = useCallback(
    async (v: ServerView) => {
      setOpen(false);
      const view: SavedView = {
        name: v.name,
        namespace: v.namespace || null,
        tab: v.tab,
        search: v.search,
        viewMode: v.viewMode,
      };
      if (v.clusterId > 0) {
        try {
          const active = await getActiveCluster();
          if (active.active?.id !== v.clusterId) {
            // Saved on another cluster: switch, stage the filters, reload.
            await selectCluster(v.clusterId);
            try {
              if (view.namespace) localStorage.setItem('dashboardNamespace', view.namespace);
              if (view.tab) localStorage.setItem('dashboardResourceTab', view.tab);
              localStorage.setItem('dashboardViewMode', view.viewMode);
            } catch {
              /* ignore */
            }
            window.location.reload();
            return;
          }
        } catch {
          /* cluster unavailable or no longer allowed: apply on the current one */
        }
      }
      onRestore(view);
    },
    [onRestore],
  );

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
        if (target) void restore(target);
        return;
      }
      if (/^[1-9]$/.test(e.key)) {
        const idx = Number(e.key) - 1;
        if (idx < views.length) {
          e.preventDefault();
          void restore(views[idx]);
        }
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, naming, views, focusedIdx, restore]);

  const handleSave = async () => {
    const name = draftName.trim();
    if (!name) return;
    setError(null);
    try {
      await saveView({
        name,
        namespace: current.namespace ?? '',
        tab: current.tab,
        search: current.search,
        viewMode: current.viewMode,
        shared: shareDraft,
      });
      setDraftName('');
      setShareDraft(false);
      setNaming(false);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const run = async (fn: () => Promise<unknown>) => {
    setError(null);
    try {
      await fn();
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const isCurrent = (v: ServerView) =>
    (v.namespace || null) === current.namespace &&
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
                  onClick={() => void restore(v)}
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
                      {v.clusterName ? `${v.clusterName} · ` : ''}
                      {v.namespace ? `${v.namespace}/${v.tab}` : v.tab}
                      {v.search ? ` · ${v.search}` : ''}
                      {!v.mine ? ` · ${t('dashboard.views.by', { owner: v.owner })}` : ''}
                    </div>
                  </div>
                </button>
                {v.mine ? (
                  <div className="flex shrink-0 items-center">
                    <button
                      type="button"
                      onClick={() => void run(() => shareView(v.id, !v.shared))}
                      className={`rounded p-1 transition-opacity hover:text-brand-600 ${
                        v.shared ? 'text-brand-500' : 'text-slate-300 opacity-0 group-hover:opacity-100'
                      }`}
                      title={v.shared ? t('dashboard.views.unshare') : t('dashboard.views.share')}
                      aria-label={v.shared ? t('dashboard.views.unshare') : t('dashboard.views.share')}
                    >
                      <Share2 size={12} />
                    </button>
                    <button
                      type="button"
                      onClick={() => void run(() => deleteView(v.id))}
                      className="rounded p-1 text-slate-300 opacity-0 transition-opacity hover:text-rose-600 group-hover:opacity-100"
                      title={t('dashboard.views.delete')}
                      aria-label={t('dashboard.views.delete')}
                    >
                      <Trash2 size={12} />
                    </button>
                  </div>
                ) : (
                  <span className="shrink-0 p-1 text-slate-400" title={t('dashboard.views.sharedBy', { owner: v.owner })}>
                    <Users size={12} />
                  </span>
                )}
              </li>
            ))}
          </ul>
          {error && (
            <div className="border-t border-slate-100 px-3 py-1.5 text-[11px] text-rose-600 dark:border-slate-800/70 dark:text-rose-300">
              {error}
            </div>
          )}
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
                  void handleSave();
                }}
              >
                <input
                  autoFocus
                  value={draftName}
                  onChange={(e) => setDraftName(e.target.value)}
                  placeholder={t('dashboard.views.namePlaceholder')}
                  className="min-w-0 flex-1 rounded-md border border-slate-200 bg-white px-2 py-1 text-xs text-slate-900 placeholder:text-slate-400 focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500/15 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:placeholder:text-slate-500"
                />
                <label className="flex shrink-0 items-center gap-1 text-[10px] text-slate-500 dark:text-slate-400" title={t('dashboard.views.shareHint')}>
                  <input type="checkbox" checked={shareDraft} onChange={(e) => setShareDraft(e.target.checked)} />
                  {t('dashboard.views.shareShort')}
                </label>
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
