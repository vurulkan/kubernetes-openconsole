import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Check, ChevronsUpDown, Server } from 'lucide-react';
import { listClustersPublic, selectCluster } from '../services/api';
import { User } from '../services/api';
import { confirm } from './ConfirmDialog';
import { CLUSTER_SWITCHER_EVENT_NAME } from '../hooks/useGlobalShortcuts';
import { useTranslation } from 'react-i18next';

type Props = {
  user: User;
};

type ClusterRow = { id: number; name: string; isActive: boolean; selected: boolean };

/**
 * Compact dropdown shown in the top header. Lists the clusters the user may
 * use and switches the user's OWN cluster — other users are unaffected.
 * The default cluster (set by admins) is marked; users who never picked one
 * work on it.
 */
// Props kept for call-site compatibility; switching no longer depends on the
// user's role.
export const ClusterSwitcher: React.FC<Props> = () => {
  const { t } = useTranslation();
  const [clusters, setClusters] = useState<ClusterRow[]>([]);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<number | null>(null);
  const [focusedIdx, setFocusedIdx] = useState<number>(0);
  const ref = useRef<HTMLDivElement | null>(null);
  const buttonRef = useRef<HTMLButtonElement | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const [menuPos, setMenuPos] = useState<{ top: number; left: number } | null>(null);

  const refresh = async () => {
    try {
      const result = await listClustersPublic();
      setClusters(result.items ?? []);
    } catch (err) {
      setClusters([]);
    }
  };

  useEffect(() => {
    void refresh();
    const t = setInterval(refresh, 30_000);
    return () => clearInterval(t);
  }, []);

  // Outside-click must consider BOTH the trigger button (in header) and the
  // menu itself (portaled to body). Checking only `ref.current` would close
  // the menu on every item click before the item's onClick had a chance to
  // run — exactly what caused "dropdown shows but doesn't activate".
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => {
      const target = e.target as Node;
      if (ref.current?.contains(target)) return;
      if (menuRef.current?.contains(target)) return;
      setOpen(false);
    };
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, [open]);

  // Anchor the floating menu to the button in viewport coordinates. Rendered
  // via position: fixed so it escapes any ancestor stacking context (header,
  // sidebar, etc.) and always sits on top.
  useLayoutEffect(() => {
    if (!open || !buttonRef.current) return;
    const update = () => {
      const rect = buttonRef.current!.getBoundingClientRect();
      setMenuPos({ top: rect.bottom + 6, left: rect.left });
    };
    update();
    window.addEventListener('resize', update);
    window.addEventListener('scroll', update, true);
    return () => {
      window.removeEventListener('resize', update);
      window.removeEventListener('scroll', update, true);
    };
  }, [open]);

  const current = clusters.find((c) => c.selected);
  const label = current?.name ?? t('clusterSwitcher.noCluster');

  // Global `c` shortcut opens the menu.
  useEffect(() => {
    const handler = () => {
      if (clusters.length < 2) return;
      setOpen(true);
      // Default focus to the current row so Enter is a no-op and arrow keys
      // land somewhere sensible even on first open.
      const idx = clusters.findIndex((c) => c.selected);
      setFocusedIdx(idx >= 0 ? idx : 0);
    };
    window.addEventListener(CLUSTER_SWITCHER_EVENT_NAME, handler as EventListener);
    return () => window.removeEventListener(CLUSTER_SWITCHER_EVENT_NAME, handler as EventListener);
  }, [clusters]);

  // In-menu keyboard navigation: digits pick a cluster by index (1..9),
  // arrows move, Enter commits the focused row, Esc closes. Only wired while
  // the menu is open so none of these keys leak into page-level shortcuts.
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        setOpen(false);
        return;
      }
      if (clusters.length === 0) return;
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setFocusedIdx((i) => (i + 1) % clusters.length);
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        setFocusedIdx((i) => (i - 1 + clusters.length) % clusters.length);
        return;
      }
      if (e.key === 'Enter') {
        e.preventDefault();
        const target = clusters[focusedIdx];
        if (target && !target.selected) void choose(target.id);
        else setOpen(false);
        return;
      }
      // Digit selection: 1-based so '1' maps to clusters[0]. Capped at 9 —
      // beyond that users scroll with arrows (which keep working).
      if (/^[1-9]$/.test(e.key)) {
        const idx = Number(e.key) - 1;
        if (idx < clusters.length) {
          e.preventDefault();
          const target = clusters[idx];
          setFocusedIdx(idx);
          if (!target.selected) void choose(target.id);
          else setOpen(false);
        }
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, clusters, focusedIdx]);

  const choose = async (id: number) => {
    setBusy(id);
    try {
      await selectCluster(id);
      await refresh();
      setOpen(false);
      // Reload to re-fetch namespaces and permissions against the new cluster.
      window.location.reload();
    } catch (err) {
      await confirm({
        title: t('clusterSwitcher.activationFailed'),
        message: (err as Error).message || t('clusterSwitcher.unknownError'),
        confirmText: t('actions.ok'),
        cancelText: t('actions.dismiss'),
      });
    } finally {
      setBusy(null);
    }
  };

  if (clusters.length === 0) {
    return (
      <span className="rounded-md border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-500 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400">
        {t('clusterSwitcher.noCluster')}
      </span>
    );
  }

  return (
    <div ref={ref} className="relative">
      <button
        ref={buttonRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        disabled={clusters.length === 1}
        title={current?.isActive ? t('clusterSwitcher.defaultHint') : undefined}
        className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-2.5 py-1 text-[11px] font-medium text-slate-700 shadow-sm transition-colors hover:border-slate-300 hover:bg-slate-50 disabled:opacity-70 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700/60"
      >
        <Server size={12} className="text-brand-500" />
        <span className="font-mono">{label}</span>
        {clusters.length > 1 && <ChevronsUpDown size={12} className="text-slate-400" />}
      </button>

      {/*
        The header uses backdrop-filter which creates a containing block for
        position:fixed descendants — a dropdown placed there, however high the
        z-index, stays trapped inside the header's stacking context and gets
        covered by the sidebar rail. Portaling to document.body lets the fixed
        position actually be viewport-relative and z-index comparable to the rail.
      */}
      {open && menuPos && createPortal(
        <div
          ref={menuRef}
          className="fixed z-[1000] w-56 animate-slide-up overflow-hidden rounded-xl border border-slate-200 bg-white shadow-elevated dark:border-slate-800 dark:bg-slate-900"
          style={{ top: menuPos.top, left: menuPos.left }}
        >
          <div className="px-3 py-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-400 dark:text-slate-500">
            {t('clusterSwitcher.clusters')}
          </div>
          <ul className="max-h-72 overflow-auto pb-1">
            {clusters.map((c, idx) => (
              <li key={c.id}>
                <button
                  type="button"
                  onMouseEnter={() => setFocusedIdx(idx)}
                  onClick={() => {
                    if (c.selected) {
                      setOpen(false);
                      return;
                    }
                    void choose(c.id);
                  }}
                  disabled={busy !== null}
                  className={`flex w-full items-center gap-2 px-3 py-2 text-left text-sm transition-colors ${
                    c.selected
                      ? 'bg-brand-50 text-brand-700 dark:bg-brand-500/15 dark:text-brand-200'
                      : focusedIdx === idx
                      ? 'bg-slate-100 text-slate-900 dark:bg-slate-800 dark:text-slate-100'
                      : 'text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-800'
                  }`}
                >
                  {idx < 9 && (
                    <kbd className="rounded border border-slate-200 bg-white px-1 text-[9px] font-mono text-slate-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400">
                      {idx + 1}
                    </kbd>
                  )}
                  <span className="flex-1 truncate font-mono">{c.name}</span>
                  {c.isActive && (
                    <span className="rounded bg-slate-100 px-1 text-[9px] font-medium uppercase text-slate-500 dark:bg-slate-800 dark:text-slate-400">
                      {t('clusterSwitcher.default')}
                    </span>
                  )}
                  {c.selected && <Check size={14} className="text-brand-600 dark:text-brand-300" />}
                  {busy === c.id && (
                    <span className="text-[10px] text-slate-400">{t('clusterSwitcher.switching')}</span>
                  )}
                </button>
              </li>
            ))}
          </ul>
          <div className="border-t border-slate-200 px-3 py-1.5 text-[10px] text-slate-400 dark:border-slate-800">
            {t('clusterSwitcher.onlyYou')}
          </div>
        </div>,
        document.body
      )}
    </div>
  );
};

export default ClusterSwitcher;
