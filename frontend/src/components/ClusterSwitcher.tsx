import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Check, ChevronsUpDown, Server } from 'lucide-react';
import { activateCluster, listClustersPublic } from '../services/api';
import { User } from '../services/api';
import { confirm } from './ConfirmDialog';

type Props = {
  user: User;
};

type ClusterRow = { id: number; name: string; isActive: boolean };

/**
 * Compact dropdown shown in the top header. Reads the public cluster list
 * (any authenticated user may see names). Admins can switch via the dropdown;
 * non-admins see the active cluster but cannot switch it.
 */
export const ClusterSwitcher: React.FC<Props> = ({ user }) => {
  const [clusters, setClusters] = useState<ClusterRow[]>([]);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<number | null>(null);
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

  const active = clusters.find((c) => c.isActive);
  const label = active?.name ?? 'no cluster';

  const activate = async (id: number) => {
    setBusy(id);
    try {
      await activateCluster(id);
      await refresh();
      setOpen(false);
      // Reload to re-fetch namespaces and permissions against the new cluster.
      window.location.reload();
    } catch (err) {
      await confirm({
        title: 'Cluster activation failed',
        message: (err as Error).message || 'Unknown error.',
        confirmText: 'OK',
        cancelText: 'Dismiss',
      });
    } finally {
      setBusy(null);
    }
  };

  if (clusters.length === 0) {
    return (
      <span className="rounded-md border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-500 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400">
        no cluster
      </span>
    );
  }

  return (
    <div ref={ref} className="relative">
      <button
        ref={buttonRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        disabled={!user.isAdmin && clusters.length === 1}
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
            Clusters
          </div>
          <ul className="max-h-72 overflow-auto pb-1">
            {clusters.map((c) => (
              <li key={c.id}>
                <button
                  type="button"
                  onClick={() => {
                    if (!user.isAdmin) return;
                    if (c.isActive) {
                      setOpen(false);
                      return;
                    }
                    void activate(c.id);
                  }}
                  disabled={busy !== null}
                  className={`flex w-full items-center gap-2 px-3 py-2 text-left text-sm transition-colors ${
                    c.isActive
                      ? 'bg-brand-50 text-brand-700 dark:bg-brand-500/15 dark:text-brand-200'
                      : 'text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-800'
                  } ${!user.isAdmin && !c.isActive ? 'cursor-not-allowed opacity-50' : ''}`}
                >
                  <span className="flex-1 truncate font-mono">{c.name}</span>
                  {c.isActive && <Check size={14} className="text-brand-600 dark:text-brand-300" />}
                  {busy === c.id && (
                    <span className="text-[10px] text-slate-400">switching…</span>
                  )}
                </button>
              </li>
            ))}
          </ul>
          {!user.isAdmin && (
            <div className="border-t border-slate-200 px-3 py-1.5 text-[10px] text-slate-400 dark:border-slate-800">
              Only admins can switch clusters.
            </div>
          )}
        </div>,
        document.body
      )}
    </div>
  );
};

export default ClusterSwitcher;
