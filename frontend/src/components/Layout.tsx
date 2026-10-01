import React, { useState } from 'react';
import { Home, Keyboard, LogOut, Menu, Settings, ShieldCheck, X } from 'lucide-react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Button } from './ui';
import { ThemeToggle } from './ThemeProvider';
import ClusterSwitcher from './ClusterSwitcher';
import { dispatchOpenShortcuts } from '../hooks/useGlobalShortcuts';
import { User } from '../services/api';

type Props = {
  user: User;
  /** Section-specific panel content (namespace list, admin sub-nav, etc.). */
  panel?: React.ReactNode;
  /** Optional panel heading, shown above the panel content. */
  panelTitle?: string;
  children: React.ReactNode;
};

type RailItem = {
  key: string;
  label: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
  path: string;
  adminOnly?: boolean;
};

const RAIL: RailItem[] = [
  { key: 'dashboard', label: 'Dashboard', icon: Home, path: '/' },
  { key: 'admin', label: 'Admin', icon: Settings, path: '/admin', adminOnly: true },
];

const LogoMark: React.FC<{ compact?: boolean }> = ({ compact = false }) => (
  <div className="flex items-center gap-2.5">
    <div className="relative flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-brand-500 to-brand-700 shadow-[0_0_0_1px_rgba(255,255,255,0.08)_inset,0_8px_16px_-6px_rgba(79,70,229,0.6)]">
      <svg
        viewBox="0 0 24 24"
        className="h-4 w-4 text-white"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.2"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M12 2 3 7l9 5 9-5-9-5Z" />
        <path d="M3 12l9 5 9-5" />
        <path d="M3 17l9 5 9-5" />
      </svg>
    </div>
    {!compact && (
      <div className="flex flex-col leading-tight">
        <span className="text-[13px] font-semibold tracking-tight text-slate-900 dark:text-slate-100">
          Kubernetes OpenConsole
        </span>
        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-slate-400 dark:text-slate-500">
          Cluster Visibility
        </span>
      </div>
    )}
  </div>
);

const Layout: React.FC<Props> = ({ user, panel, panelTitle, children }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const [drawerOpen, setDrawerOpen] = useState(false);

  const handleLogout = () => {
    localStorage.removeItem('authToken');
    navigate('/login');
  };

  const items = RAIL.filter((item) => !item.adminOnly || user.isAdmin);
  const isActive = (path: string) =>
    path === '/' ? location.pathname === '/' : location.pathname.startsWith(path);

  const closeDrawer = () => setDrawerOpen(false);

  return (
    <div className="min-h-screen font-sans text-slate-900 dark:text-slate-100">
      {/* ── Top header ─────────────────────────────────────────────── */}
      <header className="fixed left-0 right-0 top-0 z-30 flex h-14 items-center gap-3 border-b border-slate-200 dark:border-slate-800/70 bg-white dark:bg-slate-900/80 px-4 backdrop-blur-md supports-[backdrop-filter]:bg-white dark:bg-slate-900/60">
        <button
          className="rounded-lg p-1.5 text-slate-500 dark:text-slate-400 transition-colors hover:bg-slate-100 dark:hover:bg-slate-800 dark:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100 dark:text-slate-100 focus:outline-none lg:hidden"
          onClick={() => setDrawerOpen(true)}
          aria-label="Open navigation"
        >
          <Menu size={20} />
        </button>

        <LogoMark />

        <div className="ml-6 hidden items-center gap-2 lg:flex">
          <ClusterSwitcher user={user} />
        </div>

        <div className="ml-auto flex items-center gap-2">
          <button
            type="button"
            onClick={() => dispatchOpenShortcuts()}
            title="View keyboard shortcuts (?)"
            className="hidden items-center gap-1.5 rounded-md border border-slate-200 bg-white/60 px-2 py-1 text-[10px] font-medium text-slate-500 transition-colors hover:border-slate-300 hover:bg-slate-100 hover:text-slate-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/40 dark:border-slate-700 dark:bg-slate-900/60 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-200 md:inline-flex"
          >
            <Keyboard size={12} className="shrink-0" />
            Shortcuts
            <kbd className="rounded border border-slate-200 bg-white px-1 font-mono text-[10px] dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
              ?
            </kbd>
          </button>
          <span
            className="hidden items-center gap-1 rounded-md border border-slate-200 bg-white/60 px-2 py-1 text-[10px] font-medium text-slate-500 dark:border-slate-700 dark:bg-slate-900/60 dark:text-slate-400 md:inline-flex"
            title="Open command palette"
          >
            Press
            <kbd className="rounded border border-slate-200 bg-white px-1 font-mono text-[10px] dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
              ⌘K
            </kbd>
          </span>
          <ThemeToggle className="hidden sm:inline-flex" />
          <div className="hidden items-center gap-2 pr-2 sm:flex">
            <div className="flex h-7 w-7 items-center justify-center rounded-full bg-brand-50 dark:bg-brand-500/15 text-xs font-semibold text-brand-700 dark:text-brand-200 ring-1 ring-inset ring-brand-200 dark:ring-brand-500/30">
              {(user.username ?? '?').slice(0, 1).toUpperCase()}
            </div>
            <div className="flex flex-col leading-tight">
              <span className="text-xs font-medium text-slate-900 dark:text-slate-100">
                {user.username}
              </span>
              {user.isAdmin && (
                <span className="text-[10px] font-medium uppercase tracking-wide text-slate-400 dark:text-slate-500">
                  Administrator
                </span>
              )}
            </div>
          </div>
          <Button variant="primary" size="sm" onClick={handleLogout}>
            <LogOut size={14} className="shrink-0" />
            Sign out
          </Button>
        </div>
      </header>

      {/* ── Mobile drawer backdrop ─────────────────────────────────── */}
      {drawerOpen && (
        <div
          className="fixed inset-0 z-40 bg-slate-900/60 backdrop-blur-sm lg:hidden"
          onClick={closeDrawer}
        />
      )}

      {/* ── Rail (icons) ───────────────────────────────────────────── */}
      <aside
        className={`fixed bottom-0 left-0 top-0 z-50 flex w-[64px] flex-col items-center border-r border-slate-800/70 bg-sidebar-gradient py-3 text-slate-200 transition-transform duration-200 lg:top-14 lg:translate-x-0 ${
          drawerOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        <div className="mb-4 lg:hidden">
          <LogoMark compact />
        </div>

        <nav className="flex w-full flex-col items-center gap-1">
          {items.map((item) => {
            const Icon = item.icon;
            const active = isActive(item.path);
            return (
              <button
                key={item.key}
                onClick={() => {
                  navigate(item.path);
                  closeDrawer();
                }}
                className={`group relative flex h-10 w-10 items-center justify-center rounded-lg transition-colors ${
                  active
                    ? 'bg-brand-600/20 text-brand-200 ring-1 ring-inset ring-brand-500/40'
                    : 'text-slate-400 dark:text-slate-500 hover:bg-slate-800/80 hover:text-white'
                }`}
                aria-label={item.label}
                title={item.label}
              >
                {active && (
                  <span className="absolute left-0 top-1/2 -translate-y-1/2 h-5 w-0.5 rounded-r bg-brand-400" />
                )}
                <Icon size={18} />
              </button>
            );
          })}
        </nav>

        <div className="mt-auto flex flex-col items-center gap-2 pb-1">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg text-emerald-400" title="Permissioned cluster access">
            <ShieldCheck size={18} />
          </div>
        </div>
      </aside>

      {/* ── Section panel ──────────────────────────────────────────── */}
      <aside
        className={`fixed bottom-0 left-[64px] top-14 z-40 hidden w-[240px] flex-col border-r border-slate-200 dark:border-slate-800/70 bg-white dark:bg-slate-900/80 backdrop-blur-sm lg:flex`}
      >
        {panelTitle && (
          <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800/70 px-4 py-3">
            <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-500 dark:text-slate-400">
              {panelTitle}
            </span>
          </div>
        )}
        <div className="flex-1 overflow-auto">{panel}</div>
      </aside>

      {/* ── Mobile panel inside drawer ─────────────────────────────── */}
      {drawerOpen && panel && (
        <aside className="fixed bottom-0 left-[64px] top-14 z-50 flex w-[260px] flex-col border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 lg:hidden">
          <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 px-4 py-3">
            <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-500 dark:text-slate-400">
              {panelTitle ?? 'Menu'}
            </span>
            <button
              onClick={closeDrawer}
              className="rounded p-1 text-slate-400 dark:text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 dark:bg-slate-800"
              aria-label="Close"
            >
              <X size={16} />
            </button>
          </div>
          <div className="flex-1 overflow-auto" onClick={closeDrawer}>
            {panel}
          </div>
        </aside>
      )}

      {/* ── Main content ───────────────────────────────────────────── */}
      <main className="min-h-screen pt-14 pl-[64px] lg:pl-[304px]">
        <div className="mx-auto max-w-[1600px] px-4 py-6 sm:px-6 lg:px-8">{children}</div>
      </main>
    </div>
  );
};

export default Layout;
