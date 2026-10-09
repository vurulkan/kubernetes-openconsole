import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Boxes, Home, Search, Settings, ShieldCheck } from 'lucide-react';
import { useLocation, useNavigate } from 'react-router-dom';
import { User } from '../services/api';
import { useTheme } from './ThemeProvider';
import { PALETTE_EVENT_NAME } from '../hooks/useGlobalShortcuts';

type CommandKind = 'nav' | 'namespace' | 'theme';

type Command = {
  id: string;
  label: string;
  hint?: string;
  kind: CommandKind;
  onRun: () => void;
  icon?: React.ComponentType<{ size?: number | string; className?: string }>;
};

type Props = {
  user: User;
  namespaces: string[];
  onPickNamespace?: (ns: string) => void;
};

/**
 * ⌘K / Ctrl+K command palette. Opens globally; actions:
 *  - navigate to Dashboard or Admin
 *  - pick a namespace (fires onPickNamespace or writes an URL hash the
 *    Dashboard listens to)
 *  - switch theme (light/dark/system)
 */
export const CommandPalette: React.FC<Props> = ({ user, namespaces, onPickNamespace }) => {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const navigate = useNavigate();
  const location = useLocation();
  const { setMode } = useTheme();

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const isMetaK = (e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k';
      if (isMetaK) {
        e.preventDefault();
        setOpen((prev) => !prev);
        setQuery('');
        setCursor(0);
      } else if (open && e.key === 'Escape') {
        e.preventDefault();
        setOpen(false);
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open]);

  // Allow other components / hooks to open the palette via a custom event.
  // Dashboard's "n" shortcut dispatches this; dispatchOpenPalette() is the
  // public helper from useGlobalShortcuts.
  useEffect(() => {
    const open = () => {
      setOpen(true);
      setQuery('');
      setCursor(0);
    };
    window.addEventListener(PALETTE_EVENT_NAME, open as EventListener);
    return () => window.removeEventListener(PALETTE_EVENT_NAME, open as EventListener);
  }, []);

  useEffect(() => {
    if (!open) return;
    const t = setTimeout(() => inputRef.current?.focus(), 10);
    return () => clearTimeout(t);
  }, [open]);

  const close = () => {
    setOpen(false);
    setQuery('');
    setCursor(0);
  };

  const commands = useMemo<Command[]>(() => {
    const navs: Command[] = [
      {
        id: 'nav:dashboard',
        label: 'Go to Dashboard',
        kind: 'nav',
        icon: Home,
        onRun: () => navigate('/'),
      },
    ];
    if (user.isAdmin) {
      navs.push({
        id: 'nav:admin',
        label: 'Go to Admin',
        kind: 'nav',
        icon: Settings,
        onRun: () => navigate('/admin'),
      });
    }
    const themes: Command[] = [
      {
        id: 'theme:light',
        label: 'Theme: Light',
        kind: 'theme',
        icon: ShieldCheck,
        onRun: () => setMode('light'),
      },
      {
        id: 'theme:dark',
        label: 'Theme: Dark',
        kind: 'theme',
        icon: ShieldCheck,
        onRun: () => setMode('dark'),
      },
      {
        id: 'theme:system',
        label: 'Theme: System',
        kind: 'theme',
        icon: ShieldCheck,
        onRun: () => setMode('system'),
      },
    ];
    const nss: Command[] = namespaces.map((ns) => ({
      id: 'ns:' + ns,
      label: ns,
      hint: 'Switch namespace',
      kind: 'namespace',
      icon: Boxes,
      onRun: () => {
        if (location.pathname !== '/') navigate('/');
        if (onPickNamespace) {
          onPickNamespace(ns);
        } else {
          window.location.hash = 'ns:' + ns;
        }
      },
    }));
    return [...navs, ...themes, ...nss];
  }, [user, namespaces, navigate, location.pathname, onPickNamespace, setMode]);

  const q = query.trim().toLowerCase();
  const filtered = useMemo(() => {
    if (!q) return commands;
    return commands.filter(
      (c) =>
        c.label.toLowerCase().includes(q) ||
        c.id.toLowerCase().includes(q) ||
        (c.hint ?? '').toLowerCase().includes(q)
    );
  }, [commands, q]);

  const grouped = useMemo(() => {
    const byKind: Record<CommandKind, Command[]> = { nav: [], namespace: [], theme: [] };
    filtered.forEach((c) => byKind[c.kind].push(c));
    return byKind;
  }, [filtered]);

  const flat = useMemo(
    () => [...grouped.nav, ...grouped.theme, ...grouped.namespace],
    [grouped]
  );

  useEffect(() => {
    if (cursor >= flat.length) setCursor(flat.length === 0 ? 0 : flat.length - 1);
  }, [flat.length, cursor]);

  const run = (c: Command) => {
    c.onRun();
    close();
  };

  const handleKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setCursor((v) => Math.min(flat.length - 1, v + 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setCursor((v) => Math.max(0, v - 1));
    } else if (e.key === 'Enter' && flat[cursor]) {
      e.preventDefault();
      run(flat[cursor]);
    }
  };

  if (!open) return null;

  const section = (title: string, items: Command[]) => {
    if (items.length === 0) return null;
    return (
      <div>
        <p className="px-3 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500 dark:text-slate-400">
          {title}
        </p>
        <ul>
          {items.map((c) => {
            const Icon = c.icon ?? Search;
            const idx = flat.indexOf(c);
            const active = idx === cursor;
            return (
              <li key={c.id}>
                <button
                  type="button"
                  onMouseEnter={() => setCursor(idx)}
                  onClick={() => run(c)}
                  className={`flex w-full items-center gap-2.5 px-3 py-2 text-left text-sm transition-colors ${
                    active
                      ? 'bg-brand-50 text-brand-700 dark:bg-brand-500/15 dark:text-brand-200'
                      : 'text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-800'
                  }`}
                >
                  <Icon size={14} className="shrink-0 text-slate-500 dark:text-slate-400" />
                  <span className="flex-1 truncate">{c.label}</span>
                  {c.hint && (
                    <span className="text-[11px] text-slate-500 dark:text-slate-400">{c.hint}</span>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    );
  };

  return (
    <div className="fixed inset-0 z-[60] flex items-start justify-center p-4 pt-[12vh]">
      <div className="absolute inset-0 bg-slate-900/50 backdrop-blur-sm" onClick={close} />
      <div
        className="relative z-10 w-full max-w-xl animate-slide-up overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-elevated dark:border-slate-800 dark:bg-slate-900"
        role="dialog"
        aria-label="Command palette"
      >
        <div className="flex items-center gap-2 border-b border-slate-200 px-3 py-2 dark:border-slate-800">
          <Search size={16} className="text-slate-400" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setCursor(0);
            }}
            onKeyDown={handleKey}
            placeholder="Type a command or namespace…"
            className="w-full border-0 bg-transparent py-1.5 text-sm outline-none placeholder:text-slate-400 dark:text-slate-100"
          />
          <kbd className="rounded-md border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] font-medium text-slate-500 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400">
            ESC
          </kbd>
        </div>
        <div className="max-h-[50vh] overflow-auto py-1">
          {flat.length === 0 && (
            <p className="px-3 py-6 text-center text-sm text-slate-500 dark:text-slate-400">No results.</p>
          )}
          {section('Navigate', grouped.nav)}
          {section('Theme', grouped.theme)}
          {section('Namespaces', grouped.namespace)}
        </div>
        <div className="flex items-center justify-between border-t border-slate-200 bg-slate-50/60 px-3 py-1.5 text-[10px] text-slate-500 dark:text-slate-400 dark:border-slate-800 dark:bg-slate-900/60">
          <span>↑↓ Navigate · ↵ Select</span>
          <span>
            <kbd className="rounded border border-slate-200 bg-white px-1 dark:border-slate-700 dark:bg-slate-800">
              ⌘K
            </kbd>{' '}
            toggle
          </span>
        </div>
      </div>
    </div>
  );
};

export default CommandPalette;
