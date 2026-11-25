import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Boxes, Box, Gauge, History, Home, KeyRound, Search, Server, Settings, ShieldCheck, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useLocation, useNavigate } from 'react-router-dom';
import { getFeatures, searchResources, tabClusterId, type SearchHit, type SearchKind, User } from '../services/api';
import { useTheme } from './ThemeProvider';
import { PALETTE_EVENT_NAME } from '../hooks/useGlobalShortcuts';
import { useDialogFocus } from '../hooks/useDialogFocus';
import { KIND_NAME, takeFilters, typingNamespace, type PaletteKind } from '../utils/paletteQuery';
import { podStatus } from '../utils/podStatus';
import { openDashboard } from '../utils/openDashboard';

type CommandKind = 'nav' | 'namespace' | 'theme' | 'resource' | 'recent';

type Command = {
  id: string;
  label: string;
  hint?: string;
  /** Resource rows: the kind, shown before the name. */
  badge?: string;
  kind: CommandKind;
  onRun: () => void;
  icon?: React.ComponentType<{ size?: number | string; className?: string }>;
};

type Recent = { kind: SearchKind; namespace?: string; name: string };
const RECENT_MAX = 5;
// Per user and cluster, in this browser only (never sent to the server).
const recentKey = (userId: number) => `palette:recent:${userId}:${tabClusterId() ?? 0}`;
function readRecent(userId: number): Recent[] {
  try {
    const v = JSON.parse(localStorage.getItem(recentKey(userId)) ?? '[]');
    return Array.isArray(v) ? v.filter((r) => r && typeof r.name === 'string' && typeof r.kind === 'string') : [];
  } catch {
    return [];
  }
}
function writeRecent(userId: number, list: Recent[]) {
  try {
    localStorage.setItem(recentKey(userId), JSON.stringify(list.slice(0, RECENT_MAX)));
  } catch {
    /* ignore */
  }
}
const sameResource = (a: Recent, b: Recent) => a.kind === b.kind && a.name === b.name && (a.namespace ?? '') === (b.namespace ?? '');

const DRAWER_KINDS: SearchKind[] = ['pods', 'deployments', 'statefulsets', 'daemonsets'];

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
 *  - find a resource on the tab's cluster by name or IP (/api/search) and open it; a kind word or
 *    ns:<name> first narrows it (utils/paletteQuery.ts) and becomes a chip; the last few opened
 *    resources show while the box is empty
 */
export const CommandPalette: React.FC<Props> = ({ user, namespaces, onPickNamespace }) => {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [chips, setChips] = useState<{ kind?: PaletteKind; ns?: string }>({});
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [recent, setRecent] = useState<Recent[]>([]);
  const [cursor, setCursor] = useState(0);
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [apiKeysOn, setApiKeysOn] = useState(true);
  useEffect(() => {
    void getFeatures().then((f) => setApiKeysOn(f.api_keys !== false));
  }, []);
  const location = useLocation();
  const { setMode } = useTheme();

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const isMetaK = (e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k';
      if (isMetaK) {
        e.preventDefault();
        setOpen((prev) => !prev);
        setQuery('');
        setChips({});
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
      setChips({});
      setCursor(0);
    };
    window.addEventListener(PALETTE_EVENT_NAME, open as EventListener);
    return () => window.removeEventListener(PALETTE_EVENT_NAME, open as EventListener);
  }, []);

  // Focus goes to the search box, stays in the palette, and returns on close.
  const dialogRef = useRef<HTMLDivElement | null>(null);
  useDialogFocus(dialogRef, open);

  const close = () => {
    setOpen(false);
    setQuery('');
    setChips({});
    setCursor(0);
  };

  useEffect(() => {
    if (open) setRecent(readRecent(user.id));
  }, [open, user.id]);

  // What goes to the server: the chips, plus an `ns:pro` still being typed.
  const typed = typingNamespace(query);
  const searchNs = chips.ns ?? typed.ns;
  const searchText = typed.text;
  const searchKind = chips.kind === 'namespaces' ? undefined : chips.kind;
  const wantsSearch = open && chips.kind !== 'namespaces' && (searchText.length >= 2 || !!searchNs);
  useEffect(() => {
    if (!wantsSearch) {
      setHits([]);
      return;
    }
    let stale = false;
    const timer = window.setTimeout(() => {
      searchResources({ q: searchText, kind: searchKind, ns: searchNs })
        .then((r) => !stale && setHits(r.items ?? []))
        .catch(() => !stale && setHits([]));
    }, 200);
    return () => {
      stale = true;
      window.clearTimeout(timer);
    };
  }, [wantsSearch, searchText, searchKind, searchNs]);

  const openResource = ({ kind, namespace, name }: Recent) => {
    const r = { kind, namespace, name };
    writeRecent(user.id, [r, ...readRecent(user.id).filter((x) => !sameResource(x, r))]);
    if (r.kind === 'nodes') {
      navigate(`/nodes?node=${encodeURIComponent(r.name)}`);
      return;
    }
    openDashboard(navigate, {
      dashboardNamespace: r.namespace ?? '',
      dashboardResourceTab: r.kind,
      dashboardPendingSearch: r.name,
      ...(DRAWER_KINDS.includes(r.kind) ? { dashboardPendingDetail: r.name } : {}),
    });
  };
  // A recent one that is gone (or no longer yours to list) leaves the list; it still opens, so a
  // missing permission shows the Dashboard's usual error.
  const openRecent = (r: Recent) => {
    void searchResources({ q: r.name, kind: r.kind, ns: r.namespace })
      .then((res) => {
        if (!res.items.some((h) => sameResource(h, r))) writeRecent(user.id, readRecent(user.id).filter((x) => !sameResource(x, r)));
      })
      .catch(() => {});
    openResource(r);
  };

  const commands = useMemo<Command[]>(() => {
    const navs: Command[] = [
      {
        id: 'nav:dashboard',
        label: t('palette.goToDashboard'),
        kind: 'nav',
        icon: Home,
        onRun: () => navigate('/'),
      },
    ];
    if (user.isAdmin) {
      navs.unshift({
        id: 'nav:overview',
        label: t('palette.goToOverview'),
        kind: 'nav',
        icon: Gauge,
        onRun: () => navigate('/overview'),
      });
      navs.splice(1, 0, {
        id: 'nav:nodes',
        label: t('palette.goToNodes'),
        kind: 'nav',
        icon: Server,
        onRun: () => navigate('/nodes'),
      });
      navs.push({
        id: 'nav:admin',
        label: t('palette.goToAdmin'),
        kind: 'nav',
        icon: Settings,
        onRun: () => navigate('/admin'),
      });
    }
    if (apiKeysOn) navs.push({
      id: 'nav:api-keys',
      label: t('nav.goToApiKeys'),
      kind: 'nav',
      icon: KeyRound,
      onRun: () => navigate('/account/api-keys'),
    });
    const themes: Command[] = [
      {
        id: 'theme:light',
        label: t('palette.themeLight'),
        kind: 'theme',
        icon: ShieldCheck,
        onRun: () => setMode('light'),
      },
      {
        id: 'theme:dark',
        label: t('palette.themeDark'),
        kind: 'theme',
        icon: ShieldCheck,
        onRun: () => setMode('dark'),
      },
      {
        id: 'theme:system',
        label: t('palette.themeSystem'),
        kind: 'theme',
        icon: ShieldCheck,
        onRun: () => setMode('system'),
      },
    ];
    const nss: Command[] = namespaces.map((ns) => ({
      id: 'ns:' + ns,
      label: ns,
      hint: t('palette.switchNamespace'),
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
  }, [user, namespaces, navigate, location.pathname, onPickNamespace, setMode, t, apiKeysOn]);

  const resourceRow = (r: Recent, kind: 'resource' | 'recent', detail?: string): Command => ({
    id: `${kind}:${r.kind}:${r.namespace ?? ''}/${r.name}`,
    label: r.name,
    badge: KIND_NAME[r.kind],
    hint: [r.namespace, detail].filter(Boolean).join(' · '),
    kind,
    icon: kind === 'recent' ? History : r.kind === 'nodes' ? Server : Box,
    onRun: () => (kind === 'recent' ? openRecent(r) : openResource(r)),
  });

  const q = searchText.toLowerCase();
  const filtered = useMemo(() => {
    // A kind or namespace filter narrows the palette to resources (or, for `ns`, to namespaces).
    const narrowed = chips.kind || searchNs ? commands.filter((c) => c.kind === 'namespace' && chips.kind === 'namespaces') : commands;
    if (!q) return narrowed;
    return narrowed.filter(
      (c) =>
        c.label.toLowerCase().includes(q) ||
        c.id.toLowerCase().includes(q) ||
        (c.hint ?? '').toLowerCase().includes(q)
    );
  }, [commands, q, chips.kind, searchNs]);

  const grouped = useMemo(() => {
    const byKind: Record<CommandKind, Command[]> = { nav: [], namespace: [], theme: [], resource: [], recent: [] };
    filtered.forEach((c) => byKind[c.kind].push(c));
    return byKind;
  }, [filtered]);
  // eslint-disable-next-line react-hooks/exhaustive-deps -- resourceRow / openResource only read the latest navigate + user
  const resourceRows = useMemo(() => hits.map((h) => resourceRow(h, 'resource', h.ip || (h.pod ? podStatus(h.pod).label : h.status))), [hits]);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const recentRows = useMemo(() => (!query.trim() && !chips.kind && !chips.ns ? recent.map((r) => resourceRow(r, 'recent')) : []), [recent, query, chips]);

  const flat = useMemo(
    () => [...recentRows, ...grouped.nav, ...grouped.theme, ...grouped.namespace, ...resourceRows],
    [grouped, recentRows, resourceRows]
  );

  useEffect(() => {
    if (cursor >= flat.length) setCursor(flat.length === 0 ? 0 : flat.length - 1);
  }, [flat.length, cursor]);

  const run = (c: Command) => {
    c.onRun();
    close();
  };

  const handleKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && query === '' && (chips.kind || chips.ns)) {
      e.preventDefault();
      setChips((c) => (c.ns ? { kind: c.kind } : {}));
      setCursor(0);
    } else if (e.key === 'ArrowDown') {
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

  const chipList = [
    ...(chips.kind ? [{ id: 'kind', label: KIND_NAME[chips.kind], remove: () => setChips((c) => ({ ns: c.ns })) }] : []),
    ...(chips.ns ? [{ id: 'ns', label: `ns: ${chips.ns}`, remove: () => setChips((c) => ({ kind: c.kind })) }] : []),
  ];

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
                  {c.badge && (
                    <span className="shrink-0 rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                      {c.badge}
                    </span>
                  )}
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
        ref={dialogRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label={t('palette.title')}
      >
        <div className="flex items-center gap-2 border-b border-slate-200 px-3 py-2 dark:border-slate-800">
          <Search size={16} className="shrink-0 text-slate-400" />
          {chipList.map((chip) => (
            <span
              key={chip.id}
              className="inline-flex shrink-0 items-center gap-1 rounded-md bg-brand-50 py-0.5 pl-1.5 pr-0.5 text-xs font-medium text-brand-700 dark:bg-brand-500/15 dark:text-brand-200"
            >
              {chip.label}
              <button
                type="button"
                aria-label={t('palette.removeFilter', { name: chip.label })}
                onClick={chip.remove}
                className="rounded p-0.5 hover:bg-brand-100 dark:hover:bg-brand-500/25"
              >
                <X size={11} />
              </button>
            </span>
          ))}
          <input
            value={query}
            aria-label={t('palette.title')}
            onChange={(e) => {
              const f = takeFilters(e.target.value, user.isAdmin);
              if (f.kind || f.ns) {
                setChips((c) => ({ kind: f.kind ?? c.kind, ns: f.ns ?? c.ns }));
                setQuery(f.rest);
              } else {
                setQuery(e.target.value);
              }
              setCursor(0);
            }}
            onKeyDown={handleKey}
            placeholder={t('palette.placeholder')}
            className="w-full border-0 bg-transparent py-1.5 text-sm outline-none placeholder:text-slate-400 dark:text-slate-100"
          />
          <kbd className="rounded-md border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] font-medium text-slate-500 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400">
            ESC
          </kbd>
        </div>
        {!query && !chips.kind && !chips.ns && (
          <p className="border-b border-slate-200 px-3 py-1.5 font-mono text-[11px] text-slate-500 dark:border-slate-800 dark:text-slate-400">
            {t('palette.filterHint')}
          </p>
        )}
        <div className="max-h-[50vh] overflow-auto py-1">
          {flat.length === 0 && (
            <p className="px-3 py-6 text-center text-sm text-slate-500 dark:text-slate-400">{t('palette.noResults')}</p>
          )}
          {section(t('palette.sectionRecent'), recentRows)}
          {section(t('palette.sectionNavigate'), grouped.nav)}
          {section(t('palette.sectionTheme'), grouped.theme)}
          {section(t('palette.sectionNamespaces'), grouped.namespace)}
          {section(t('palette.sectionResources'), resourceRows)}
        </div>
        <div className="flex items-center justify-between border-t border-slate-200 bg-slate-50/60 px-3 py-1.5 text-[10px] text-slate-500 dark:text-slate-400 dark:border-slate-800 dark:bg-slate-900/60">
          <span>{t('palette.footerKeys')}</span>
          <span>
            <kbd className="rounded border border-slate-200 bg-white px-1 dark:border-slate-700 dark:bg-slate-800">
              ⌘K
            </kbd>{' '}
            {t('palette.footerToggle')}
          </span>
        </div>
      </div>
    </div>
  );
};

export default CommandPalette;
