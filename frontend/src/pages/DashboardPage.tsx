import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Activity, Boxes, RefreshCw, Search as SearchIcon } from 'lucide-react';
import Layout from '../components/Layout';
import LiveEventsPanel from '../components/LiveEventsPanel';
import { LogViewer, type LogTarget } from '../components/LogViewer';
import SecretModal from '../components/SecretModal';
import { PodDrawer } from './dashboard/PodDrawer';
import { WorkloadDrawer } from './dashboard/WorkloadDrawer';
import { usePodMetrics } from '../hooks/usePodMetrics';
import YamlEditModal, { YamlEditTarget } from '../components/YamlEditModal';
import { useTheme } from '../components/ThemeProvider';
import SavedViewsMenu from '../components/SavedViewsMenu';
import { useTranslation } from 'react-i18next';
import { Alert, Badge, Button, Input } from '../components/ui';
import { useScopedShortcuts } from '../hooks/useScopedShortcuts';
import { EVENTS_PANEL_EVENT_NAME } from '../hooks/useGlobalShortcuts';
import { searchText } from '../utils/searchText';
import type { ObjectMeta } from '../utils/kubeTypes';
import { ResourceListView, type ResourceViewProps } from './dashboard/ResourceListView';
import { ResourceCardsView } from './dashboard/ResourceCardsView';
import { NamespacePanel } from './dashboard/NamespacePanel';
import { ResourceTabs } from './dashboard/ResourceTabs';
import { useNamespaceResources } from './dashboard/useNamespaceResources';
import {
  InfoModal,
  ShellModals,
  WorkloadActionModals,
  useInfoModal,
  useShell,
  useWorkloadActions,
  yamlTarget,
} from './dashboard/DashboardModals';
import {
  User,
  getMe,
  listNamespaces,
  getNamespacePermissions,
  getWorkload,
  type WorkloadKind,
} from '../services/api';
import { useNavigate } from 'react-router-dom';

const resourceOrder = [
  'pods',
  'deployments',
  'daemonsets',
  'statefulsets',
  'hpas',
  'services',
  'configmaps',
  'secrets',
  'ingresses',
  'cronjobs',
  'jobs',
];

const nameOf = (it: Record<string, unknown>) => (it.metadata as ObjectMeta | undefined)?.name;

/** Every token matches: label:k=v (exact), label:k (key present), or text found in the row's search text. */
function matchesSearch(tokens: string[], text: string, item: Record<string, unknown>): boolean {
  const labels = (item.metadata as ObjectMeta | undefined)?.labels ?? {};
  for (const t of tokens) {
    if (t.toLowerCase().startsWith('label:')) {
      const spec = t.slice('label:'.length);
      const eq = spec.indexOf('=');
      if (eq >= 0) {
        const key = spec.slice(0, eq);
        const val = spec.slice(eq + 1);
        if (labels[key] !== val) return false;
      } else {
        if (!(spec in labels)) return false;
      }
    } else {
      if (!text.includes(t.toLowerCase())) return false;
    }
  }
  return true;
}

const DashboardPage: React.FC<{ user: User }> = ({ user }) => {
  const navigate = useNavigate();
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [selectedNamespace, setSelectedNamespace] = useState<string | null>(() => {
    try {
      return localStorage.getItem('dashboardNamespace');
    } catch (err) {
      return null;
    }
  });
  const [allowedResources, setAllowedResources] = useState<Record<string, string[]>>({});
  const [activeTab, setActiveTab] = useState<string>(() => {
    try {
      return localStorage.getItem('dashboardResourceTab') ?? '';
    } catch (err) {
      return '';
    }
  });
  const { items, loading, setLoading, error, setError, reload, failingByOwner } = useNamespaceResources(
    selectedNamespace,
    activeTab,
  );
  const [searchQuery, setSearchQuery] = useState('');
  // Search text a restored saved view brings along. Changing tab/namespace
  // clears the search (effect below), so a restore that also changes them
  // parks its search here for that effect to apply instead. A view restored
  // across clusters reloads the page and stages it in localStorage.
  const pendingSearch = useRef<string | null>(
    (() => {
      try {
        const v = localStorage.getItem('dashboardPendingSearch');
        localStorage.removeItem('dashboardPendingSearch');
        return v;
      } catch {
        return null;
      }
    })(),
  );
  const [namespaceSearch, setNamespaceSearch] = useState('');
  const [logTarget, setLogTarget] = useState<(LogTarget & { namespace: string }) | null>(null);
  const info = useInfoModal(selectedNamespace);
  const actions = useWorkloadActions(selectedNamespace, reload);

  const canRestartDeployments = (allowedResources.deployments ?? []).includes('restart');
  const canScaleDeployments = (allowedResources.deployments ?? []).includes('scale');
  const canScaleStatefulSets = (allowedResources.statefulsets ?? []).includes('scale');
  const canExecPods = (allowedResources.pods ?? []).includes('exec');
  // Pod, workload and job logs all need pods:logs; without it no Logs button.
  const canPodLogs = (allowedResources.pods ?? []).includes('logs');
  const canRevealSecrets = (allowedResources.secrets ?? []).includes('reveal');
  const canEditSecrets = (allowedResources.secrets ?? []).includes('edit');
  // Secret whose keys modal is open (null = closed).
  const [secretTarget, setSecretTarget] = useState<string | null>(null);
  const shell = useShell();
  // Detail drawer. obj is a snapshot for objects not in the current tab (a pod opened from its deployment).
  const [detail, setDetail] = useState<{ kind: 'pods' | WorkloadKind; name: string; obj?: Record<string, unknown> } | null>(null);
  useEffect(() => setDetail(null), [selectedNamespace]);
  // Admin → Overview opens a pod's drawer here; it stages the pod like a saved view stages its search.
  const pendingPod = useRef(localStorage.getItem('dashboardPendingPod'));
  useEffect(() => {
    if (!pendingPod.current) return;
    setDetail({ kind: 'pods', name: pendingPod.current });
    localStorage.removeItem('dashboardPendingPod');
  }, []);
  const detailObj = detail
    ? (activeTab === detail.kind ? items.find((it) => nameOf(it) === detail.name) : undefined) ?? detail.obj ?? null
    : null;
  const isWorkloadTab = activeTab === 'deployments' || activeTab === 'statefulsets' || activeTab === 'daemonsets';
  const metrics = usePodMetrics(selectedNamespace, activeTab === 'pods' || isWorkloadTab || detail !== null);
  const openDetail = (item: Record<string, unknown>) => {
    const name = nameOf(item);
    if (name && (activeTab === 'pods' || isWorkloadTab)) setDetail({ kind: activeTab as 'pods' | WorkloadKind, name });
  };
  const [viewMode, setViewMode] = useState<'card' | 'list'>(() => {
    try {
      // List is the default; a user who picked cards keeps them.
      const stored = localStorage.getItem('dashboardViewMode');
      return stored === 'card' ? 'card' : 'list';
    } catch (err) {
      return 'list';
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem('dashboardViewMode', viewMode);
    } catch (err) {
      /* ignore */
    }
  }, [viewMode]);
  const theme = useTheme();
  const { t, i18n } = useTranslation();
  const [yamlEdit, setYamlEdit] = useState<YamlEditTarget | null>(null);
  const [eventsOpen, setEventsOpen] = useState<boolean>(() => {
    try {
      return localStorage.getItem('dashboardEventsOpen') === '1';
    } catch (err) {
      return false;
    }
  });
  const [eventsLive, setEventsLive] = useState(false);
  useEffect(() => {
    try {
      localStorage.setItem('dashboardEventsOpen', eventsOpen ? '1' : '0');
    } catch (err) {
      /* ignore */
    }
  }, [eventsOpen]);
  useEffect(() => {
    const handler = () => setEventsOpen((v) => !v);
    window.addEventListener(EVENTS_PANEL_EVENT_NAME, handler as EventListener);
    return () => window.removeEventListener(EVENTS_PANEL_EVENT_NAME, handler as EventListener);
  }, []);

  const openJobLogs = (namespace: string, name: string) => setLogTarget({ kind: 'jobs', namespace, name });
  const openDeploymentLogs = (namespace: string, name: string) => setLogTarget({ kind: 'deployments', namespace, name });
  const openLogModal = (namespace: string, name: string, previous?: string) =>
    setLogTarget({ kind: 'pods', namespace, name, previous });

  const orderedResources = useMemo(
    () => resourceOrder.filter((resource) => Object.keys(allowedResources).includes(resource)),
    [allowedResources]
  );

  // Search input supports two concepts in a single box:
  //   • plain text  → matches the name or any column's text (utils/searchText.ts)
  //   • label:k=v   → matches metadata.labels[k] == v exactly
  //   • label:k     → matches any resource with the label key present
  // Multiple tokens are AND'd. "foo label:tier=front label:app"
  // keeps rows that contain "foo" AND have tier=front AND have an
  // "app" label.
  // Built once per refresh, so a keystroke only runs substring checks.
  const haystacks = useMemo(
    () => new Map(items.map((it) => [it, searchText(activeTab, it)])),
    // i18n.language: translated status texts are part of the haystack; searchText reads them
    // through the global i18n, so the hook can't see this dependency.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [items, activeTab, i18n.language],
  );
  const filteredItems = useMemo(() => {
    const q = searchQuery.trim();
    if (!q) return items;
    const tokens = q.split(/\s+/);
    return items.filter((item) => matchesSearch(tokens, haystacks.get(item) ?? '', item));
  }, [items, searchQuery, haystacks]);

  const loadNamespaces = async () => {
    try {
      setError(null);
      const me = await getMe();
      if (me.user.mustChangePassword) {
        navigate('/change-password');
        return;
      }
      const result = await listNamespaces();
      setNamespaces(result.namespaces);
      // Honor the previously-active namespace on refresh when it is still in
      // the user's allowed list; fall back to the first otherwise so a
      // deleted / permission-revoked / cluster-switched entry doesn't leave
      // the dashboard stuck on an invisible selection.
      const stored = (() => {
        try {
          return localStorage.getItem('dashboardNamespace');
        } catch (err) {
          return null;
        }
      })();
      const defaultNamespace =
        stored && result.namespaces.includes(stored)
          ? stored
          : result.namespaces[0] ?? null;
      setSelectedNamespace(defaultNamespace);
    } catch (err) {
      setError((err as Error).message || t('dashboard.loadFailed'));
      setNamespaces([]);
      setSelectedNamespace(null);
    } finally {
      setLoading(false);
    }
  };

  // Once on mount; the namespace list doesn't follow later renders (a new t or navigate).
  const loadNamespacesOnce = useRef(loadNamespaces);
  useEffect(() => {
    void loadNamespacesOnce.current();
  }, []);

  // Persist the current namespace + resource tab across refreshes. Hydration
  // happens in the useState initializers above; the loadNamespaces /
  // loadPermissions passes validate the stored values against what the user
  // can actually see on the active cluster, so a stale entry won't crash.
  useEffect(() => {
    try {
      if (selectedNamespace) {
        localStorage.setItem('dashboardNamespace', selectedNamespace);
      }
    } catch (err) {
      /* ignore */
    }
  }, [selectedNamespace]);

  useEffect(() => {
    try {
      if (activeTab) {
        localStorage.setItem('dashboardResourceTab', activeTab);
      }
    } catch (err) {
      /* ignore */
    }
  }, [activeTab]);

  // Switch namespace when the command palette writes a #ns:<name> hash.
  useEffect(() => {
    const applyHash = () => {
      const h = window.location.hash;
      if (!h.startsWith('#ns:')) return;
      const target = decodeURIComponent(h.slice(4));
      if (!target || target === selectedNamespace) return;
      if (namespaces.includes(target)) {
        setSelectedNamespace(target);
        // Clear the hash so clicking the same palette item twice still works.
        history.replaceState(null, '', window.location.pathname + window.location.search);
      }
    };
    applyHash();
    window.addEventListener('hashchange', applyHash);
    return () => window.removeEventListener('hashchange', applyHash);
  }, [namespaces, selectedNamespace]);

  useEffect(() => {
    const loadPermissions = async () => {
      if (!selectedNamespace) return;
      try {
        const permissions = await getNamespacePermissions(selectedNamespace);
        setAllowedResources(permissions.resources);
        // Preserve the user's current resource tab across namespace switches
        // when the new namespace also grants it; otherwise fall back to the
        // first resource they can see.
        setActiveTab((prev) => {
          if (prev && permissions.resources[prev]) return prev;
          return resourceOrder.find((resource) => permissions.resources[resource]) ?? '';
        });
      } catch (err) {
        setAllowedResources({});
        setActiveTab('');
        setError((err as Error).message || t('dashboard.loadFailed'));
      }
    };
    void loadPermissions();
  }, [selectedNamespace, t, setError]);

  useEffect(() => {
    setSearchQuery(pendingSearch.current ?? '');
    pendingSearch.current = null;
  }, [activeTab, selectedNamespace]);

  // ─── Page shortcuts ───────────────────────────────────────────────────────
  // [ / ] cycle resource tabs, r refresh, / focus the search box, n open the
  // command palette with the namespace list in view. Suspended while any
  // modal is open and while typing.
  useScopedShortcuts(
    [
      // Physical-key bindings so Turkish Q layout (where [ / ] / / live under
      // AltGr) still reaches these — same positions on US and TR layouts.
      {
        code: 'BracketLeft',
        handler: () => {
          if (orderedResources.length === 0) return;
          const idx = orderedResources.indexOf(activeTab);
          const next = orderedResources[(idx - 1 + orderedResources.length) % orderedResources.length];
          setActiveTab(next);
        },
      },
      {
        code: 'BracketRight',
        handler: () => {
          if (orderedResources.length === 0) return;
          const idx = orderedResources.indexOf(activeTab);
          const next = orderedResources[(idx + 1) % orderedResources.length];
          setActiveTab(next);
        },
      },
      { key: 'r', handler: () => void reload() },
      {
        code: 'Slash',
        handler: () => {
          const el = document.querySelector<HTMLInputElement>('input[data-shortcut="dashboard-search"]');
          el?.focus();
          el?.select();
        },
      },
      {
        key: 'n',
        handler: () => {
          const el = document.querySelector<HTMLInputElement>('input[data-shortcut="namespace-search"]');
          el?.focus();
          el?.select();
        },
      },
    ],
    true
  );

  const openYamlModal = (resource: string, namespace: string, name: string) => {
    const target = yamlTarget(resource, namespace, name, (allowedResources[resource] ?? []).includes('edit'));
    if (target) setYamlEdit(target);
  };

  // ─── Render ───────────────────────────────────────────────────────────────

  // What the list and the card view both show and do.
  const viewProps: ResourceViewProps = {
    activeTab,
    items: filteredItems,
    selectedNamespace: selectedNamespace ?? '',
    searchQuery,
    loading,
    canExecPods,
    canRestartDeployments,
    canScaleDeployments,
    canScaleStatefulSets,
    openYamlModal,
    openEventsModal: info.openEvents,
    openLogModal: canPodLogs ? openLogModal : undefined,
    onOpen: openDetail,
    metrics,
    failingByOwner,
    openConfigMapDataModal: info.openConfigMapData,
    openSecretModal: (name) => setSecretTarget(name),
    canEditSecrets,
    openDeploymentLogs: canPodLogs ? openDeploymentLogs : undefined,
    openJobLogs: canPodLogs ? openJobLogs : undefined,
    onExec: shell.openShell,
    onRestart: actions.openRestart,
    onScale: (name, current) => actions.openScale(name, current),
    onScaleStatefulSet: (name, current) => actions.openScale(name, current, 'statefulsets'),
  };

  const namespacePanel = (
    <NamespacePanel
      namespaces={namespaces}
      selected={selectedNamespace}
      onSelect={setSelectedNamespace}
      search={namespaceSearch}
      onSearch={setNamespaceSearch}
    />
  );

  return (
    <Layout user={user} panel={namespacePanel} panelTitle={t('nav.namespaces')} liveEvents={{ open: eventsOpen, connected: eventsLive }}>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-medium text-slate-500 dark:text-slate-400">
            <Activity size={14} className="text-brand-600 dark:text-brand-300" />
            <span className="uppercase tracking-wider">{t('dashboard.overview')}</span>
          </div>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">
            {t('dashboard.title')}
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            {t('dashboard.subtitle')}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Badge variant="info" className="gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-brand-500" />
            {t('dashboard.overviewBadge.namespaces', { count: namespaces.length })}
          </Badge>
          {selectedNamespace && (
            <Badge variant="default" className="gap-1.5">
              <span className="font-mono text-[11px] text-slate-600 dark:text-slate-400">ns</span>
              <span className="font-mono">{selectedNamespace}</span>
            </Badge>
          )}
        </div>
      </div>

      {error && (
        <Alert severity="warning" className="mt-4">
          {error}
        </Alert>
      )}
      {actions.actionError && (
        <Alert severity="error" className="mt-4">
          {actions.actionError}
        </Alert>
      )}
      {actions.actionNotice && (
        <Alert severity="success" className="mt-4">
          {actions.actionNotice}
        </Alert>
      )}

      {/* ── Resource card ─────────────────────────────────────────── */}
      <div className="card-surface mt-6 overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800/70 bg-slate-50 dark:bg-slate-900/50 px-5 py-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2">
              <div className="flex h-7 w-7 items-center justify-center rounded-md bg-brand-50 dark:bg-brand-500/15 text-brand-600 dark:text-brand-300 ring-1 ring-inset ring-brand-100">
                <Boxes size={14} />
              </div>
              <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {selectedNamespace ?? t('dashboard.noNamespace')}
              </span>
            </div>
            <div className="relative">
              <SearchIcon
                size={14}
                className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500 dark:text-slate-400"
              />
              <Input
                placeholder={activeTab ? t('dashboard.search', { resource: activeTab }) : t('dashboard.searchGeneric')}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-64 pl-8"
                data-shortcut="dashboard-search"
                aria-label={activeTab ? t('dashboard.search', { resource: activeTab }) : t('dashboard.searchGeneric')}
                title={t('dashboard.searchHint')}
              />
            </div>
          </div>
          <div className="flex items-center gap-3">
            {(activeTab === 'pods' || activeTab === 'deployments') && (
              <span className="hidden items-center gap-1.5 text-[11px] font-medium text-slate-500 dark:text-slate-400 sm:inline-flex">
                <span className="h-1.5 w-1.5 animate-live rounded-full bg-emerald-500" />
                {t('dashboard.autoRefresh')}
              </span>
            )}
            <SavedViewsMenu
              current={{
                namespace: selectedNamespace,
                tab: activeTab,
                search: searchQuery,
                viewMode,
              }}
              onRestore={(v) => {
                if ((v.namespace && v.namespace !== selectedNamespace) || (v.tab && v.tab !== activeTab)) {
                  pendingSearch.current = v.search;
                }
                if (v.namespace) setSelectedNamespace(v.namespace);
                if (v.tab) setActiveTab(v.tab);
                setSearchQuery(v.search);
                setViewMode(v.viewMode);
              }}
            />
            <Button
              variant="ghost"
              size="sm"
              onClick={() => void reload()}
              disabled={loading || !activeTab}
            >
              <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
              {t('dashboard.refresh')}
            </Button>
          </div>
        </div>

        <ResourceTabs
          resources={orderedResources}
          active={activeTab}
          onSelect={setActiveTab}
          viewMode={viewMode}
          onViewMode={setViewMode}
        />

        {(activeTab === 'pods' || isWorkloadTab) && metrics && !metrics.available &&
          ['metrics_server_missing', 'forbidden'].includes(metrics.reason ?? '') && (
            <p className="px-5 pt-3 text-xs text-slate-500 dark:text-slate-400">
              {t(`dashboard.usage.unavailable.${metrics.reason}`)}
            </p>
          )}
        {/* Items — card or list view */}
        {viewMode === 'list' && <ResourceListView {...viewProps} />}
        {viewMode === 'card' && <ResourceCardsView {...viewProps} actionBusy={actions.actionBusy} />}
      </div>

      <InfoModal {...info.props} />

      <LogViewer
        namespace={logTarget?.namespace ?? ''}
        target={logTarget}
        pod={
          logTarget?.kind === 'pods'
            ? [...(activeTab === 'pods' ? items : []), detailObj ?? {}].find((it) => nameOf(it) === logTarget.name)
            : undefined
        }
        onClose={() => setLogTarget(null)}
      />

      {detail?.kind === 'pods' && (
        <PodDrawer
          pod={detailObj}
          namespace={selectedNamespace ?? ''}
          canExec={canExecPods}
          onClose={() => setDetail(null)}
          onLogs={canPodLogs ? (name, previous) => openLogModal(selectedNamespace ?? '', name, previous) : undefined}
          onShell={shell.openShell}
          onYaml={(name) => openYamlModal('pods', selectedNamespace ?? '', name)}
          metrics={metrics}
          onOpenNode={user.isAdmin ? (node) => navigate(`/nodes?node=${encodeURIComponent(node)}`) : undefined}
          onOpenOwner={(kind, name) =>
            getWorkload(kind, selectedNamespace ?? '', name)
              .then((obj) => setDetail({ kind, name, obj }))
              .catch(() => undefined)
          }
        />
      )}
      {detail && detail.kind !== 'pods' && (
        <WorkloadDrawer
          kind={detail.kind}
          workload={detailObj}
          namespace={selectedNamespace ?? ''}
          canRestart={canRestartDeployments}
          canScale={detail.kind === 'statefulsets' ? canScaleStatefulSets : canScaleDeployments}
          metrics={metrics}
          onClose={() => setDetail(null)}
          onOpenPod={(pod) => setDetail({ kind: 'pods', name: pod.metadata?.name ?? '', obj: pod })}
          onLogs={canPodLogs ? (name) => openDeploymentLogs(selectedNamespace ?? '', name) : undefined}
          onYaml={(name) => openYamlModal(detail.kind, selectedNamespace ?? '', name)}
          onRestart={actions.openRestart}
          onScale={(name, current) =>
            actions.openScale(name, current, detail.kind === 'statefulsets' ? 'statefulsets' : undefined)
          }
        />
      )}

      <WorkloadActionModals {...actions.modals} />

      {/* ── Secret keys modal ─────────────────────────────────────── */}
      <SecretModal
        open={secretTarget !== null}
        onClose={() => setSecretTarget(null)}
        namespace={selectedNamespace ?? ''}
        name={secretTarget ?? ''}
        canReveal={canRevealSecrets}
      />

      <ShellModals {...shell.modals} namespace={selectedNamespace ?? ''} />

      <LiveEventsPanel
        namespace={selectedNamespace}
        open={eventsOpen}
        onClose={() => setEventsOpen(false)}
        onConnectedChange={setEventsLive}
      />

      <YamlEditModal
        target={yamlEdit}
        onClose={() => setYamlEdit(null)}
        onApplied={() => void reload()}
        theme={theme.effective}
      />
    </Layout>
  );
};

export default DashboardPage;
