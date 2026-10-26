import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  Boxes,
  Calendar,
  FileCode2,
  FileText,
  Gauge,
  Globe,
  Database,
  HardDrive,
  KeyRound,
  LayoutGrid,
  List as ListIcon,
  ListChecks,
  Minus,
  Plus,
  RefreshCw,
  RotateCcw,
  Scaling,
  Search as SearchIcon,
  Terminal,
} from 'lucide-react';
import Layout from '../components/Layout';
import LiveEventsPanel from '../components/LiveEventsPanel';
import PodExecModal from '../components/PodExecModal';
import { ContainerPicker } from '../components/ContainerPicker';
import { LogViewer, type LogTarget } from '../components/LogViewer';
import SecretModal from '../components/SecretModal';
import { PodRestarts, PodStatusBadge, STATUS_DOT } from '../components/PodStatusBadge';
import { podOwner, podStatus } from '../utils/podStatus';
import { PodDrawer } from './dashboard/PodDrawer';
import { KIND, WorkloadDrawer } from './dashboard/WorkloadDrawer';
import { usePodMetrics } from '../hooks/usePodMetrics';
import { UsageBar } from '../components/Usage';
import { ownerUsage, podResources, scaleResources } from '../utils/resources';
import YamlEditModal, { YamlEditTarget } from '../components/YamlEditModal';
import { useTheme } from '../components/ThemeProvider';
import SavedViewsMenu from '../components/SavedViewsMenu';
import { useTranslation } from 'react-i18next';
import { Alert, Badge, Button, Input, Modal, Spinner } from '../components/ui';
import { useScopedShortcuts } from '../hooks/useScopedShortcuts';
import { EVENTS_PANEL_EVENT_NAME } from '../hooks/useGlobalShortcuts';
import { formatAge } from '../utils/age';
import { ResourceListView } from './dashboard/ResourceListView';
import {
  User,
  getMe,
  listNamespaces,
  getNamespacePermissions,
  listPods,
  listDeployments,
  listServices,
  listConfigMaps,
  listSecrets,
  getSecretYaml,
  listIngresses,
  listCronJobs,
  listDaemonSets,
  listStatefulSets,
  listHPAs,
  listJobs,
  getDaemonSetYaml,
  getStatefulSetYaml,
  getHPAYaml,
  scaleStatefulSet,
  getDeploymentYaml,
  getServiceYaml,
  getConfigMapYaml,
  getIngressYaml,
  getCronJobYaml,
  getJobYaml,
  getConfigMapData,
  getPodEvents,
  getWorkload,
  getDeploymentEvents,
  restartDeployment,
  scaleDeployment,
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

const RESOURCE_META: Record<
  string,
  { label: string; icon: React.ComponentType<{ size?: number | string; className?: string }> }
> = {
  pods: { label: 'Pods', icon: Boxes },
  deployments: { label: 'Deployments', icon: LayoutGrid },
  daemonsets: { label: 'DaemonSets', icon: HardDrive },
  statefulsets: { label: 'StatefulSets', icon: Database },
  hpas: { label: 'HPAs', icon: Gauge },
  services: { label: 'Services', icon: Globe },
  configmaps: { label: 'ConfigMaps', icon: FileText },
  secrets: { label: 'Secrets', icon: KeyRound },
  ingresses: { label: 'Ingresses', icon: Globe },
  cronjobs: { label: 'CronJobs', icon: Calendar },
  jobs: { label: 'Jobs', icon: ListChecks },
};

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
  const [items, setItems] = useState<Array<Record<string, unknown>>>([]);
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
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [modalTitle, setModalTitle] = useState('');
  const [modalContent, setModalContent] = useState('');
  const [modalLoading, setModalLoading] = useState(false);
  const [logTarget, setLogTarget] = useState<(LogTarget & { namespace: string }) | null>(null);
  const [scaleTarget, setScaleTarget] = useState<{
    name: string;
    current: number;
    // Only set when scaling a StatefulSet; deployment scaling leaves this
    // undefined so the modal keeps the historical "scale a Deployment" flow.
    kind?: 'statefulsets';
  } | null>(null);
  const [scaleReplicas, setScaleReplicas] = useState(1);
  const [scaleBusy, setScaleBusy] = useState(false);
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const canRestartDeployments = (allowedResources.deployments ?? []).includes('restart');
  const canScaleDeployments = (allowedResources.deployments ?? []).includes('scale');
  const canScaleStatefulSets = (allowedResources.statefulsets ?? []).includes('scale');
  const canExecPods = (allowedResources.pods ?? []).includes('exec');
  const canRevealSecrets = (allowedResources.secrets ?? []).includes('reveal');
  const canEditSecrets = (allowedResources.secrets ?? []).includes('edit');
  // Secret whose keys modal is open (null = closed).
  const [secretTarget, setSecretTarget] = useState<string | null>(null);
  const [execTarget, setExecTarget] = useState<{ name: string; containers: string[]; container?: string } | null>(null);
  // A pod with sidecars asks which container first, in a small menu under the Shell button.
  const [shellPick, setShellPick] = useState<{ pod: Record<string, any>; anchor: HTMLElement } | null>(null);
  const openShell = (pod: Record<string, any>, anchor: HTMLElement) => {
    const containers: string[] = (pod.spec?.containers ?? []).map((c: { name: string }) => c.name);
    if (containers.length > 1) setShellPick({ pod, anchor });
    else setExecTarget({ name: pod.metadata?.name ?? '', containers, container: containers[0] });
  };
  // Detail drawer. obj is a snapshot for objects not in the current tab (a pod opened from its deployment).
  const [detail, setDetail] = useState<{ kind: 'pods' | WorkloadKind; name: string; obj?: Record<string, any> } | null>(null);
  useEffect(() => setDetail(null), [selectedNamespace]);
  // Admin → Overview opens a pod's drawer here; it stages the pod like a saved view stages its search.
  const pendingPod = useRef(localStorage.getItem('dashboardPendingPod'));
  useEffect(() => {
    if (!pendingPod.current) return;
    setDetail({ kind: 'pods', name: pendingPod.current });
    localStorage.removeItem('dashboardPendingPod');
  }, []);
  const detailObj = detail
    ? (activeTab === detail.kind ? items.find((it) => (it.metadata as { name?: string })?.name === detail.name) : undefined) ??
      detail.obj ??
      null
    : null;
  const isWorkloadTab = activeTab === 'deployments' || activeTab === 'statefulsets' || activeTab === 'daemonsets';
  const metrics = usePodMetrics(selectedNamespace, activeTab === 'pods' || isWorkloadTab || detail !== null);
  // Workload tabs also read the namespace's pods (auto-refresh, not audited) to flag workloads with failing pods.
  const [workloadPods, setWorkloadPods] = useState<Array<Record<string, unknown>>>([]);
  const failingByOwner = React.useMemo(() => {
    const m = new Map<string, number>();
    for (const p of workloadPods) {
      const owner = podOwner(p);
      if (owner && podStatus(p).tone === 'error') m.set(owner, (m.get(owner) ?? 0) + 1);
    }
    return m;
  }, [workloadPods]);
  const usageOf = (name: string) => (metrics?.available ? metrics.items.find((p) => p.name === name) : undefined);
  const openDetail = (item: Record<string, unknown>) => {
    const name = (item.metadata as { name?: string })?.name;
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
  const [restartTarget, setRestartTarget] = useState<string | null>(null);
  const theme = useTheme();
  const { t } = useTranslation();
  const [yamlTarget, setYamlTarget] = useState<YamlEditTarget | null>(null);
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

  const showActionNotice = (msg: string) => {
    setActionNotice(msg);
    setTimeout(() => setActionNotice((v) => (v === msg ? null : v)), 4000);
  };

  const openJobLogs = (namespace: string, name: string) => setLogTarget({ kind: 'jobs', namespace, name });
  const openDeploymentLogs = (namespace: string, name: string) => setLogTarget({ kind: 'deployments', namespace, name });
  const openLogModal = (namespace: string, name: string, previous?: string) =>
    setLogTarget({ kind: 'pods', namespace, name, previous });
  const logContainerRef = React.useRef<HTMLPreElement | null>(null);

  const orderedResources = useMemo(
    () => resourceOrder.filter((resource) => Object.keys(allowedResources).includes(resource)),
    [allowedResources]
  );

  // Search input supports two concepts in a single box:
  //   • plain text  → matches the resource name (what we had before)
  //   • label:k=v   → matches metadata.labels[k] == v exactly
  //   • label:k     → matches any resource with the label key present
  // Multiple tokens are AND'd. "foo label:tier=front label:app"
  // keeps rows whose name contains "foo" AND has tier=front AND has an
  // "app" label.
  const filteredItems = useMemo(() => {
    const q = searchQuery.trim();
    if (!q) return items;
    const tokens = q.split(/\s+/);
    return items.filter((item) => {
      const name = (item.metadata as { name?: string })?.name ?? '';
      const labels = ((item.metadata as { labels?: Record<string, string> })?.labels) ?? {};
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
          if (!name.toLowerCase().includes(t.toLowerCase())) return false;
        }
      }
      return true;
    });
  }, [items, searchQuery]);

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
      setError((err as Error).message || 'Failed to load namespaces.');
      setNamespaces([]);
      setSelectedNamespace(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadNamespaces();
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
        setError((err as Error).message || 'Failed to load permissions.');
      }
    };
    void loadPermissions();
  }, [selectedNamespace]);

  // auto: the periodic refresh, which the server doesn't audit.
  const loadResources = useCallback(async (auto = false) => {
    if (!selectedNamespace || !activeTab) return;
    setLoading(true);
    try {
      let result: { items: Array<Record<string, unknown>> } | null = null;
      if (activeTab === 'pods') result = await listPods(selectedNamespace, auto);
      else if (activeTab === 'deployments') result = await listDeployments(selectedNamespace, auto);
      else if (activeTab === 'daemonsets') result = await listDaemonSets(selectedNamespace);
      else if (activeTab === 'statefulsets') result = await listStatefulSets(selectedNamespace);
      else if (activeTab === 'hpas') result = await listHPAs(selectedNamespace);
      else if (activeTab === 'services') result = await listServices(selectedNamespace);
      else if (activeTab === 'configmaps') result = await listConfigMaps(selectedNamespace);
      else if (activeTab === 'secrets') result = await listSecrets(selectedNamespace);
      else if (activeTab === 'ingresses') result = await listIngresses(selectedNamespace);
      else if (activeTab === 'cronjobs') result = await listCronJobs(selectedNamespace);
      else if (activeTab === 'jobs') result = await listJobs(selectedNamespace);

      // Pods tab: hide pods owned by a Job. Job-created pods clutter the Pods
      // list (CronJob runs, migration helpers, one-shots). They're now visible
      // on their own Jobs tab with proper status chips.
      let items = result?.items ?? [];
      if (activeTab === 'deployments' || activeTab === 'statefulsets' || activeTab === 'daemonsets') {
        listPods(selectedNamespace, true)
          .then((r) => setWorkloadPods(r.items ?? []))
          .catch(() => setWorkloadPods([]));
      }
      if (activeTab === 'pods') {
        items = items.filter((p) => {
          const owners = ((p.metadata as any)?.ownerReferences ?? []) as Array<{ kind?: string }>;
          return !owners.some((o) => o.kind === 'Job');
        });
      }
      setItems(items);
    } catch (err) {
      setItems([]);
      setError((err as Error).message || 'Failed to load resources.');
    }
    setLoading(false);
  }, [activeTab, selectedNamespace]);

  useEffect(() => {
    void loadResources();
  }, [loadResources]);

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
      { key: 'r', handler: () => void loadResources() },
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

  useEffect(() => {
    if (!selectedNamespace || (activeTab !== 'pods' && activeTab !== 'deployments')) return;
    const interval = setInterval(() => {
      void loadResources(true);
    }, 10000);
    return () => clearInterval(interval);
  }, [activeTab, loadResources, selectedNamespace]);

  const closeModal = () => {
    setModalOpen(false);
    setTimeout(() => {
      setModalTitle('');
      setModalContent('');
      setModalLoading(false);
    }, 50);
  };

  const fetchYaml = async (type: string, namespace: string, name: string) => {
    setModalLoading(true);
    setModalContent('');
    try {
      let result: { yaml: string } = { yaml: '' };
      if (type === 'deployments') result = await getDeploymentYaml(namespace, name);
      else if (type === 'daemonsets') result = await getDaemonSetYaml(namespace, name);
      else if (type === 'statefulsets') result = await getStatefulSetYaml(namespace, name);
      else if (type === 'hpas') result = await getHPAYaml(namespace, name);
      else if (type === 'services') result = await getServiceYaml(namespace, name);
      else if (type === 'configmaps') result = await getConfigMapYaml(namespace, name);
      else if (type === 'ingresses') result = await getIngressYaml(namespace, name);
      else if (type === 'cronjobs') result = await getCronJobYaml(namespace, name);
      else if (type === 'jobs') result = await getJobYaml(namespace, name);
      setModalContent(result.yaml);
    } catch (err) {
      setModalContent((err as Error).message);
    } finally {
      setModalLoading(false);
    }
  };

  const openYamlModal = (resource: string, namespace: string, name: string) => {
    const fetchByResource: Record<string, (ns: string, n: string) => Promise<{ yaml: string }>> = {
      deployments: getDeploymentYaml,
      daemonsets: getDaemonSetYaml,
      statefulsets: getStatefulSetYaml,
      hpas: getHPAYaml,
      services: getServiceYaml,
      configmaps: getConfigMapYaml,
      secrets: getSecretYaml,
      ingresses: getIngressYaml,
      cronjobs: getCronJobYaml,
      jobs: getJobYaml,
    };
    const label: Record<string, string> = {
      deployments: 'Deployment',
      daemonsets: 'DaemonSet',
      statefulsets: 'StatefulSet',
      hpas: 'HPA',
      services: 'Service',
      configmaps: 'ConfigMap',
      secrets: 'Secret',
      ingresses: 'Ingress',
      cronjobs: 'CronJob',
      jobs: 'Job',
    };
    const fetcher = fetchByResource[resource];
    if (!fetcher) return;
    setYamlTarget({
      resource,
      resourceLabel: label[resource] ?? resource,
      namespace,
      name,
      fetchYaml: fetcher,
      canEdit: (allowedResources[resource] ?? []).includes('edit'),
    });
  };

  const openConfigMapDataModal = async (namespace: string, name: string) => {
    setModalOpen(true);
    setModalTitle(`ConfigMap Data - ${name}`);
    setModalLoading(true);
    setModalContent('');
    try {
      const result = await getConfigMapData(namespace, name);
      setModalContent(JSON.stringify(result.data, null, 2));
    } catch (err) {
      setModalContent((err as Error).message);
    } finally {
      setModalLoading(false);
    }
  };

  const openEventsModal = async (type: 'pods' | 'deployments', namespace: string, name: string) => {
    setModalOpen(true);
    setModalTitle(`${type.toUpperCase()} Events - ${name}`);
    setModalLoading(true);
    setModalContent('');
    try {
      const result =
        type === 'pods'
          ? await getPodEvents(namespace, name)
          : await getDeploymentEvents(namespace, name);
      setModalContent(JSON.stringify(result.items, null, 2));
    } catch (err) {
      setModalContent((err as Error).message);
    } finally {
      setModalLoading(false);
    }
  };

  const handleModalSelectAll = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (!(event.ctrlKey || event.metaKey) || event.key.toLowerCase() !== 'a') return;
    if (!logContainerRef.current) return;
    event.preventDefault();
    const selection = window.getSelection();
    if (!selection) return;
    const range = document.createRange();
    range.selectNodeContents(logContainerRef.current);
    selection.removeAllRanges();
    selection.addRange(range);
  };

  const refreshModal = async () => {
    if (!selectedNamespace || !modalTitle) return;
    const name = modalTitle.split(' - ')[1];
    if (!name) return;
    if (modalTitle.startsWith('ConfigMap Data')) {
      await openConfigMapDataModal(selectedNamespace, name);
    } else if (modalTitle.startsWith('PODS Events')) {
      await openEventsModal('pods', selectedNamespace, name);
    } else if (modalTitle.startsWith('DEPLOYMENTS Events')) {
      await openEventsModal('deployments', selectedNamespace, name);
    } else if (
      modalTitle.startsWith('DEPLOYMENTS') ||
      modalTitle.startsWith('SERVICES') ||
      modalTitle.startsWith('CONFIGMAPS') ||
      modalTitle.startsWith('INGRESSES') ||
      modalTitle.startsWith('CRONJOBS') ||
      modalTitle.startsWith('JOBS')
    ) {
      const type = modalTitle.split(' ')[0].toLowerCase();
      await fetchYaml(type, selectedNamespace, name);
    }
  };

  // ─── Panel: namespace list ────────────────────────────────────────────────
  const filteredNamespaces = namespaceSearch
    ? namespaces.filter((ns) =>
        ns.toLowerCase().includes(namespaceSearch.trim().toLowerCase())
      )
    : namespaces;

  const namespacePanel = (
    <div className="flex h-full flex-col gap-3 p-3">
      <input
        type="text"
        value={namespaceSearch}
        onChange={(e) => setNamespaceSearch(e.target.value)}
        placeholder={t('dashboard.namespacesSearch')}
        data-shortcut="namespace-search"
        className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 dark:placeholder:text-slate-500 dark:text-slate-100 focus:border-brand-500 focus:outline-none focus:ring-4 focus:ring-brand-500/15"
      />
      <div className="scrollbar-thin flex flex-col gap-0.5 overflow-auto pr-1">
        {filteredNamespaces.length === 0 && (
          <p className="rounded-md px-3 py-2 text-xs text-slate-500 dark:text-slate-400">
            {namespaces.length === 0
              ? t('dashboard.namespacesEmpty')
              : t('dashboard.namespacesNoMatch')}
          </p>
        )}
        {filteredNamespaces.map((ns) => {
          const active = selectedNamespace === ns;
          return (
            <button
              key={ns}
              onClick={() => setSelectedNamespace(ns)}
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

  // ─── Render ───────────────────────────────────────────────────────────────

  return (
    <Layout user={user} panel={namespacePanel} panelTitle="Namespaces" liveEvents={{ open: eventsOpen, connected: eventsLive }}>
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
      {actionError && (
        <Alert severity="error" className="mt-4">
          {actionError}
        </Alert>
      )}
      {actionNotice && (
        <Alert severity="success" className="mt-4">
          {actionNotice}
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
                className="h-9 w-64 pl-8"
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
              onClick={() => void loadResources()}
              disabled={loading || !activeTab}
            >
              <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
              {t('dashboard.refresh')}
            </Button>
          </div>
        </div>

        {/* Tab bar */}
        <div className="border-b border-slate-200 dark:border-slate-800/70 bg-white dark:bg-slate-900">
          <div className="flex items-center gap-1 overflow-x-auto px-3 py-2">
            {orderedResources.length === 0 && (
              <p className="px-2 py-2 text-xs text-slate-500 dark:text-slate-400">
                {t('dashboard.noResourcePerms')}
              </p>
            )}
            {orderedResources.map((resource) => {
              const meta = RESOURCE_META[resource];
              const Icon = meta?.icon ?? Boxes;
              const active = activeTab === resource;
              return (
                <button
                  key={resource}
                  onClick={() => setActiveTab(resource)}
                  className={`group inline-flex shrink-0 items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-semibold uppercase tracking-wide transition-all duration-150 focus:outline-none ${
                    active
                      ? 'bg-brand-50 dark:bg-brand-500/15 text-brand-700 dark:text-brand-200 ring-1 ring-inset ring-brand-200 dark:ring-brand-500/30'
                      : 'text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 dark:bg-slate-800 hover:text-slate-800 dark:hover:text-slate-100 dark:text-slate-100'
                  }`}
                >
                  <Icon
                    size={14}
                    className={active ? 'text-brand-600 dark:text-brand-300' : 'text-slate-500 dark:text-slate-400 group-hover:text-slate-600 dark:text-slate-300'}
                  />
                  {t(`resources.${resource}`, { defaultValue: meta?.label ?? resource })}
                </button>
              );
            })}

            {orderedResources.length > 0 && (
              <div className="ml-auto flex shrink-0 items-center gap-0.5 rounded-lg border border-slate-200 bg-white p-0.5 dark:border-slate-700 dark:bg-slate-800">
                <button
                  type="button"
                  onClick={() => setViewMode('card')}
                  aria-pressed={viewMode === 'card'}
                  aria-label={t('dashboard.cardView')}
                  title={t('dashboard.cardView')}
                  className={`flex h-7 w-7 items-center justify-center rounded-md transition-colors ${
                    viewMode === 'card'
                      ? 'bg-brand-50 text-brand-700 dark:bg-brand-500/15 dark:text-brand-200'
                      : 'text-slate-500 hover:bg-slate-100 hover:text-slate-800 dark:text-slate-400 dark:hover:bg-slate-700 dark:hover:text-slate-100'
                  }`}
                >
                  <LayoutGrid size={14} />
                </button>
                <button
                  type="button"
                  onClick={() => setViewMode('list')}
                  aria-pressed={viewMode === 'list'}
                  aria-label={t('dashboard.listView')}
                  title={t('dashboard.listView')}
                  className={`flex h-7 w-7 items-center justify-center rounded-md transition-colors ${
                    viewMode === 'list'
                      ? 'bg-brand-50 text-brand-700 dark:bg-brand-500/15 dark:text-brand-200'
                      : 'text-slate-500 hover:bg-slate-100 hover:text-slate-800 dark:text-slate-400 dark:hover:bg-slate-700 dark:hover:text-slate-100'
                  }`}
                >
                  <ListIcon size={14} />
                </button>
              </div>
            )}
          </div>
        </div>

        {(activeTab === 'pods' || isWorkloadTab) && metrics && !metrics.available &&
          ['metrics_server_missing', 'forbidden'].includes(metrics.reason ?? '') && (
            <p className="px-5 pt-3 text-xs text-slate-500 dark:text-slate-400">
              {t(`dashboard.usage.unavailable.${metrics.reason}`)}
            </p>
          )}
        {/* Items — card or list view */}
        {viewMode === 'list' && (
          <ResourceListView
            activeTab={activeTab}
            items={filteredItems}
            selectedNamespace={selectedNamespace ?? ''}
            searchQuery={searchQuery}
            loading={loading}
            canExecPods={canExecPods}
            canRestartDeployments={canRestartDeployments}
            canScaleDeployments={canScaleDeployments}
            canScaleStatefulSets={canScaleStatefulSets}
            openYamlModal={openYamlModal}
            openEventsModal={openEventsModal}
            openLogModal={openLogModal}
            onOpen={openDetail}
            metrics={metrics}
            failingByOwner={failingByOwner}
            openConfigMapDataModal={openConfigMapDataModal}
            openSecretModal={(name) => setSecretTarget(name)}
            canEditSecrets={canEditSecrets}
            openDeploymentLogs={openDeploymentLogs}
            openJobLogs={openJobLogs}
            onExec={openShell}
            onRestart={(name) => setRestartTarget(name)}
            onScale={(name, current) => {
              setScaleTarget({ name, current });
              setScaleReplicas(current);
              setActionError(null);
            }}
            onScaleStatefulSet={(name, current) => {
              setScaleTarget({ name, current, kind: 'statefulsets' });
              setScaleReplicas(current);
              setActionError(null);
            }}
          />
        )}
        <div
          className={`grid grid-cols-1 gap-3 p-5 sm:grid-cols-2 xl:grid-cols-3 ${
            viewMode === 'card' ? '' : 'hidden'
          }`}
        >
          {filteredItems.length === 0 && !loading && (
            <div className="col-span-full">
              <div className="flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60 px-6 py-10 text-center">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400">
                  <SearchIcon size={16} />
                </div>
                <p className="text-sm font-medium text-slate-600 dark:text-slate-300">
                  {searchQuery ? t('dashboard.emptyFiltered') : t('dashboard.empty')}
                </p>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  {searchQuery ? t('dashboard.emptyHintSearch') : t('dashboard.emptyHint')}
                </p>
              </div>
            </div>
          )}

          {filteredItems.map((item, index) => {
            const name = (item.metadata as { name?: string })?.name ?? 'Unnamed';
            const pod = activeTab === 'pods' ? podStatus(item) : null;

            const desiredReplicas = (item.spec as { replicas?: number })?.replicas ?? 0;
            const readyReplicas = (item.status as { readyReplicas?: number })?.readyReplicas ?? 0;
            const allReplicasReady = desiredReplicas > 0 && readyReplicas >= desiredReplicas;

            const cronSchedule = (item.spec as { schedule?: string })?.schedule ?? 'N/A';
            const lastSchedule =
              (item.status as { lastScheduleTime?: string })?.lastScheduleTime ?? 'Never';
            const isSuspended = (item.spec as { suspend?: boolean })?.suspend ?? false;

            const ingressRules = (
              item.spec as {
                rules?: Array<{
                  host?: string;
                  http?: { paths?: Array<{ path?: string }> };
                }>;
              }
            )?.rules ?? [];
            const ingressHosts = ingressRules
              .map((r) => r.host)
              .filter(Boolean) as string[];
            const ingressPaths = ingressRules
              .flatMap((r) => r.http?.paths ?? [])
              .map((p) => p.path)
              .filter(Boolean) as string[];

            // Compute status indicator
            let dotClass = '';
            let statusLabel: React.ReactNode = null;
            if (pod) {
              // A healthy pod that has restarted keeps its green dot with an amber ring.
              dotClass =
                pod.tone === 'ok' && pod.restarts > 0
                  ? 'status-dot bg-emerald-500 ring-1 ring-amber-400/50 ring-offset-2 ring-offset-white dark:ring-offset-slate-900'
                  : STATUS_DOT[pod.tone];
              statusLabel = <PodStatusBadge namespace={selectedNamespace ?? ''} podName={name} status={pod} />;
            } else if (activeTab === 'deployments') {
              if (desiredReplicas === 0) {
                dotClass = 'status-dot status-dot-idle';
                statusLabel = <Badge variant="default">{t('dashboard.status.scaledToZero')}</Badge>;
              } else if (allReplicasReady) {
                dotClass = 'status-dot status-dot-success';
                statusLabel = <Badge variant="success">{t('dashboard.status.available')}</Badge>;
              } else {
                dotClass = 'status-dot status-dot-warning';
                statusLabel = <Badge variant="warning">{t('dashboard.status.progressing')}</Badge>;
              }
            } else if (activeTab === 'daemonsets') {
              const dsStatus = (item.status as {
                desiredNumberScheduled?: number;
                numberReady?: number;
              }) ?? {};
              const desired = dsStatus.desiredNumberScheduled ?? 0;
              const ready = dsStatus.numberReady ?? 0;
              if (desired === 0) {
                dotClass = 'status-dot status-dot-idle';
                statusLabel = <Badge variant="default">{t('dashboard.status.noNodes')}</Badge>;
              } else if (ready >= desired) {
                dotClass = 'status-dot status-dot-success';
                statusLabel = <Badge variant="success">{t('dashboard.status.ready', { ready, desired })}</Badge>;
              } else {
                dotClass = 'status-dot status-dot-warning';
                statusLabel = <Badge variant="warning">{t('dashboard.status.ready', { ready, desired })}</Badge>;
              }
            } else if (activeTab === 'statefulsets') {
              const ssStatus = (item.status as { replicas?: number; readyReplicas?: number }) ?? {};
              const ssDesired = (item.spec as { replicas?: number })?.replicas ?? ssStatus.replicas ?? 0;
              const ssReady = ssStatus.readyReplicas ?? 0;
              if (ssDesired === 0) {
                dotClass = 'status-dot status-dot-idle';
                statusLabel = <Badge variant="default">{t('dashboard.status.scaledToZero')}</Badge>;
              } else if (ssReady >= ssDesired) {
                dotClass = 'status-dot status-dot-success';
                statusLabel = <Badge variant="success">{t('dashboard.status.availableCount', { ready: ssReady, desired: ssDesired })}</Badge>;
              } else {
                dotClass = 'status-dot status-dot-warning';
                statusLabel = <Badge variant="warning">{t('dashboard.status.progressingCount', { ready: ssReady, desired: ssDesired })}</Badge>;
              }
            } else if (activeTab === 'hpas') {
              const hpaStatus = (item.status as {
                currentReplicas?: number;
                desiredReplicas?: number;
              }) ?? {};
              const hpaMin = (item.spec as { minReplicas?: number })?.minReplicas;
              const hpaMax = (item.spec as { maxReplicas?: number })?.maxReplicas ?? 0;
              dotClass = 'status-dot status-dot-success';
              statusLabel = (
                <Badge variant="info">
                  {hpaStatus.currentReplicas ?? 0}/{hpaStatus.desiredReplicas ?? 0}
                  {' · '}
                  {hpaMin ?? 1}–{hpaMax}
                </Badge>
              );
            } else if (activeTab === 'cronjobs') {
              dotClass = isSuspended ? 'status-dot status-dot-warning' : 'status-dot status-dot-success';
              statusLabel = isSuspended ? (
                <Badge variant="warning">{t('dashboard.status.suspended')}</Badge>
              ) : (
                <Badge variant="success">{t('dashboard.status.active')}</Badge>
              );
            } else if (activeTab === 'jobs') {
              const jobStatus = (item.status as {
                succeeded?: number;
                failed?: number;
                active?: number;
                completionTime?: string;
              }) ?? {};
              const succeeded = jobStatus.succeeded ?? 0;
              const failed = jobStatus.failed ?? 0;
              const activeCount = jobStatus.active ?? 0;
              if (failed > 0) {
                dotClass = 'status-dot status-dot-error';
                statusLabel = <Badge variant="error">{t('dashboard.status.failedN', { count: failed })}</Badge>;
              } else if (activeCount > 0) {
                dotClass = 'status-dot status-dot-warning';
                statusLabel = <Badge variant="warning">{t('dashboard.status.runningN', { count: activeCount })}</Badge>;
              } else if (succeeded > 0) {
                dotClass = 'status-dot status-dot-success';
                statusLabel = <Badge variant="success">{t('dashboard.status.succeeded')}</Badge>;
              } else {
                dotClass = 'status-dot status-dot-idle';
                statusLabel = <Badge variant="default">{t('dashboard.status.pending')}</Badge>;
              }
            }

            // A workload whose pods are failing says so, whatever its rollout status.
            const failingPods = isWorkloadTab ? failingByOwner.get(`${KIND[activeTab as WorkloadKind]}/${name}`) ?? 0 : 0;
            if (failingPods > 0) {
              dotClass = STATUS_DOT.error;
              statusLabel = (
                <span className="inline-flex items-center gap-1 whitespace-nowrap">
                  {statusLabel}
                  <Badge variant="error">{t('dashboard.detail.podsFailing', { count: failingPods })}</Badge>
                </span>
              );
            }
            const showDot = ['pods', 'deployments', 'daemonsets', 'statefulsets', 'hpas', 'cronjobs', 'jobs'].includes(activeTab);
            const createdAt = (item.metadata as { creationTimestamp?: string })?.creationTimestamp;

            return (
              <div
                key={index}
                className="group relative flex flex-col gap-3 rounded-xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-slate-900 p-4 shadow-card transition-all duration-150 hover:-translate-y-[1px] hover:border-brand-200 dark:border-brand-500/30 hover:shadow-elevated"
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex min-w-0 flex-1 items-center gap-2">
                    {showDot && <span className={`shrink-0 ${dotClass}`} />}
                    {activeTab === 'pods' || isWorkloadTab ? (
                      <button
                        type="button"
                        onClick={() => openDetail(item)}
                        className="truncate rounded font-mono text-[13px] font-semibold text-slate-900 underline-offset-2 hover:text-brand-700 hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 dark:text-slate-100 dark:hover:text-brand-300"
                        title={name}
                      >
                        {name}
                      </button>
                    ) : (
                      <span
                        className="truncate font-mono text-[13px] font-semibold text-slate-900 dark:text-slate-100"
                        title={name}
                      >
                        {name}
                      </span>
                    )}
                  </div>
                  <div className="shrink-0 whitespace-nowrap">{statusLabel}</div>
                </div>

                <div className="flex flex-col gap-1 text-[11px] text-slate-500 dark:text-slate-400">
                  <div className="flex items-center gap-1.5">
                    <Calendar size={11} className="text-slate-500 dark:text-slate-400" />
                    <span>{formatAge(createdAt)}</span>
                  </div>

                  {pod && (
                    <div className="flex items-center gap-1.5">
                      <RefreshCw size={11} className="text-slate-500 dark:text-slate-400" />
                      <span>Restarts:</span>
                      <PodRestarts status={pod} />
                    </div>
                  )}
                  {metrics?.available && (activeTab === 'pods' || isWorkloadTab) && (() => {
                    const owner = isWorkloadTab ? `${KIND[activeTab as WorkloadKind]}/${name}` : '';
                    const used = activeTab === 'pods' ? usageOf(name) : ownerUsage(metrics.items, owner);
                    const budget =
                      activeTab === 'pods'
                        ? podResources((item.spec as any)?.containers)
                        : scaleResources(
                            podResources((item.spec as any)?.template?.spec?.containers),
                            ownerUsage(metrics.items, owner).pods,
                          );
                    if (!used || (isWorkloadTab && !(used as { pods: number }).pods)) return null;
                    return (
                      <div className="grid grid-cols-2 gap-3 pt-0.5">
                        <UsageBar kind="cpu" used={used.cpu} limit={budget.cpu.limit} request={budget.cpu.request} />
                        <UsageBar kind="mem" used={used.memory} limit={budget.mem.limit} request={budget.mem.request} />
                      </div>
                    );
                  })()}
                  {activeTab === 'deployments' && (
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                      <span className="rounded-md bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-700 dark:text-slate-200">
                        desired {desiredReplicas}
                      </span>
                      <span className="rounded-md bg-emerald-50 px-1.5 py-0.5 font-mono text-[10px] text-emerald-700 ring-1 ring-inset ring-emerald-200">
                        ready {readyReplicas}
                      </span>
                      <span className="rounded-md bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-700 dark:text-slate-200">
                        available {(item.status as { availableReplicas?: number })?.availableReplicas ?? 0}
                      </span>
                    </div>
                  )}
                  {activeTab === 'ingresses' && (
                    <>
                      <div className="truncate">
                        <span className="text-slate-500 dark:text-slate-400">Hosts:</span>{' '}
                        <span className="font-mono text-slate-700 dark:text-slate-200">
                          {ingressHosts.length > 0 ? ingressHosts.join(', ') : 'N/A'}
                        </span>
                      </div>
                      <div className="truncate">
                        <span className="text-slate-500 dark:text-slate-400">Paths:</span>{' '}
                        <span className="font-mono text-slate-700 dark:text-slate-200">
                          {ingressPaths.length > 0 ? ingressPaths.join(', ') : 'N/A'}
                        </span>
                      </div>
                    </>
                  )}
                  {activeTab === 'secrets' && (
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                      <span className="truncate rounded-md bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-700 dark:bg-slate-800 dark:text-slate-200">
                        {String(item.type ?? '')}
                      </span>
                      <span>{t('secrets.keyCount', { count: ((item.keys as unknown[]) ?? []).length })}</span>
                    </div>
                  )}
                  {activeTab === 'cronjobs' && (
                    <>
                      <div>
                        <span className="text-slate-500 dark:text-slate-400">Schedule:</span>{' '}
                        <span className="font-mono text-slate-700 dark:text-slate-200">{cronSchedule}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 dark:text-slate-400">Last run:</span>{' '}
                        <span className="font-mono text-slate-700 dark:text-slate-200">{lastSchedule}</span>
                      </div>
                    </>
                  )}
                  {activeTab === 'jobs' && (() => {
                    const spec = (item.spec as { completions?: number; parallelism?: number; backoffLimit?: number }) ?? {};
                    const st = (item.status as {
                      succeeded?: number; failed?: number; active?: number;
                      startTime?: string; completionTime?: string;
                    }) ?? {};
                    return (
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                        <span className="rounded-md bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-700 dark:text-slate-200">
                          completions {st.succeeded ?? 0}/{spec.completions ?? 1}
                        </span>
                        {(st.active ?? 0) > 0 && (
                          <span className="rounded-md bg-amber-50 px-1.5 py-0.5 font-mono text-[10px] text-amber-800 ring-1 ring-inset ring-amber-200">
                            active {st.active}
                          </span>
                        )}
                        {(st.failed ?? 0) > 0 && (
                          <span className="rounded-md bg-rose-50 px-1.5 py-0.5 font-mono text-[10px] text-rose-700 ring-1 ring-inset ring-rose-200">
                            failed {st.failed}
                          </span>
                        )}
                        {st.completionTime && (
                          <span className="text-slate-500 dark:text-slate-400">
                            done {st.completionTime}
                          </span>
                        )}
                      </div>
                    );
                  })()}
                </div>

                <div className="mt-auto flex flex-wrap gap-2 pt-1">
                  {activeTab === 'pods' && (
                    <>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openLogModal(selectedNamespace ?? '', name)}
                      >
                        <Terminal size={13} />
                        {t('dashboard.actions.logs')}
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openEventsModal('pods', selectedNamespace ?? '', name)}
                      >
                        <Activity size={13} />
                        {t('dashboard.actions.events')}
                      </Button>
                      {canExecPods && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={(e) => openShell(item, e.currentTarget)}
                        >
                          <Terminal size={13} />
                          {t('dashboard.actions.shell')}
                        </Button>
                      )}
                    </>
                  )}
                  {activeTab === 'deployments' && (
                    <>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openYamlModal('deployments', selectedNamespace ?? '', name)}
                      >
                        <FileCode2 size={13} />
                        {t('dashboard.actions.yaml')}
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openDeploymentLogs(selectedNamespace ?? '', name)}
                      >
                        <Terminal size={13} />
                        {t('dashboard.actions.logs')}
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() =>
                          openEventsModal('deployments', selectedNamespace ?? '', name)
                        }
                      >
                        <Activity size={13} />
                        {t('dashboard.actions.events')}
                      </Button>
                      {canScaleDeployments && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            setScaleTarget({ name, current: desiredReplicas });
                            setScaleReplicas(desiredReplicas);
                            setActionError(null);
                          }}
                        >
                          <Scaling size={13} />
                          {t('dashboard.actions.scale')}
                        </Button>
                      )}
                      {canRestartDeployments && (
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={actionBusy === `restart:${name}`}
                          onClick={() => setRestartTarget(name)}
                        >
                          <RotateCcw size={13} />
                          {actionBusy === `restart:${name}` ? t('dashboard.actions.restarting') : t('dashboard.actions.restart')}
                        </Button>
                      )}
                    </>
                  )}
                  {activeTab === 'daemonsets' && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => openYamlModal('daemonsets', selectedNamespace ?? '', name)}
                    >
                      <FileCode2 size={13} />
                      {t('dashboard.actions.yaml')}
                    </Button>
                  )}
                  {activeTab === 'statefulsets' && (
                    <>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openYamlModal('statefulsets', selectedNamespace ?? '', name)}
                      >
                        <FileCode2 size={13} />
                        {t('dashboard.actions.yaml')}
                      </Button>
                      {canScaleStatefulSets && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            const current = ((item.spec as { replicas?: number })?.replicas) ?? 0;
                            setScaleTarget({ name, current, kind: 'statefulsets' });
                            setScaleReplicas(current);
                            setActionError(null);
                          }}
                        >
                          <Scaling size={13} />
                          {t('dashboard.actions.scale')}
                        </Button>
                      )}
                    </>
                  )}
                  {activeTab === 'hpas' && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => openYamlModal('hpas', selectedNamespace ?? '', name)}
                    >
                      <FileCode2 size={13} />
                      {t('dashboard.actions.yaml')}
                    </Button>
                  )}
                  {activeTab === 'services' && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => openYamlModal('services', selectedNamespace ?? '', name)}
                    >
                      <FileCode2 size={13} />
                      {t('dashboard.actions.yaml')}
                    </Button>
                  )}
                  {activeTab === 'ingresses' && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => openYamlModal('ingresses', selectedNamespace ?? '', name)}
                    >
                      <FileCode2 size={13} />
                      {t('dashboard.actions.yaml')}
                    </Button>
                  )}
                  {activeTab === 'configmaps' && (
                    <>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openConfigMapDataModal(selectedNamespace ?? '', name)}
                      >
                        <FileText size={13} />
                        {t('dashboard.actions.data')}
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openYamlModal('configmaps', selectedNamespace ?? '', name)}
                      >
                        <FileCode2 size={13} />
                        {t('dashboard.actions.yaml')}
                      </Button>
                    </>
                  )}
                  {activeTab === 'secrets' && (
                    <>
                      <Button variant="outline" size="sm" onClick={() => setSecretTarget(name)}>
                        <KeyRound size={13} />
                        {t('secrets.keys')}
                      </Button>
                      {/* The YAML carries every value, so it is gated on edit, not get. */}
                      {canEditSecrets && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => openYamlModal('secrets', selectedNamespace ?? '', name)}
                        >
                          <FileCode2 size={13} />
                          {t('dashboard.actions.yaml')}
                        </Button>
                      )}
                    </>
                  )}
                  {activeTab === 'cronjobs' && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => openYamlModal('cronjobs', selectedNamespace ?? '', name)}
                    >
                      <FileCode2 size={13} />
                      {t('dashboard.actions.yaml')}
                    </Button>
                  )}
                  {activeTab === 'jobs' && (
                    <>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openYamlModal('jobs', selectedNamespace ?? '', name)}
                      >
                        <FileCode2 size={13} />
                        {t('dashboard.actions.yaml')}
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openJobLogs(selectedNamespace ?? '', name)}
                      >
                        <Terminal size={13} />
                        {t('dashboard.actions.logs')}
                      </Button>
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── Modal ─────────────────────────────────────────────────── */}
      {/* Live-translate the modal title: setModalTitle stores an English
          kind-marker like "Pod Logs - foo", which the branching logic below
          already parses. Here we recompute the user-facing title from that
          marker on every render so a locale switch while the modal is open
          updates the title without a refresh. */}
      <Modal
        open={modalOpen}
        onClose={closeModal}
        title={(() => {
          if (!modalTitle) return '';
          const dashAt = modalTitle.indexOf(' - ');
          if (dashAt < 0) return modalTitle;
          const kind = modalTitle.slice(0, dashAt);
          const name = modalTitle.slice(dashAt + 3);
          const map: Record<string, string> = {
            'ConfigMap Data': 'configmapData',
            'PODS Events': 'podEvents',
            'DEPLOYMENTS Events': 'deploymentEvents',
          };
          const key = map[kind];
          return key ? t(`dashboard.modalTitles.${key}`, { name }) : modalTitle;
        })()}
        onKeyDown={handleModalSelectAll}
        footer={
          <>
            <Button variant="outline" size="sm" onClick={refreshModal}>
              <RefreshCw size={14} />
              Refresh
            </Button>
            <Button variant="primary" size="sm" onClick={closeModal}>
              Close
            </Button>
          </>
        }
      >
        {modalLoading ? (
          <div className="flex h-full items-center justify-center">
            <Spinner size="md" />
          </div>
        ) : (
          <div className="flex h-full flex-col gap-3">
            <pre
              ref={logContainerRef}
              className="flex-1 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-4 font-mono text-xs leading-5 text-slate-100 shadow-inner"
              style={{ whiteSpace: 'pre' }}
            >
              {modalContent || 'No data'}
            </pre>
          </div>
        )}
      </Modal>

      <LogViewer
        namespace={logTarget?.namespace ?? ''}
        target={logTarget}
        pod={
          logTarget?.kind === 'pods'
            ? [...(activeTab === 'pods' ? items : []), detailObj ?? {}].find(
                (it) => (it.metadata as { name?: string } | undefined)?.name === logTarget.name,
              )
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
          onLogs={(name, previous) => openLogModal(selectedNamespace ?? '', name, previous)}
          onShell={openShell}
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
          onOpenPod={(pod) => setDetail({ kind: 'pods', name: pod.metadata?.name, obj: pod })}
          onLogs={(name) => openDeploymentLogs(selectedNamespace ?? '', name)}
          onYaml={(name) => openYamlModal(detail.kind, selectedNamespace ?? '', name)}
          onRestart={(name) => setRestartTarget(name)}
          onScale={(name, current) => {
            setScaleTarget(detail.kind === 'statefulsets' ? { name, current, kind: 'statefulsets' } : { name, current });
            setScaleReplicas(current);
            setActionError(null);
          }}
        />
      )}

      {/* ── Restart confirm modal ─────────────────────────────────── */}
      {restartTarget && (
        <Modal
          open={restartTarget !== null}
          onClose={() => (actionBusy ? undefined : setRestartTarget(null))}
          title={t('dashboard.restartConfirm.title', { name: restartTarget })}
          size="sm"
          footer={
            <>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setRestartTarget(null)}
                disabled={actionBusy !== null}
              >
                {t('actions.cancel')}
              </Button>
              <Button
                variant="primary"
                size="sm"
                disabled={actionBusy !== null}
                onClick={async () => {
                  if (!selectedNamespace || !restartTarget) return;
                  const name = restartTarget;
                  setActionBusy(`restart:${name}`);
                  setActionError(null);
                  try {
                    await restartDeployment(selectedNamespace, name);
                    showActionNotice(`Restart triggered for ${name}.`);
                    setRestartTarget(null);
                    await loadResources();
                  } catch (err) {
                    setActionError((err as Error).message || 'Restart failed.');
                  } finally {
                    setActionBusy(null);
                  }
                }}
              >
                {actionBusy ? t('dashboard.actions.restarting') : t('dashboard.actions.restart')}
              </Button>
            </>
          }
        >
          <p className="text-sm text-slate-700 dark:text-slate-200">
            {t('dashboard.restartConfirm.message', { name: restartTarget })}
          </p>
        </Modal>
      )}

      {/* ── Secret keys modal ─────────────────────────────────────── */}
      <SecretModal
        open={secretTarget !== null}
        onClose={() => setSecretTarget(null)}
        namespace={selectedNamespace ?? ''}
        name={secretTarget ?? ''}
        canReveal={canRevealSecrets}
      />

      {/* ── Pod exec (shell) modal ─────────────────────────────────── */}
      {shellPick && (
        <ContainerPicker
          pod={shellPick.pod}
          anchor={shellPick.anchor}
          onClose={() => setShellPick(null)}
          onPick={(container) => {
            const containers = (shellPick.pod.spec?.containers ?? []).map((c: { name: string }) => c.name);
            setExecTarget({ name: shellPick.pod.metadata?.name ?? '', containers, container });
            setShellPick(null);
          }}
        />
      )}
      <PodExecModal
        key={execTarget ? `${execTarget.name}/${execTarget.container}` : ''}
        open={execTarget !== null}
        onClose={() => setExecTarget(null)}
        namespace={selectedNamespace ?? ''}
        pod={execTarget?.name ?? ''}
        containers={execTarget?.containers ?? []}
        container={execTarget?.container}
      />

      {/* ── Scale modal ───────────────────────────────────────────── */}
      {scaleTarget && (
        <Modal
          open={scaleTarget !== null}
          onClose={() => (scaleBusy ? undefined : setScaleTarget(null))}
          title={`Scale · ${scaleTarget.name}`}
          size="sm"
          footer={
            <>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setScaleTarget(null)}
                disabled={scaleBusy}
              >
                Cancel
              </Button>
              <Button
                variant="primary"
                size="sm"
                disabled={scaleBusy || scaleReplicas === scaleTarget.current}
                onClick={async () => {
                  if (!selectedNamespace || !scaleTarget) return;
                  setScaleBusy(true);
                  setActionError(null);
                  try {
                    if (scaleTarget.kind === 'statefulsets') {
                      await scaleStatefulSet(selectedNamespace, scaleTarget.name, scaleReplicas);
                    } else {
                      await scaleDeployment(selectedNamespace, scaleTarget.name, scaleReplicas);
                    }
                    showActionNotice(
                      `Scaled ${scaleTarget.name}: ${scaleTarget.current} → ${scaleReplicas} replicas.`
                    );
                    setScaleTarget(null);
                    await loadResources();
                  } catch (err) {
                    setActionError((err as Error).message || 'Scale failed.');
                  } finally {
                    setScaleBusy(false);
                  }
                }}
              >
                {scaleBusy ? 'Applying…' : 'Apply'}
              </Button>
            </>
          }
        >
          <div className="flex flex-col gap-4">
            <div className="flex items-center justify-between gap-4 rounded-lg bg-slate-50 dark:bg-slate-800/40 px-3 py-2">
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                  Current
                </p>
                <p className="font-mono text-lg font-semibold text-slate-900 dark:text-slate-100">
                  {scaleTarget.current}
                </p>
              </div>
              <span className="text-slate-400">→</span>
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wide text-brand-600 dark:text-brand-300">
                  Target
                </p>
                <div className="mt-0.5 flex items-center gap-1.5">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setScaleReplicas(Math.max(0, scaleReplicas - 1))}
                  >
                    <Minus size={12} />
                  </Button>
                  <input
                    type="number"
                    min={0}
                    max={100}
                    value={scaleReplicas}
                    onChange={(e) =>
                      setScaleReplicas(Math.max(0, Math.min(100, Number(e.target.value) || 0)))
                    }
                    onKeyDown={(e) => {
                      // Shift+↑/↓ jumps by 10 for faster scaling in large deployments.
                      if (!e.shiftKey) return;
                      if (e.key === 'ArrowUp') {
                        e.preventDefault();
                        setScaleReplicas((v) => Math.min(100, v + 10));
                      } else if (e.key === 'ArrowDown') {
                        e.preventDefault();
                        setScaleReplicas((v) => Math.max(0, v - 10));
                      }
                    }}
                    className="w-16 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2 py-1 text-center font-mono text-base font-semibold focus:border-brand-500 focus:outline-none focus:ring-4 focus:ring-brand-500/15 dark:text-slate-100"
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setScaleReplicas(Math.min(100, scaleReplicas + 1))}
                  >
                    <Plus size={12} />
                  </Button>
                </div>
              </div>
            </div>

            {scaleReplicas === 0 && (
              <Alert severity="warning">
                Scaling to <strong>0</strong> stops all pods — the deployment goes offline.
              </Alert>
            )}
            {scaleReplicas > scaleTarget.current + 5 && (
              <Alert severity="info">
                Large step: {scaleTarget.current} → {scaleReplicas}.
              </Alert>
            )}
          </div>
        </Modal>
      )}

      <LiveEventsPanel
        namespace={selectedNamespace}
        open={eventsOpen}
        onClose={() => setEventsOpen(false)}
        onConnectedChange={setEventsLive}
      />

      <YamlEditModal
        target={yamlTarget}
        onClose={() => setYamlTarget(null)}
        onApplied={() => void loadResources()}
        theme={theme.effective}
      />
    </Layout>
  );
};

export default DashboardPage;
