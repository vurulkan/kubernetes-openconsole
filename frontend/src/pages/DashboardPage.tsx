import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  Boxes,
  Calendar,
  FileCode2,
  FileText,
  Globe,
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
import { PodNotReadyBadge } from '../components/PodNotReadyBadge';
import { Alert, Badge, Button, Input, Modal, Spinner, Toggle } from '../components/ui';
import { useScopedShortcuts } from '../hooks/useScopedShortcuts';
import { dispatchOpenPalette } from '../hooks/useGlobalShortcuts';
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
  listIngresses,
  listCronJobs,
  listJobs,
  getDeploymentYaml,
  getServiceYaml,
  getConfigMapYaml,
  getIngressYaml,
  getCronJobYaml,
  getJobYaml,
  getConfigMapData,
  getPodEvents,
  getDeploymentEvents,
  restartDeployment,
  scaleDeployment,
} from '../services/api';
import { useNavigate } from 'react-router-dom';

const resourceOrder = ['pods', 'deployments', 'services', 'configmaps', 'ingresses', 'cronjobs', 'jobs'];

const RESOURCE_META: Record<
  string,
  { label: string; icon: React.ComponentType<{ size?: number; className?: string }> }
> = {
  pods: { label: 'Pods', icon: Boxes },
  deployments: { label: 'Deployments', icon: LayoutGrid },
  services: { label: 'Services', icon: Globe },
  configmaps: { label: 'ConfigMaps', icon: FileText },
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
  const [namespaceSearch, setNamespaceSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [modalTitle, setModalTitle] = useState('');
  const [modalContent, setModalContent] = useState('');
  const [modalLoading, setModalLoading] = useState(false);
  const [logPaused, setLogPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(false);
  const [wordWrap, setWordWrap] = useState(false);
  const [scaleTarget, setScaleTarget] = useState<{
    name: string;
    current: number;
  } | null>(null);
  const [scaleReplicas, setScaleReplicas] = useState(1);
  const [scaleBusy, setScaleBusy] = useState(false);
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const canRestartDeployments = (allowedResources.deployments ?? []).includes('restart');
  const canScaleDeployments = (allowedResources.deployments ?? []).includes('scale');
  const canExecPods = (allowedResources.pods ?? []).includes('exec');
  const [execTarget, setExecTarget] = useState<{ name: string; containers: string[] } | null>(null);
  const [viewMode, setViewMode] = useState<'card' | 'list'>(() => {
    try {
      const stored = localStorage.getItem('dashboardViewMode');
      return stored === 'list' ? 'list' : 'card';
    } catch (err) {
      return 'card';
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
  const [eventsOpen, setEventsOpen] = useState<boolean>(() => {
    try {
      return localStorage.getItem('dashboardEventsOpen') === '1';
    } catch (err) {
      return false;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem('dashboardEventsOpen', eventsOpen ? '1' : '0');
    } catch (err) {
      /* ignore */
    }
  }, [eventsOpen]);

  const showActionNotice = (msg: string) => {
    setActionNotice(msg);
    setTimeout(() => setActionNotice((v) => (v === msg ? null : v)), 4000);
  };

  // Job "Logs" opens one WebSocket to the backend fan-out that follows every
  // pod of the job (label-selected by job-name). Same visual as deployment
  // logs; the modal title prefix drives the Reconnect handler.
  const openJobLogs = (ns: string, jobName: string) => {
    if (logSocketRef.current) {
      logSocketRef.current.close();
      logSocketRef.current = null;
    }
    setModalOpen(true);
    setModalTitle(`Job Logs - ${jobName}`);
    setModalContent('');
    setAutoScroll(true);
    setLogPaused(false);

    const token = localStorage.getItem('authToken') ?? '';
    if (!token) {
      setModalContent('[log stream error] Missing auth token.\n');
      return;
    }
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const wsUrl = `${protocol}://${window.location.host}/ws/namespaces/${ns}/jobs/${jobName}/logs?tail=100&token=${encodeURIComponent(token)}`;
    const socket = new WebSocket(wsUrl);
    socket.onopen = () => {
      setModalContent((prev) => (prev ? `${prev}\n` : '') + '[log stream connected]\n');
    };
    socket.onmessage = (event) => {
      if (!logPausedRef.current) {
        setModalContent((prev) => `${prev}${event.data}`);
      }
    };
    socket.onerror = () => {
      setModalContent((prev) => `${prev}\n[log stream error]\n`);
    };
    socket.onclose = (event) => {
      if (event.code !== 1000) {
        setModalContent((prev) => `${prev}\n[log stream closed: ${event.code}]\n`);
      }
    };
    logSocketRef.current = socket;
  };

  // Deployment "Logs" opens one WebSocket to a backend fan-out that follows
  // every pod × container of the deployment and prefixes each line with
  // `[pod/container]`, matching the behavior of
  //    kubectl logs -f -l <selector> --all-containers --prefix
  const openDeploymentLogs = (ns: string, deploymentName: string) => {
    if (logSocketRef.current) {
      logSocketRef.current.close();
      logSocketRef.current = null;
    }
    setModalOpen(true);
    setModalTitle(`Deployment Logs - ${deploymentName}`);
    setModalContent('');
    setAutoScroll(true);
    setLogPaused(false);

    const token = localStorage.getItem('authToken') ?? '';
    if (!token) {
      setModalContent('[log stream error] Missing auth token.\n');
      return;
    }
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const wsUrl = `${protocol}://${window.location.host}/ws/namespaces/${ns}/deployments/${deploymentName}/logs?tail=100&token=${encodeURIComponent(token)}`;
    const socket = new WebSocket(wsUrl);
    socket.onopen = () => {
      setModalContent((prev) => (prev ? `${prev}\n` : '') + '[log stream connected]\n');
    };
    socket.onmessage = (event) => {
      if (!logPausedRef.current) {
        setModalContent((prev) => `${prev}${event.data}`);
      }
    };
    socket.onerror = () => {
      setModalContent((prev) => `${prev}\n[log stream error]\n`);
    };
    socket.onclose = (event) => {
      if (event.code !== 1000) {
        setModalContent((prev) => `${prev}\n[log stream closed: ${event.code}]\n`);
      }
    };
    logSocketRef.current = socket;
  };
  const logContainerRef = React.useRef<HTMLPreElement | null>(null);
  const logSocketRef = React.useRef<WebSocket | null>(null);
  const logPausedRef = React.useRef(false);

  const orderedResources = useMemo(
    () => resourceOrder.filter((resource) => Object.keys(allowedResources).includes(resource)),
    [allowedResources]
  );

  const filteredItems = useMemo(() => {
    if (!searchQuery.trim()) return items;
    const query = searchQuery.trim().toLowerCase();
    return items.filter((item) => {
      const name = (item.metadata as { name?: string })?.name ?? '';
      return name.toLowerCase().includes(query);
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

  const loadResources = useCallback(async () => {
    if (!selectedNamespace || !activeTab) return;
    setLoading(true);
    try {
      let result: { items: Array<Record<string, unknown>> } | null = null;
      if (activeTab === 'pods') result = await listPods(selectedNamespace);
      else if (activeTab === 'deployments') result = await listDeployments(selectedNamespace);
      else if (activeTab === 'services') result = await listServices(selectedNamespace);
      else if (activeTab === 'configmaps') result = await listConfigMaps(selectedNamespace);
      else if (activeTab === 'ingresses') result = await listIngresses(selectedNamespace);
      else if (activeTab === 'cronjobs') result = await listCronJobs(selectedNamespace);
      else if (activeTab === 'jobs') result = await listJobs(selectedNamespace);

      // Pods tab: hide pods owned by a Job. Job-created pods clutter the Pods
      // list (CronJob runs, migration helpers, one-shots). They're now visible
      // on their own Jobs tab with proper status chips.
      let items = result?.items ?? [];
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
    setSearchQuery('');
  }, [activeTab, selectedNamespace]);

  // Log modal shortcuts: p toggles pause, w toggles word-wrap. Must run even
  // though a modal is open, so we attach via a dedicated effect that only
  // listens while the log modal is visible.
  useEffect(() => {
    const isLog =
      modalOpen &&
      (modalTitle.startsWith('Pod Logs') ||
        modalTitle.startsWith('Deployment Logs') ||
        modalTitle.startsWith('Job Logs'));
    if (!isLog) return;
    const handler = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const tgt = e.target as HTMLElement | null;
      if (tgt && (tgt.tagName === 'INPUT' || tgt.tagName === 'TEXTAREA' || tgt.isContentEditable)) return;
      if (e.key === 'p' || e.key === 'P') {
        e.preventDefault();
        setLogPaused((v) => !v);
      } else if (e.key === 'w' || e.key === 'W') {
        e.preventDefault();
        setWordWrap((v) => !v);
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [modalOpen, modalTitle]);

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
      { key: 'n', handler: () => dispatchOpenPalette() },
    ],
    true
  );

  useEffect(() => {
    if (!selectedNamespace || (activeTab !== 'pods' && activeTab !== 'deployments')) return;
    const interval = setInterval(() => {
      void loadResources();
    }, 10000);
    return () => clearInterval(interval);
  }, [activeTab, loadResources, selectedNamespace]);

  useEffect(() => {
    if (!logContainerRef.current) return;
    if (autoScroll) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [modalContent, autoScroll]);

  useEffect(() => {
    if (!modalOpen || !logContainerRef.current) return;
    if (modalTitle.startsWith('Pod Logs')) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [modalOpen, modalTitle]);

  useEffect(() => {
    logPausedRef.current = logPaused;
  }, [logPaused]);

  const closeModal = () => {
    setModalOpen(false);
    setLogPaused(false);
    setAutoScroll(false);
    setWordWrap(false);
    if (logSocketRef.current) {
      logSocketRef.current.close();
      logSocketRef.current = null;
    }
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

  const openYamlModal = async (type: string, namespace: string, name: string) => {
    setModalOpen(true);
    setModalTitle(`${type.toUpperCase()} YAML - ${name}`);
    setAutoScroll(false);
    await fetchYaml(type, namespace, name);
  };

  const openConfigMapDataModal = async (namespace: string, name: string) => {
    setModalOpen(true);
    setModalTitle(`ConfigMap Data - ${name}`);
    setAutoScroll(false);
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

  const connectLogs = (namespace: string, name: string) => {
    if (logSocketRef.current) {
      logSocketRef.current.close();
    }
    const token = localStorage.getItem('authToken') ?? '';
    if (!token) {
      setModalContent('[log stream error] Missing auth token.\n');
      return;
    }
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const wsUrl = `${protocol}://${window.location.host}/ws/namespaces/${namespace}/pods/${name}/logs?tail=100&token=${encodeURIComponent(token)}`;
    const socket = new WebSocket(wsUrl);
    socket.onopen = () => {
      setModalContent((prev) => (prev ? `${prev}\n` : '') + '[log stream connected]\n');
    };
    socket.onmessage = (event) => {
      if (!logPausedRef.current) {
        setModalContent((prev) => `${prev}${event.data}`);
      }
    };
    socket.onerror = () => {
      setModalContent((prev) => `${prev}\n[log stream error]\n`);
    };
    socket.onclose = (event) => {
      if (event.code !== 1000) {
        setModalContent((prev) => `${prev}\n[log stream closed: ${event.code}]\n`);
      }
    };
    logSocketRef.current = socket;
  };

  const openLogModal = (namespace: string, name: string) => {
    setModalOpen(true);
    setModalTitle(`Pod Logs - ${name}`);
    setModalContent('');
    setAutoScroll(true);
    setLogPaused(false);
    connectLogs(namespace, name);
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
        placeholder="Search namespaces…"
        className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm placeholder:text-slate-400 dark:placeholder:text-slate-500 dark:text-slate-500 focus:border-brand-500 focus:outline-none focus:ring-4 focus:ring-brand-500/15"
      />
      <div className="scrollbar-thin flex flex-col gap-0.5 overflow-auto pr-1">
        {filteredNamespaces.length === 0 && (
          <p className="rounded-md px-3 py-2 text-xs text-slate-400 dark:text-slate-500">
            {namespaces.length === 0
              ? 'No namespaces available.'
              : 'No namespaces match your search.'}
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
    <Layout user={user} panel={namespacePanel} panelTitle="Namespaces">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-medium text-slate-500 dark:text-slate-400">
            <Activity size={14} className="text-brand-600 dark:text-brand-300" />
            <span className="uppercase tracking-wider">Overview</span>
          </div>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">
            Cluster Resources
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Pick a namespace to inspect its authorized resources. Unauthorized resources are hidden.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Badge variant="info" className="gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-brand-500" />
            {namespaces.length} namespaces
          </Badge>
          {selectedNamespace && (
            <Badge variant="default" className="gap-1.5">
              <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">ns</span>
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
                {selectedNamespace ?? 'No namespace available'}
              </span>
            </div>
            <div className="relative">
              <SearchIcon
                size={14}
                className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500"
              />
              <Input
                placeholder={activeTab ? `Search ${activeTab}…` : 'Search…'}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="h-9 w-56 pl-8"
                data-shortcut="dashboard-search"
              />
            </div>
          </div>
          <div className="flex items-center gap-3">
            {(activeTab === 'pods' || activeTab === 'deployments') && (
              <span className="hidden items-center gap-1.5 text-[11px] font-medium text-slate-500 dark:text-slate-400 sm:inline-flex">
                <span className="h-1.5 w-1.5 animate-live rounded-full bg-emerald-500" />
                Auto-refresh 10s
              </span>
            )}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => void loadResources()}
              disabled={loading || !activeTab}
            >
              <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
              Refresh
            </Button>
          </div>
        </div>

        {/* Tab bar */}
        <div className="border-b border-slate-200 dark:border-slate-800/70 bg-white dark:bg-slate-900">
          <div className="flex items-center gap-1 overflow-x-auto px-3 py-2">
            {orderedResources.length === 0 && (
              <p className="px-2 py-2 text-xs text-slate-400 dark:text-slate-500">
                You have no resource permissions in this namespace.
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
                    className={active ? 'text-brand-600 dark:text-brand-300' : 'text-slate-400 dark:text-slate-500 group-hover:text-slate-600 dark:text-slate-300'}
                  />
                  {meta?.label ?? resource}
                </button>
              );
            })}

            {orderedResources.length > 0 && (
              <div className="ml-auto flex shrink-0 items-center gap-0.5 rounded-lg border border-slate-200 bg-white p-0.5 dark:border-slate-700 dark:bg-slate-800">
                <button
                  type="button"
                  onClick={() => setViewMode('card')}
                  aria-pressed={viewMode === 'card'}
                  title="Card view"
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
                  title="List view"
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
            openYamlModal={openYamlModal}
            openEventsModal={openEventsModal}
            openLogModal={openLogModal}
            openConfigMapDataModal={openConfigMapDataModal}
            openDeploymentLogs={openDeploymentLogs}
            openJobLogs={openJobLogs}
            onExec={(name, containers) => setExecTarget({ name, containers })}
            onRestart={(name) => setRestartTarget(name)}
            onScale={(name, current) => {
              setScaleTarget({ name, current });
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
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-slate-100 dark:bg-slate-800 text-slate-400 dark:text-slate-500">
                  <SearchIcon size={16} />
                </div>
                <p className="text-sm font-medium text-slate-600 dark:text-slate-300">
                  {searchQuery ? 'No matching records found.' : 'No records available.'}
                </p>
                <p className="text-xs text-slate-400 dark:text-slate-500">
                  {searchQuery ? 'Try a different search term.' : 'The namespace is empty or no records match your access.'}
                </p>
              </div>
            </div>
          )}

          {filteredItems.map((item, index) => {
            const name = (item.metadata as { name?: string })?.name ?? 'Unnamed';
            const containerStatuses = (
              item.status as {
                containerStatuses?: Array<{ ready?: boolean; restartCount?: number }>;
              }
            )?.containerStatuses ?? [];
            const restartCount = containerStatuses.reduce(
              (sum, s) => sum + (s.restartCount ?? 0),
              0
            );
            const allReady =
              containerStatuses.length > 0 && containerStatuses.every((s) => s.ready);
            const isRunning = (item.status as { phase?: string })?.phase === 'Running';
            const isHealthy = allReady && isRunning;

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
            if (activeTab === 'pods') {
              if (isHealthy) {
                // Healthy pod — if it has restarted at least once, show an
                // amber ring around the green dot so operators notice recent
                // crash recovery at a glance.
                dotClass =
                  restartCount > 0
                    ? 'status-dot bg-emerald-500 ring-1 ring-amber-400/50 ring-offset-2 ring-offset-white dark:ring-offset-slate-900'
                    : 'status-dot status-dot-success';
                statusLabel = (
                  <Badge variant={restartCount > 0 ? 'warning' : 'success'}>
                    <span
                      className={`h-1.5 w-1.5 animate-live rounded-full ${
                        restartCount > 0 ? 'bg-amber-500' : 'bg-emerald-500'
                      }`}
                    />
                    {restartCount > 0 ? `Running · ${restartCount} restart${restartCount > 1 ? 's' : ''}` : 'Running'}
                  </Badge>
                );
              } else {
                dotClass = 'status-dot status-dot-warning';
                statusLabel = (
                  <PodNotReadyBadge namespace={selectedNamespace ?? ''} podName={name} />
                );
              }
            } else if (activeTab === 'deployments') {
              if (desiredReplicas === 0) {
                dotClass = 'status-dot status-dot-idle';
                statusLabel = <Badge variant="default">Scaled to 0</Badge>;
              } else if (allReplicasReady) {
                dotClass = 'status-dot status-dot-success';
                statusLabel = <Badge variant="success">Available</Badge>;
              } else {
                dotClass = 'status-dot status-dot-warning';
                statusLabel = <Badge variant="warning">Progressing</Badge>;
              }
            } else if (activeTab === 'cronjobs') {
              dotClass = isSuspended ? 'status-dot status-dot-warning' : 'status-dot status-dot-success';
              statusLabel = isSuspended ? (
                <Badge variant="warning">Suspended</Badge>
              ) : (
                <Badge variant="success">Active</Badge>
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
                statusLabel = <Badge variant="error">Failed · {failed}</Badge>;
              } else if (activeCount > 0) {
                dotClass = 'status-dot status-dot-warning';
                statusLabel = <Badge variant="warning">Running · {activeCount}</Badge>;
              } else if (succeeded > 0) {
                dotClass = 'status-dot status-dot-success';
                statusLabel = <Badge variant="success">Succeeded</Badge>;
              } else {
                dotClass = 'status-dot status-dot-idle';
                statusLabel = <Badge variant="default">Pending</Badge>;
              }
            }

            const showDot = ['pods', 'deployments', 'cronjobs', 'jobs'].includes(activeTab);
            const createdAt = (item.metadata as { creationTimestamp?: string })?.creationTimestamp;

            return (
              <div
                key={index}
                className="group relative flex flex-col gap-3 rounded-xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-slate-900 p-4 shadow-card transition-all duration-150 hover:-translate-y-[1px] hover:border-brand-200 dark:border-brand-500/30 hover:shadow-elevated"
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex min-w-0 flex-1 items-center gap-2">
                    {showDot && <span className={`shrink-0 ${dotClass}`} />}
                    <span
                      className="truncate font-mono text-[13px] font-semibold text-slate-900 dark:text-slate-100"
                      title={name}
                    >
                      {name}
                    </span>
                  </div>
                  <div className="shrink-0 whitespace-nowrap">{statusLabel}</div>
                </div>

                <div className="flex flex-col gap-1 text-[11px] text-slate-500 dark:text-slate-400">
                  <div className="flex items-center gap-1.5">
                    <Calendar size={11} className="text-slate-400 dark:text-slate-500" />
                    <span>{formatAge(createdAt)}</span>
                  </div>

                  {activeTab === 'pods' && (
                    <div className="flex items-center gap-1.5">
                      <RefreshCw size={11} className="text-slate-400 dark:text-slate-500" />
                      <span>Restarts: <span className="font-medium text-slate-700 dark:text-slate-200">{restartCount}</span></span>
                    </div>
                  )}
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
                        <span className="text-slate-400 dark:text-slate-500">Hosts:</span>{' '}
                        <span className="font-mono text-slate-700 dark:text-slate-200">
                          {ingressHosts.length > 0 ? ingressHosts.join(', ') : 'N/A'}
                        </span>
                      </div>
                      <div className="truncate">
                        <span className="text-slate-400 dark:text-slate-500">Paths:</span>{' '}
                        <span className="font-mono text-slate-700 dark:text-slate-200">
                          {ingressPaths.length > 0 ? ingressPaths.join(', ') : 'N/A'}
                        </span>
                      </div>
                    </>
                  )}
                  {activeTab === 'cronjobs' && (
                    <>
                      <div>
                        <span className="text-slate-400 dark:text-slate-500">Schedule:</span>{' '}
                        <span className="font-mono text-slate-700 dark:text-slate-200">{cronSchedule}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 dark:text-slate-500">Last run:</span>{' '}
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
                          <span className="text-slate-400 dark:text-slate-500">
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
                        Logs
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openEventsModal('pods', selectedNamespace ?? '', name)}
                      >
                        <Activity size={13} />
                        Events
                      </Button>
                      {canExecPods && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            const containers = (
                              (item.spec as {
                                containers?: Array<{ name?: string }>;
                              })?.containers ?? []
                            )
                              .map((c) => c.name)
                              .filter(Boolean) as string[];
                            setExecTarget({ name, containers });
                          }}
                        >
                          <Terminal size={13} />
                          Shell
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
                        YAML
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openDeploymentLogs(selectedNamespace ?? '', name)}
                      >
                        <Terminal size={13} />
                        Logs
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() =>
                          openEventsModal('deployments', selectedNamespace ?? '', name)
                        }
                      >
                        <Activity size={13} />
                        Events
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
                          Scale
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
                          {actionBusy === `restart:${name}` ? 'Restarting…' : 'Restart'}
                        </Button>
                      )}
                    </>
                  )}
                  {activeTab === 'services' && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => openYamlModal('services', selectedNamespace ?? '', name)}
                    >
                      <FileCode2 size={13} />
                      YAML
                    </Button>
                  )}
                  {activeTab === 'ingresses' && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => openYamlModal('ingresses', selectedNamespace ?? '', name)}
                    >
                      <FileCode2 size={13} />
                      YAML
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
                        Data
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openYamlModal('configmaps', selectedNamespace ?? '', name)}
                      >
                        <FileCode2 size={13} />
                        YAML
                      </Button>
                    </>
                  )}
                  {activeTab === 'cronjobs' && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => openYamlModal('cronjobs', selectedNamespace ?? '', name)}
                    >
                      <FileCode2 size={13} />
                      YAML
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
                        YAML
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openJobLogs(selectedNamespace ?? '', name)}
                      >
                        <Terminal size={13} />
                        Logs
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
      <Modal
        open={modalOpen}
        onClose={closeModal}
        title={modalTitle}
        onKeyDown={handleModalSelectAll}
        footer={
          <>
            {modalTitle.startsWith('Pod Logs') ||
            modalTitle.startsWith('Deployment Logs') ||
            modalTitle.startsWith('Job Logs') ? (
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  const name = modalTitle.split(' - ')[1] ?? '';
                  if (modalTitle.startsWith('Deployment Logs')) {
                    openDeploymentLogs(selectedNamespace ?? '', name);
                  } else if (modalTitle.startsWith('Job Logs')) {
                    openJobLogs(selectedNamespace ?? '', name);
                  } else {
                    connectLogs(selectedNamespace ?? '', name);
                  }
                }}
              >
                <RefreshCw size={14} />
                Reconnect
              </Button>
            ) : (
              <Button variant="outline" size="sm" onClick={refreshModal}>
                <RefreshCw size={14} />
                Refresh
              </Button>
            )}
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
            {(modalTitle.startsWith('Pod Logs') ||
              modalTitle.startsWith('Deployment Logs') ||
              modalTitle.startsWith('Job Logs')) && (
              <div className="flex flex-wrap items-center gap-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 px-3 py-2">
                <Toggle
                  checked={!logPaused}
                  onChange={(v) => setLogPaused(!v)}
                  label={logPaused ? 'Paused' : 'Live'}
                />
                <Toggle checked={autoScroll} onChange={setAutoScroll} label="Auto-scroll" />
                <Toggle checked={wordWrap} onChange={setWordWrap} label="Word wrap" />
                {!logPaused && (
                  <span className="ml-auto inline-flex items-center gap-1.5 text-[11px] text-emerald-600">
                    <span className="h-1.5 w-1.5 animate-live rounded-full bg-emerald-500" />
                    Streaming
                  </span>
                )}
              </div>
            )}
            <pre
              ref={logContainerRef}
              className="flex-1 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-4 font-mono text-xs leading-5 text-slate-100 shadow-inner"
              style={{ whiteSpace: wordWrap ? 'pre-wrap' : 'pre' }}
            >
              {modalContent || 'No data'}
            </pre>
          </div>
        )}
      </Modal>

      {/* ── Restart confirm modal ─────────────────────────────────── */}
      {restartTarget && (
        <Modal
          open={restartTarget !== null}
          onClose={() => (actionBusy ? undefined : setRestartTarget(null))}
          title={`Restart deployment · ${restartTarget}`}
          size="sm"
          footer={
            <>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setRestartTarget(null)}
                disabled={actionBusy !== null}
              >
                Cancel
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
                {actionBusy ? 'Restarting…' : 'Restart'}
              </Button>
            </>
          }
        >
          <p className="text-sm text-slate-700 dark:text-slate-200">
            This triggers a rolling restart. All pods managed by this deployment are
            replaced one at a time while service remains available.
          </p>
        </Modal>
      )}

      {/* ── Pod exec (shell) modal ─────────────────────────────────── */}
      <PodExecModal
        open={execTarget !== null}
        onClose={() => setExecTarget(null)}
        namespace={selectedNamespace ?? ''}
        pod={execTarget?.name ?? ''}
        containers={execTarget?.containers ?? []}
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
                    await scaleDeployment(selectedNamespace, scaleTarget.name, scaleReplicas);
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
        onToggle={() => setEventsOpen(true)}
        onClose={() => setEventsOpen(false)}
      />
    </Layout>
  );
};

export default DashboardPage;
