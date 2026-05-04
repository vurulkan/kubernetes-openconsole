import React, { useCallback, useEffect, useMemo, useState } from 'react';
import Layout from '../components/Layout';
import { Alert, Button, Input, Modal, Spinner, Toggle } from '../components/ui';
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
  getDeploymentYaml,
  getServiceYaml,
  getConfigMapYaml,
  getIngressYaml,
  getCronJobYaml,
  getConfigMapData,
  getPodEvents,
  getDeploymentEvents,
} from '../services/api';
import { useNavigate } from 'react-router-dom';

const resourceOrder = ['pods', 'deployments', 'services', 'configmaps', 'ingresses', 'cronjobs'];

const DashboardPage: React.FC<{ user: User }> = ({ user }) => {
  const navigate = useNavigate();
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [selectedNamespace, setSelectedNamespace] = useState<string | null>(null);
  const [allowedResources, setAllowedResources] = useState<Record<string, string[]>>({});
  const [activeTab, setActiveTab] = useState<string>('');
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
      const defaultNamespace = result.namespaces[0] ?? null;
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

  useEffect(() => {
    const loadPermissions = async () => {
      if (!selectedNamespace) return;
      try {
        const permissions = await getNamespacePermissions(selectedNamespace);
        setAllowedResources(permissions.resources);
        const first = resourceOrder.find((resource) => permissions.resources[resource]);
        setActiveTab(first ?? '');
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
      setItems(result?.items ?? []);
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
      modalTitle.startsWith('CRONJOBS')
    ) {
      const type = modalTitle.split(' ')[0].toLowerCase();
      await fetchYaml(type, selectedNamespace, name);
    }
  };

  // ─── Render ───────────────────────────────────────────────────────────────

  return (
    <Layout
      user={user}
      namespaces={namespaces}
      activeNamespace={selectedNamespace}
      onNamespaceChange={(ns) => setSelectedNamespace(ns)}
      namespaceSearch={namespaceSearch}
      onNamespaceSearchChange={setNamespaceSearch}
    >
      <h1 className="text-xl font-semibold text-gray-900">Cluster Overview</h1>
      <p className="mt-1 text-sm text-gray-500">
        Select a namespace to view authorized resources. Unauthorized resources never appear.
      </p>

      {error && (
        <Alert severity="warning" className="mt-4">
          {error}
        </Alert>
      )}

      {/* ── Resource card ─────────────────────────────────────────── */}
      <div className="mt-6 rounded-xl border border-gray-200 bg-white shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4">
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-base font-semibold text-gray-900">
              {selectedNamespace ?? 'No namespace available'}
            </span>
            <Input
              placeholder={`Search ${activeTab}`}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-48"
            />
          </div>
          {loading && <Spinner size="sm" />}
        </div>

        {/* Tab bar */}
        <div className="border-t border-gray-100">
          <div className="flex gap-0 overflow-x-auto px-4">
            {orderedResources.map((resource) => (
              <button
                key={resource}
                onClick={() => setActiveTab(resource)}
                className={`shrink-0 border-b-2 px-4 py-3 text-xs font-semibold uppercase tracking-wide transition-colors focus:outline-none ${
                  activeTab === resource
                    ? 'border-blue-600 text-blue-600'
                    : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'
                }`}
              >
                {resource}
              </button>
            ))}
          </div>
        </div>

        {/* Items grid */}
        <div className="flex flex-col gap-3 p-5">
          {filteredItems.length === 0 && !loading && (
            <p className="text-sm text-gray-400">
              {searchQuery ? 'No matching records found.' : 'No records available for this resource.'}
            </p>
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

            // Status dot color
            let dotColor = '';
            let dotRing = '';
            if (activeTab === 'pods') {
              dotColor = isHealthy ? 'bg-green-500' : 'bg-orange-400';
              dotRing = isHealthy && restartCount > 0 ? 'ring-2 ring-orange-400' : '';
            } else if (activeTab === 'deployments') {
              dotColor =
                desiredReplicas === 0
                  ? 'bg-transparent border-2 border-gray-400'
                  : allReplicasReady
                  ? 'bg-green-500'
                  : 'bg-orange-400';
            } else if (activeTab === 'cronjobs') {
              dotColor = isSuspended ? 'bg-orange-400' : 'bg-green-500';
            }

            const showDot = ['pods', 'deployments', 'cronjobs'].includes(activeTab);

            return (
              <div
                key={index}
                className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm"
              >
                <div className="flex items-center gap-2">
                  {showDot && (
                    <span
                      className={`h-2.5 w-2.5 shrink-0 rounded-full ${dotColor} ${dotRing}`}
                    />
                  )}
                  <span className="text-sm font-semibold text-gray-900">{name}</span>
                </div>

                <p className="mt-1 text-xs text-gray-400">
                  {(item.metadata as { creationTimestamp?: string })?.creationTimestamp ?? 'N/A'}
                </p>

                {activeTab === 'pods' && (
                  <p className="text-xs text-gray-500">Restarts: {restartCount}</p>
                )}
                {activeTab === 'deployments' && (
                  <p className="text-xs text-gray-500">
                    Replicas: {desiredReplicas} | Ready: {readyReplicas} | Available:{' '}
                    {(item.status as { availableReplicas?: number })?.availableReplicas ?? 0}
                  </p>
                )}
                {activeTab === 'ingresses' && (
                  <>
                    <p className="text-xs text-gray-500">
                      Hosts: {ingressHosts.length > 0 ? ingressHosts.join(', ') : 'N/A'}
                    </p>
                    <p className="text-xs text-gray-500">
                      Paths: {ingressPaths.length > 0 ? ingressPaths.join(', ') : 'N/A'}
                    </p>
                  </>
                )}
                {activeTab === 'cronjobs' && (
                  <>
                    <p className="text-xs text-gray-500">Schedule: {cronSchedule}</p>
                    <p className="text-xs text-gray-500">Last schedule: {lastSchedule}</p>
                    <p className="text-xs text-gray-500">
                      Status: {isSuspended ? 'Disabled' : 'Enabled'}
                    </p>
                  </>
                )}

                <div className="mt-3 flex flex-wrap gap-2">
                  {activeTab === 'pods' && (
                    <>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openLogModal(selectedNamespace ?? '', name)}
                      >
                        Logs
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openEventsModal('pods', selectedNamespace ?? '', name)}
                      >
                        Events
                      </Button>
                    </>
                  )}
                  {activeTab === 'deployments' && (
                    <>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openYamlModal('deployments', selectedNamespace ?? '', name)}
                      >
                        YAML
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() =>
                          openEventsModal('deployments', selectedNamespace ?? '', name)
                        }
                      >
                        Events
                      </Button>
                    </>
                  )}
                  {activeTab === 'services' && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => openYamlModal('services', selectedNamespace ?? '', name)}
                    >
                      YAML
                    </Button>
                  )}
                  {activeTab === 'ingresses' && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => openYamlModal('ingresses', selectedNamespace ?? '', name)}
                    >
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
                        Data
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openYamlModal('configmaps', selectedNamespace ?? '', name)}
                      >
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
                      YAML
                    </Button>
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
            {modalTitle.startsWith('Pod Logs') ? (
              <Button
                variant="outline"
                size="sm"
                onClick={() =>
                  connectLogs(selectedNamespace ?? '', modalTitle.split(' - ')[1] ?? '')
                }
              >
                Reconnect
              </Button>
            ) : (
              <Button variant="outline" size="sm" onClick={refreshModal}>
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
            {modalTitle.startsWith('Pod Logs') && (
              <div className="flex flex-wrap items-center gap-4">
                <Toggle
                  checked={!logPaused}
                  onChange={(v) => setLogPaused(!v)}
                  label={logPaused ? 'Paused' : 'Live'}
                />
                <Toggle
                  checked={autoScroll}
                  onChange={setAutoScroll}
                  label="Auto-scroll"
                />
                <Toggle
                  checked={wordWrap}
                  onChange={setWordWrap}
                  label="Word wrap"
                />
              </div>
            )}
            <pre
              ref={logContainerRef}
              className="flex-1 overflow-auto rounded-lg bg-gray-950 p-4 font-mono text-xs leading-5 text-gray-100"
              style={{ whiteSpace: wordWrap ? 'pre-wrap' : 'pre' }}
            >
              {modalContent || 'No data'}
            </pre>
          </div>
        )}
      </Modal>
    </Layout>
  );
};

export default DashboardPage;
