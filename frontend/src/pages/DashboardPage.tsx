import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControlLabel,
  Switch,
  Tab,
  Tabs,
  TextField,
  Typography
} from '@mui/material';
import Layout from '../components/Layout';
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
  getDeploymentEvents
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

  const orderedResources = useMemo(() =>
    resourceOrder.filter((resource) => Object.keys(allowedResources).includes(resource)),
    [allowedResources]
  );

  const filteredItems = useMemo(() => {
    if (!searchQuery.trim()) {
      return items;
    }
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
      if (!selectedNamespace) {
        return;
      }
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
    if (!selectedNamespace || !activeTab) {
      return;
    }
    setLoading(true);
    try {
      let result: { items: Array<Record<string, unknown>> } | null = null;
      if (activeTab === 'pods') {
        result = await listPods(selectedNamespace);
      } else if (activeTab === 'deployments') {
        result = await listDeployments(selectedNamespace);
      } else if (activeTab === 'services') {
        result = await listServices(selectedNamespace);
      } else if (activeTab === 'configmaps') {
        result = await listConfigMaps(selectedNamespace);
      } else if (activeTab === 'ingresses') {
        result = await listIngresses(selectedNamespace);
      } else if (activeTab === 'cronjobs') {
        result = await listCronJobs(selectedNamespace);
      }
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
    if (!selectedNamespace || (activeTab !== 'pods' && activeTab !== 'deployments')) {
      return;
    }
    const interval = setInterval(() => {
      void loadResources();
    }, 10000);
    return () => clearInterval(interval);
  }, [activeTab, loadResources, selectedNamespace]);

  useEffect(() => {
    if (!logContainerRef.current) {
      return;
    }
    if (autoScroll) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
      return;
    }
    if (modalOpen) {
      logContainerRef.current.scrollTop = 0;
    }
  }, [modalContent, autoScroll, modalOpen]);

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
      if (type === 'deployments') {
        result = await getDeploymentYaml(namespace, name);
      } else if (type === 'services') {
        result = await getServiceYaml(namespace, name);
      } else if (type === 'configmaps') {
        result = await getConfigMapYaml(namespace, name);
      } else if (type === 'ingresses') {
        result = await getIngressYaml(namespace, name);
      } else if (type === 'cronjobs') {
        result = await getCronJobYaml(namespace, name);
      }
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
        type === 'pods' ? await getPodEvents(namespace, name) : await getDeploymentEvents(namespace, name);
      setModalContent(JSON.stringify(result.items, null, 2));
    } catch (err) {
      setModalContent((err as Error).message);
    } finally {
      setModalLoading(false);
    }
  };

  const refreshModal = async () => {
    if (!selectedNamespace || !modalTitle) {
      return;
    }
    const name = modalTitle.split(' - ')[1];
    if (!name) {
      return;
    }
    if (modalTitle.startsWith('ConfigMap Data')) {
      await openConfigMapDataModal(selectedNamespace, name);
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

  return (
    <Layout
      user={user}
      namespaces={namespaces}
      activeNamespace={selectedNamespace}
      onNamespaceChange={(ns) => setSelectedNamespace(ns)}
      namespaceSearch={namespaceSearch}
      onNamespaceSearchChange={setNamespaceSearch}
    >
      <Typography variant="h5" fontWeight={600} gutterBottom>
        Cluster Overview
      </Typography>
      <Typography variant="body2" color="text.secondary" gutterBottom>
        Select a namespace to view authorized resources. Unauthorized resources never appear.
      </Typography>
      {error && (
        <Alert severity="warning" sx={{ mt: 2 }}>
          {error}
        </Alert>
      )}

      <Card sx={{ mt: 3, boxShadow: 2 }}>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center">
            <Box display="flex" alignItems="center" gap={2} flexWrap="wrap">
              <Typography variant="h6" fontWeight={600}>
                {selectedNamespace ?? 'No namespace available'}
              </Typography>
              <TextField
                size="small"
                placeholder={`Search ${activeTab}`}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </Box>
            {loading && <CircularProgress size={20} />}
          </Box>
          <Divider sx={{ my: 2 }} />
          <Tabs
            value={activeTab}
            onChange={(_, value) => setActiveTab(value)}
            textColor="primary"
            indicatorColor="primary"
          >
            {orderedResources.map((resource) => (
              <Tab key={resource} value={resource} label={resource.toUpperCase()} />
            ))}
          </Tabs>
          <Divider sx={{ my: 2 }} />
          <Box display="grid" gap={2}>
            {filteredItems.length === 0 && !loading && (
              <Typography variant="body2" color="text.secondary">
                {searchQuery ? 'No matching records found.' : 'No records available for this resource.'}
              </Typography>
            )}
            {filteredItems.map((item, index) => {
              const name = (item.metadata as { name?: string })?.name ?? 'Unnamed';
              const containerStatuses = (item.status as { containerStatuses?: Array<{ ready?: boolean; restartCount?: number }> })
                ?.containerStatuses ?? [];
              const restartCount = containerStatuses.reduce((sum, status) => sum + (status.restartCount ?? 0), 0);
              const allReady = containerStatuses.length > 0 && containerStatuses.every((status) => status.ready);
              const isRunning = (item.status as { phase?: string })?.phase === 'Running';
              const isHealthy = allReady && isRunning;
              const healthyColor = '#16a34a';
              const warningColor = '#f97316';
              const neutralColor = '#111827';
              const desiredReplicas = (item.spec as { replicas?: number })?.replicas ?? 0;
              const readyReplicas = (item.status as { readyReplicas?: number })?.readyReplicas ?? 0;
              const allReplicasReady = desiredReplicas > 0 && readyReplicas >= desiredReplicas;
              const cronSchedule = (item.spec as { schedule?: string })?.schedule ?? 'N/A';
              const lastSchedule = (item.status as { lastScheduleTime?: string })?.lastScheduleTime ?? 'Never';
              const isSuspended = (item.spec as { suspend?: boolean })?.suspend ?? false;
              const ingressRules = (item.spec as { rules?: Array<{ host?: string; http?: { paths?: Array<{ path?: string }> } }> })
                ?.rules ?? [];
              const ingressHosts = ingressRules.map((rule) => rule.host).filter(Boolean) as string[];
              const ingressPaths = ingressRules
                .flatMap((rule) => rule.http?.paths ?? [])
                .map((path) => path.path)
                .filter(Boolean) as string[];
              return (
              <Box
                key={index}
                sx={{
                  p: 2,
                  borderRadius: 2,
                  border: '1px solid #e0e5f2',
                  backgroundColor: '#fff'
                }}
              >
                {activeTab === 'pods' && (
                  <Box display="flex" alignItems="center" gap={1}>
                    <Box
                      sx={{
                        width: 12,
                        height: 12,
                        borderRadius: '50%',
                        backgroundColor: isHealthy ? healthyColor : warningColor,
                        border: isHealthy && restartCount > 0 ? `2px solid ${warningColor}` : `1px solid ${isHealthy ? healthyColor : warningColor}`,
                        boxSizing: 'border-box',
                        flexShrink: 0
                      }}
                    />
                    <Typography variant="subtitle2" fontWeight={600}>
                      {name}
                    </Typography>
                  </Box>
                )}
                {activeTab === 'deployments' && (
                  <Box display="flex" alignItems="center" gap={1}>
                    <Box
                      sx={{
                        width: 12,
                        height: 12,
                        borderRadius: '50%',
                        backgroundColor: desiredReplicas === 0 ? 'transparent' : allReplicasReady ? healthyColor : warningColor,
                        border: desiredReplicas === 0 ? `2px solid ${neutralColor}` : `1px solid ${allReplicasReady ? healthyColor : warningColor}`,
                        boxSizing: 'border-box',
                        flexShrink: 0
                      }}
                    />
                    <Typography variant="subtitle2" fontWeight={600}>
                      {name}
                    </Typography>
                  </Box>
                )}
                {(activeTab !== 'pods' && activeTab !== 'deployments' && activeTab !== 'cronjobs') && (
                  <Typography variant="subtitle2" fontWeight={600}>
                    {name}
                  </Typography>
                )}
                {activeTab === 'cronjobs' && (
                  <Box display="flex" alignItems="center" gap={1}>
                    <Box
                      sx={{
                        width: 12,
                        height: 12,
                        borderRadius: '50%',
                        backgroundColor: isSuspended ? warningColor : healthyColor,
                        border: `1px solid ${isSuspended ? warningColor : healthyColor}`,
                        boxSizing: 'border-box',
                        flexShrink: 0
                      }}
                    />
                    <Typography variant="subtitle2" fontWeight={600}>
                      {name}
                    </Typography>
                  </Box>
                )}
                <Typography variant="body2" color="text.secondary">
                  {(item.metadata as { creationTimestamp?: string })?.creationTimestamp ?? 'N/A'}
                </Typography>
                {activeTab === 'pods' && (
                  <Typography variant="body2" color="text.secondary">
                    Restarts: {restartCount}
                  </Typography>
                )}
                {activeTab === 'deployments' && (
                  <Typography variant="body2" color="text.secondary">
                    Replicas: {desiredReplicas} | Ready: {readyReplicas} | Available:{' '}
                    {(item.status as { availableReplicas?: number })?.availableReplicas ?? 0}
                  </Typography>
                )}
                {activeTab === 'ingresses' && (
                  <>
                    <Typography variant="body2" color="text.secondary">
                      Hosts: {ingressHosts.length > 0 ? ingressHosts.join(', ') : 'N/A'}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Paths: {ingressPaths.length > 0 ? ingressPaths.join(', ') : 'N/A'}
                    </Typography>
                  </>
                )}
                {activeTab === 'cronjobs' && (
                  <>
                    <Typography variant="body2" color="text.secondary">
                      Schedule: {cronSchedule}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Last schedule: {lastSchedule}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Status: {isSuspended ? 'Disabled' : 'Enabled'}
                    </Typography>
                  </>
                )}
                <Box mt={2} display="flex" gap={1} flexWrap="wrap">
                  {activeTab === 'pods' && (
                    <Button size="small" variant="outlined" onClick={() => openLogModal(selectedNamespace ?? '', name)}>
                      Logs
                    </Button>
                  )}
                  {activeTab === 'pods' && (
                    <Button size="small" variant="outlined" onClick={() => openEventsModal('pods', selectedNamespace ?? '', name)}>
                      Events
                    </Button>
                  )}
                  {activeTab === 'deployments' && (
                    <Button size="small" variant="outlined" onClick={() => openYamlModal('deployments', selectedNamespace ?? '', name)}>
                      YAML
                    </Button>
                  )}
                  {activeTab === 'deployments' && (
                    <Button size="small" variant="outlined" onClick={() => openEventsModal('deployments', selectedNamespace ?? '', name)}>
                      Events
                    </Button>
                  )}
                  {activeTab === 'services' && (
                    <Button size="small" variant="outlined" onClick={() => openYamlModal('services', selectedNamespace ?? '', name)}>
                      YAML
                    </Button>
                  )}
                  {activeTab === 'ingresses' && (
                    <Button size="small" variant="outlined" onClick={() => openYamlModal('ingresses', selectedNamespace ?? '', name)}>
                      YAML
                    </Button>
                  )}
                  {activeTab === 'configmaps' && (
                    <>
                      <Button size="small" variant="outlined" onClick={() => openConfigMapDataModal(selectedNamespace ?? '', name)}>
                        Data
                      </Button>
                      <Button size="small" variant="outlined" onClick={() => openYamlModal('configmaps', selectedNamespace ?? '', name)}>
                        YAML
                      </Button>
                    </>
                  )}
                  {activeTab === 'cronjobs' && (
                    <Button size="small" variant="outlined" onClick={() => openYamlModal('cronjobs', selectedNamespace ?? '', name)}>
                      YAML
                    </Button>
                  )}
                </Box>
              </Box>
            )})}
          </Box>
        </CardContent>
      </Card>
      <Dialog
        open={modalOpen}
        onClose={closeModal}
        fullWidth
        maxWidth={false}
        PaperProps={{ sx: { width: '95vw', height: '95vh', maxWidth: '95vw', maxHeight: '95vh' } }}
      >
        <DialogTitle>{modalTitle}</DialogTitle>
        <DialogContent dividers>
          {modalLoading ? (
            <CircularProgress size={20} />
          ) : (
            <>
              {modalTitle.startsWith('Pod Logs') && (
                <Box display="flex" gap={2} alignItems="center" mb={2}>
                  <FormControlLabel
                    control={<Switch checked={!logPaused} onChange={(e) => setLogPaused(!e.target.checked)} />}
                    label={logPaused ? 'Paused' : 'Live'}
                  />
                  <FormControlLabel
                    control={<Switch checked={autoScroll} onChange={(e) => setAutoScroll(e.target.checked)} />}
                    label="Auto-scroll"
                  />
                  <FormControlLabel
                    control={<Switch checked={wordWrap} onChange={(e) => setWordWrap(e.target.checked)} />}
                    label="Word wrap"
                  />
                </Box>
              )}
              <pre
                ref={logContainerRef}
                style={{
                  maxHeight: '90%',
                  height: '90%',
                  overflow: 'auto',
                  whiteSpace: wordWrap ? 'pre-wrap' : 'pre',
                  fontFamily: 'monospace',
                  fontSize: '1.0em'
                }}
              >
                {modalContent || 'No data'}
              </pre>
            </>
          )}
        </DialogContent>
        <DialogActions>
          {modalTitle.startsWith('Pod Logs') ? (
            <Button onClick={() => connectLogs(selectedNamespace ?? '', modalTitle.split(' - ')[1] ?? '')}>Reconnect</Button>
          ) : (
            <Button onClick={refreshModal}>Refresh</Button>
          )}
          <Button onClick={closeModal}>Close</Button>
        </DialogActions>
      </Dialog>
    </Layout>
  );
};

export default DashboardPage;
