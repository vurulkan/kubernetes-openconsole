export type User = {
  id: number;
  username: string;
  mustChangePassword: boolean;
  isActive: boolean;
  isAdmin: boolean;
  /** Where the user signs in. Only local users can have their password reset. */
  authSource?: 'local' | 'ldap' | 'azure';
  activeClusterId?: number;
};

export type NamespacePermission = {
  id: number;
  roleId: number;
  clusterId: number; // 0 = "all clusters" (wildcard)
  clusterName?: string; // decorated by backend for display
  namespace: string;
  resource: string;
  action: string;
};

export type SessionSettings = {
  sessionMinutes: number;
};

export type LDAPConfig = {
  enabled: boolean;
  url: string;
  host: string;
  port: number;
  useSsl: boolean;
  startTls: boolean;
  sslSkipVerify: boolean;
  timeoutSeconds: number;
  bindDn: string;
  bindPassword: string;
  userBaseDn: string;
  userBaseDns: string[];
  userFilter: string;
  usernameAttribute: string;
  passwordConfigured?: boolean;
};

export type AzureADConfig = {
  enabled: boolean;
  tenantId: string;
  clientId: string;
  clientSecret: string;
  redirectUrl: string;
  passwordConfigured?: boolean;
};

export type KubeClusterStatus = {
  method: string;
  server: string;
  active: boolean;
  ready?: boolean;
  lastError?: string;
};

export const hasToken = () => Boolean(getToken());

const BASE_URL = '';

const getToken = () => localStorage.getItem('authToken') ?? '';

const apiRequest = async <T>(path: string, options: RequestInit = {}): Promise<T> => {
  let response: Response;
  try {
    response = await fetch(`${BASE_URL}${path}`, {
      ...options,
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
        ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {})
      }
    });
  } catch (error) {
    const target = `${window.location.origin}${path}`;
    throw new Error(`Network error while contacting the server: ${target}`);
  }

  if (!response.ok) {
    const contentType = response.headers.get('content-type') || '';
    const messageText = await response.text();
    if (contentType.includes('application/json')) {
      try {
        const parsed = JSON.parse(messageText) as { error?: string };
        throw new Error(parsed.error || response.statusText);
      } catch (error) {
        throw new Error(messageText || response.statusText);
      }
    }
    if (messageText.startsWith('{') && messageText.includes('"error"')) {
      try {
        const parsed = JSON.parse(messageText) as { error?: string };
        throw new Error(parsed.error || response.statusText);
      } catch (error) {
        throw new Error(messageText || response.statusText);
      }
    }
    throw new Error(messageText || response.statusText);
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json() as Promise<T>;
};

const formRequest = async <T>(path: string, formData: FormData): Promise<T> => {
  let response: Response;
  try {
    response = await fetch(`${BASE_URL}${path}`, {
      method: 'POST',
      body: formData,
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {
        ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {})
      }
    });
  } catch (error) {
    const target = `${window.location.origin}${path}`;
    throw new Error(`Network error while contacting the server: ${target}`);
  }

  if (!response.ok) {
    const contentType = response.headers.get('content-type') || '';
    const messageText = await response.text();
    if (contentType.includes('application/json')) {
      try {
        const parsed = JSON.parse(messageText) as { error?: string };
        throw new Error(parsed.error || response.statusText);
      } catch (error) {
        throw new Error(messageText || response.statusText);
      }
    }
    if (messageText.startsWith('{') && messageText.includes('"error"')) {
      try {
        const parsed = JSON.parse(messageText) as { error?: string };
        throw new Error(parsed.error || response.statusText);
      } catch (error) {
        throw new Error(messageText || response.statusText);
      }
    }
    throw new Error(messageText || response.statusText);
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json() as Promise<T>;
};

const xhrRequest = async <T>(path: string, payload: unknown): Promise<T> => {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open('POST', path, true);
    request.setRequestHeader('Content-Type', 'application/json');
    const token = getToken();
    if (token) {
      request.setRequestHeader('Authorization', `Bearer ${token}`);
    }
    request.onreadystatechange = () => {
      if (request.readyState !== XMLHttpRequest.DONE) {
        return;
      }
      if (request.status >= 200 && request.status < 300) {
        try {
          resolve(JSON.parse(request.responseText) as T);
        } catch (error) {
          resolve({} as T);
        }
      } else {
        try {
          const parsed = JSON.parse(request.responseText) as { error?: string };
          reject(new Error(parsed.error || request.statusText));
        } catch (error) {
          reject(new Error(request.responseText || request.statusText));
        }
      }
    };
    request.onerror = () => reject(new Error('Network error while contacting the server.'));
    request.send(JSON.stringify(payload));
  });
};

export const login = (username: string, password: string) =>
  apiRequest<{ token: string; user: User }>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password })
  });

export const getAuthProviders = () => apiRequest<{ azureAdEnabled: boolean }>('/api/auth/providers');

export const startAzureLogin = () => {
  window.location.assign('/api/auth/azure/start');
};

export const getMe = () =>
  apiRequest<{ user: User; namespaces: string[]; permissions: NamespacePermission[] }>('/api/auth/me');

export const changePassword = (currentPassword: string, newPassword: string) =>
  apiRequest('/api/auth/change-password', {
    method: 'POST',
    body: JSON.stringify({ currentPassword, newPassword })
  });

export const listNamespaces = () => apiRequest<{ namespaces: string[] }>('/api/namespaces');

export const getNamespacePermissions = (namespace: string) =>
  apiRequest<{ resources: Record<string, string[]> }>(`/api/namespaces/${namespace}/permissions`);

export const listPods = (namespace: string) =>
  apiRequest<{ items: Array<Record<string, unknown>> }>(`/api/namespaces/${namespace}/pods`);

export const listDeployments = (namespace: string) =>
  apiRequest<{ items: Array<Record<string, unknown>> }>(`/api/namespaces/${namespace}/deployments`);

export const listServices = (namespace: string) =>
  apiRequest<{ items: Array<Record<string, unknown>> }>(`/api/namespaces/${namespace}/services`);

export const listConfigMaps = (namespace: string) =>
  apiRequest<{ items: Array<Record<string, unknown>> }>(`/api/namespaces/${namespace}/configmaps`);

export const listIngresses = (namespace: string) =>
  apiRequest<{ items: Array<Record<string, unknown>> }>(`/api/namespaces/${namespace}/ingresses`);

export const listJobs = (namespace: string) =>
  apiRequest<{ items: Array<Record<string, unknown>> }>(`/api/namespaces/${namespace}/jobs`);

export const getJobYaml = (namespace: string, name: string) =>
  apiRequest<{ yaml: string }>(`/api/namespaces/${namespace}/jobs/${name}/yaml`);

export const listCronJobs = (namespace: string) =>
  apiRequest<{ items: Array<Record<string, unknown>> }>(`/api/namespaces/${namespace}/cronjobs`);

export const getDeploymentYaml = (namespace: string, name: string) =>
  apiRequest<{ yaml: string }>(`/api/namespaces/${namespace}/deployments/${name}/yaml`);

export const getServiceYaml = (namespace: string, name: string) =>
  apiRequest<{ yaml: string }>(`/api/namespaces/${namespace}/services/${name}/yaml`);

export const getConfigMapYaml = (namespace: string, name: string) =>
  apiRequest<{ yaml: string }>(`/api/namespaces/${namespace}/configmaps/${name}/yaml`);

export const getIngressYaml = (namespace: string, name: string) =>
  apiRequest<{ yaml: string }>(`/api/namespaces/${namespace}/ingresses/${name}/yaml`);

export const getCronJobYaml = (namespace: string, name: string) =>
  apiRequest<{ yaml: string }>(`/api/namespaces/${namespace}/cronjobs/${name}/yaml`);

export const getConfigMapData = (namespace: string, name: string) =>
  apiRequest<{ data: Record<string, string> }>(`/api/namespaces/${namespace}/configmaps/${name}/data`);

// Secrets: list / get return metadata + key names and sizes only; a value is
// fetched one key at a time through reveal (needs secrets:reveal, audited).
export type SecretSummary = {
  metadata: {
    name: string;
    namespace: string;
    uid: string;
    creationTimestamp: string;
    labels?: Record<string, string>;
    annotations?: Record<string, string>;
  };
  type: string;
  immutable: boolean;
  keys: Array<{ name: string; size: number }>;
};

export const listSecrets = (namespace: string) =>
  apiRequest<{ items: SecretSummary[] }>(`/api/namespaces/${namespace}/secrets`);

export const getSecret = (namespace: string, name: string) =>
  apiRequest<SecretSummary>(`/api/namespaces/${namespace}/secrets/${encodeURIComponent(name)}`);

// Editable YAML (needs secrets:edit, audited): text values are shown as
// plain-text stringData, binary ones stay base64 in data.
export const getSecretYaml = (namespace: string, name: string) =>
  apiRequest<{ yaml: string }>(`/api/namespaces/${namespace}/secrets/${encodeURIComponent(name)}/yaml`);

export const revealSecretKey = (namespace: string, name: string, key: string) =>
  apiRequest<{ key: string; value: string; encoding: 'text' | 'base64' }>(
    `/api/namespaces/${namespace}/secrets/${encodeURIComponent(name)}/reveal`,
    { method: 'POST', body: JSON.stringify({ key }) },
  );

export const getPodEvents = (namespace: string, name: string) =>
  apiRequest<{ items: Array<Record<string, unknown>> }>(`/api/namespaces/${namespace}/pods/${name}/events`);

export const getDeploymentEvents = (namespace: string, name: string) =>
  apiRequest<{ items: Array<Record<string, unknown>> }>(`/api/namespaces/${namespace}/deployments/${name}/events`);

export const restartDeployment = (namespace: string, name: string) =>
  apiRequest<{ status: string; restartedAt: string }>(
    `/api/namespaces/${namespace}/deployments/${name}/restart`,
    { method: 'POST' }
  );

// ─── Workload coverage (2.4.0) ───────────────────────────────────────────────

export const listDaemonSets = (namespace: string) =>
  apiRequest<{ items: Array<Record<string, unknown>> }>(`/api/namespaces/${namespace}/daemonsets`);

export const getDaemonSetYaml = (namespace: string, name: string) =>
  apiRequest<{ yaml: string }>(`/api/namespaces/${namespace}/daemonsets/${name}/yaml`);

export const listStatefulSets = (namespace: string) =>
  apiRequest<{ items: Array<Record<string, unknown>> }>(`/api/namespaces/${namespace}/statefulsets`);

export const getStatefulSetYaml = (namespace: string, name: string) =>
  apiRequest<{ yaml: string }>(`/api/namespaces/${namespace}/statefulsets/${name}/yaml`);

export const scaleStatefulSet = (namespace: string, name: string, replicas: number) =>
  apiRequest<{ status: string; previous: number; replicas: number }>(
    `/api/namespaces/${namespace}/statefulsets/${name}/scale`,
    { method: 'POST', body: JSON.stringify({ replicas }) }
  );

export const listHPAs = (namespace: string) =>
  apiRequest<{ items: Array<Record<string, unknown>> }>(`/api/namespaces/${namespace}/hpas`);

export const getHPAYaml = (namespace: string, name: string) =>
  apiRequest<{ yaml: string }>(`/api/namespaces/${namespace}/hpas/${name}/yaml`);

/**
 * Generic apply — hits POST .../{resource}/{name}/apply with the typed YAML.
 * dryRun=true returns the server-canonicalized object (defaulted fields,
 * timestamps) without persisting; dryRun=false actually writes. The server
 * records audit outcomes {success,denied,rate_limited,failed} either way.
 */
export const applyYaml = (
  resource: string,
  namespace: string,
  name: string,
  yaml: string,
  dryRun: boolean,
) =>
  apiRequest<{ applied: string; dryRun: boolean }>(
    `/api/namespaces/${namespace}/${resource}/${name}/apply`,
    { method: 'POST', body: JSON.stringify({ yaml, dryRun }) },
  );

// ─── Clusters (multi-cluster) ────────────────────────────────────────────────

export type ClusterListItem = {
  id: number;
  name: string;
  description?: string;
  server?: string;
  method?: string;
  isActive: boolean;
  createdAt?: string;
};

// Clusters the caller may use: isActive = the default cluster, selected =
// the caller's current one.
export const listClustersPublic = () =>
  apiRequest<{ items: Array<{ id: number; name: string; isActive: boolean; selected: boolean }> }>(
    '/api/clusters/public'
  );

// Picks the caller's own cluster (0 = back to the default). Only affects the
// current user.
export const selectCluster = (clusterId: number) =>
  apiRequest<{ status: string; clusterId: number; name: string }>('/api/cluster/select', {
    method: 'POST',
    body: JSON.stringify({ clusterId }),
  });

export const getActiveCluster = () =>
  apiRequest<{
    active: { id: number; name: string; description: string; server: string; method: string; isDefault: boolean } | null;
  }>('/api/cluster/active');

export const listClustersAdmin = () =>
  apiRequest<{ items: ClusterListItem[] }>('/api/admin/clusters');

export type ClusterCreatePayload = {
  name: string;
  description: string;
  method: 'kubeconfig' | 'token';
  kubeconfigBase64?: string;
  token?: string;
  server?: string;
  caCertBase64?: string;
};

export const createCluster = (payload: ClusterCreatePayload) =>
  apiRequest<{ id: number }>('/api/admin/clusters', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

export const updateClusterRow = (
  id: number,
  payload: ClusterCreatePayload & { replaceSecrets?: boolean }
) =>
  apiRequest<{ status: string }>(`/api/admin/clusters/${id}`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  });

export const deleteClusterRow = (id: number) =>
  apiRequest<{ status: string }>(`/api/admin/clusters/${id}`, { method: 'DELETE' });

export const activateCluster = (id: number) =>
  apiRequest<{ status: string; name: string }>(`/api/admin/clusters/${id}/activate`, {
    method: 'POST',
  });

export const deactivateCluster = (id: number) =>
  apiRequest<{ status: string }>(`/api/admin/clusters/${id}/deactivate`, { method: 'POST' });

export const scaleDeployment = (namespace: string, name: string, replicas: number) =>
  apiRequest<{ status: string; previous: number; replicas: number }>(
    `/api/namespaces/${namespace}/deployments/${name}/scale`,
    {
      method: 'POST',
      body: JSON.stringify({ replicas }),
    }
  );

export const listUsers = () => apiRequest<{ items: User[] }>('/api/admin/users');

export const createUser = (payload: { username: string; password: string; isAdmin: boolean }) =>
  apiRequest<User>('/api/admin/users', {
    method: 'POST',
    body: JSON.stringify(payload)
  });

export const updateUser = (id: number, payload: { username: string; isActive: boolean; isAdmin: boolean }) =>
  apiRequest<User>(`/api/admin/users/${id}`, {
    method: 'PUT',
    body: JSON.stringify(payload)
  });

export const deleteUser = (id: number) =>
  apiRequest(`/api/admin/users/${id}`, { method: 'DELETE' });

export const setUserGroups = (id: number, groupIds: number[]) =>
  apiRequest(`/api/admin/users/${id}/groups`, {
    method: 'PUT',
    body: JSON.stringify({ groupIds })
  });

export const getUserGroups = (id: number) =>
  apiRequest<{ groupIds: number[] }>(`/api/admin/users/${id}/groups`);

export const listGroups = () => apiRequest<{ items: Array<{ id: number; name: string }> }>('/api/admin/groups');

export const createGroup = (name: string) =>
  apiRequest<{ id: number; name: string }>('/api/admin/groups', {
    method: 'POST',
    body: JSON.stringify({ name })
  });

export const updateGroup = (id: number, name: string) =>
  apiRequest(`/api/admin/groups/${id}`, {
    method: 'PUT',
    body: JSON.stringify({ name })
  });

export const deleteGroup = (id: number) =>
  apiRequest(`/api/admin/groups/${id}`, { method: 'DELETE' });

export const setGroupRoles = (id: number, roleIds: number[]) =>
  apiRequest(`/api/admin/groups/${id}/roles`, {
    method: 'PUT',
    body: JSON.stringify({ roleIds })
  });

export const getGroupRoles = (id: number) =>
  apiRequest<{ roleIds: number[] }>(`/api/admin/groups/${id}/roles`);

export const listRoles = () => apiRequest<{ items: Array<{ id: number; name: string; description: string }> }>('/api/admin/roles');

export const createRole = (payload: { name: string; description: string }) =>
  apiRequest('/api/admin/roles', {
    method: 'POST',
    body: JSON.stringify(payload)
  });

export const updateRole = (id: number, payload: { name: string; description: string }) =>
  apiRequest(`/api/admin/roles/${id}`, {
    method: 'PUT',
    body: JSON.stringify(payload)
  });

export const deleteRole = (id: number) =>
  apiRequest(`/api/admin/roles/${id}`, { method: 'DELETE' });

export const listRolePermissions = (id: number) =>
  apiRequest<{ items: NamespacePermission[] }>(`/api/admin/roles/${id}/permissions`);

export const addRolePermission = (
  roleId: number,
  payload: { clusterId?: number; namespace: string; resource: string; action: string }
) =>
  apiRequest(`/api/admin/roles/${roleId}/permissions`, {
    method: 'POST',
    body: JSON.stringify(payload)
  });

export const deletePermission = (id: number) =>
  apiRequest(`/api/admin/permissions/${id}`, { method: 'DELETE' });

export const getLDAP = () => apiRequest<LDAPConfig>('/api/admin/ldap');

export const getAzureAD = () => apiRequest<AzureADConfig>('/api/admin/azure-ad');

export const updateLDAP = (payload: LDAPConfig) =>
  apiRequest('/api/admin/ldap', {
    method: 'PUT',
    body: JSON.stringify(payload)
  });

export const updateAzureAD = (payload: AzureADConfig) =>
  apiRequest('/api/admin/azure-ad', {
    method: 'PUT',
    body: JSON.stringify(payload)
  });

export const uploadLogo = (file: File) => {
  const formData = new FormData();
  formData.append('file', file);
  return formRequest<{ status: string }>('/api/admin/customization/logo', formData);
};

export const deleteLogo = () => apiRequest('/api/admin/customization/logo', { method: 'DELETE' });

export const testLdapConnection = () =>
  apiRequest<{ status: string }>('/api/admin/ldap/test', {
    method: 'POST'
  });

export const testAzureAdConnection = () =>
  apiRequest<{ status: string }>('/api/admin/azure-ad/test', {
    method: 'POST'
  });

export const searchLdapUsers = (query: string) =>
  apiRequest<{ items: Array<{ username: string; dn: string }> }>('/api/admin/ldap/users/search', {
    method: 'POST',
    body: JSON.stringify({ query })
  });

export const importLdapUsers = (usernames: string[]) =>
  apiRequest<{ created: number }>('/api/admin/ldap/users/import', {
    method: 'POST',
    body: JSON.stringify({ usernames })
  });

export const getSession = () => apiRequest<SessionSettings>('/api/admin/session');

export const updateSession = (payload: SessionSettings) =>
  apiRequest('/api/admin/session', {
    method: 'PUT',
    body: JSON.stringify(payload)
  });

export const getCluster = () => apiRequest<KubeClusterStatus>('/api/admin/cluster');

export const updateCluster = (payload: {
  method: string;
  kubeconfigBase64?: string;
  token?: string;
  server?: string;
  caCertBase64?: string;
}) =>
  xhrRequest<{ status: string; active?: boolean; ready?: boolean; lastError?: string }>('/api/admin/cluster', payload).catch(() =>
    apiRequest<{ status: string; active?: boolean; ready?: boolean; lastError?: string }>('/api/admin/cluster', {
      method: 'POST',
      body: JSON.stringify(payload)
    })
  );

export const validateCluster = (payload: {
  method: string;
  kubeconfigBase64?: string;
  token?: string;
  server?: string;
  caCertBase64?: string;
}) =>
  apiRequest('/api/admin/cluster/validate', {
    method: 'POST',
    body: JSON.stringify(payload)
  });

export const listAuditLogs = (
  limit = 50,
  offset = 0,
  user = '',
  action = '',
  namespace = '',
  start = '',
  end = ''
) =>
  apiRequest<{ items: Array<Record<string, unknown>>; total: number; limit: number; offset: number }>(
    `/api/admin/audit-logs?limit=${limit}&offset=${offset}&user=${encodeURIComponent(user)}&action=${encodeURIComponent(action)}&namespace=${encodeURIComponent(namespace)}&start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}`
  );

// Downloads a file from an authenticated endpoint. The bearer token can't
// ride on a plain link, so the file is fetched and handed to the browser as
// a blob. Throws the server's error message on failure.
export const downloadWithAuth = async (path: string, fallbackName: string) => {
  const response = await fetch(path, {
    credentials: 'same-origin',
    cache: 'no-store',
    headers: getToken() ? { Authorization: `Bearer ${getToken()}` } : {},
  });
  if (!response.ok) {
    const text = await response.text();
    let message = text || response.statusText;
    try {
      message = (JSON.parse(text) as { error?: string }).error || message;
    } catch {
      /* not JSON */
    }
    throw new Error(message);
  }
  const disposition = response.headers.get('content-disposition') || '';
  const filename = /filename="?([^";]+)"?/.exec(disposition)?.[1] ?? fallbackName;
  const url = URL.createObjectURL(await response.blob());
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};

export const exportAuditLogs = (user = '', action = '', namespace = '', start = '', end = '') =>
  downloadWithAuth(
    `/api/admin/audit-logs/export?user=${encodeURIComponent(user)}&action=${encodeURIComponent(action)}&namespace=${encodeURIComponent(namespace)}&start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}`,
    'audit-logs.csv',
  );

export const exportUsersCsv = () => downloadWithAuth('/api/admin/users/export', 'users.csv');
export const exportGroupsCsv = () => downloadWithAuth('/api/admin/groups/export', 'groups.csv');

export type SessionRow = {
  id: number;
  jti: string;
  userId: number;
  username: string;
  issuedAt: string;
  lastUsedAt: string;
  expiresAt: string;
  revokedAt?: string | null;
  ip: string;
  userAgent: string;
};

export const listSessions = (activeOnly: boolean, userId?: number) => {
  const qs = new URLSearchParams();
  if (activeOnly) qs.set('activeOnly', '1');
  if (userId) qs.set('userId', String(userId));
  const q = qs.toString();
  return apiRequest<{ items: SessionRow[] }>(`/api/admin/sessions${q ? `?${q}` : ''}`);
};

export const revokeSession = (id: number) =>
  apiRequest(`/api/admin/sessions/${id}`, { method: 'DELETE' });

export const revokeAllSessionsForUser = (userId: number) =>
  apiRequest(`/api/admin/users/${userId}/revoke-sessions`, { method: 'POST' });

export const checkHealth = async () => {
  try {
    const response = await fetch('/healthz');
    if (!response.ok) {
      throw new Error('Health check failed');
    }
    return { ok: true };
  } catch (error) {
    return { ok: false };
  }
};

// ─── Session recordings (2.11.0) ─────────────────────────────────────────────

export type SessionRecording = {
  id: number;
  sessionId: string;
  user: string;
  cluster: string;
  namespace: string;
  pod: string;
  container: string;
  startedAt: string;
  endedAt?: string | null;
  durationMs: number;
  sizeBytes: number;
  truncated: boolean;
  requestId: string;
};

export type RecordingFilter = {
  user?: string;
  namespace?: string;
  pod?: string;
  from?: string; // YYYY-MM-DD or RFC3339
  to?: string;
  limit?: number;
  offset?: number;
};

export type RecordingDiskPolicy = 'evict_oldest' | 'stop';

export type RecordingSettings = {
  enabled: boolean;
  retentionDays: number;
  maxSessionMb: number;
  maxTotalMb: number;
  minFreeMb: number;
  diskPolicy: RecordingDiskPolicy;
};

export type RecordingUsage = {
  dir: string;
  dirWritable: boolean;
  dirError?: string;
  count: number;
  activeCount: number;
  usedBytes: number;
  maxTotalBytes: number;
  freeBytes: number; // -1 = unknown
  minFreeBytes: number;
  limitReached: boolean;
};

export const listRecordings = (filter: RecordingFilter) => {
  const qs = new URLSearchParams();
  Object.entries(filter).forEach(([k, v]) => {
    if (v !== undefined && v !== '') qs.set(k, String(v));
  });
  return apiRequest<{ items: SessionRecording[]; total: number }>(`/api/admin/recordings?${qs.toString()}`);
};

export const deleteRecording = (id: number) =>
  apiRequest(`/api/admin/recordings/${id}`, { method: 'DELETE' });

export const getRecordingSettings = () =>
  apiRequest<{ settings: RecordingSettings; usage: RecordingUsage }>('/api/admin/recordings/settings');

export const updateRecordingSettings = (settings: RecordingSettings) =>
  apiRequest<{ settings: RecordingSettings }>('/api/admin/recordings/settings', {
    method: 'PUT',
    body: JSON.stringify(settings),
  });

// The cast endpoint needs the bearer token, so the player and the download
// button both go through fetch instead of pointing at the URL directly.
const fetchRecordingCast = async (id: number, download: boolean): Promise<Response> => {
  const response = await fetch(`/api/admin/recordings/${id}/cast${download ? '?download=1' : ''}`, {
    credentials: 'same-origin',
    cache: 'no-store',
    headers: getToken() ? { Authorization: `Bearer ${getToken()}` } : {},
  });
  if (!response.ok) {
    const text = await response.text();
    let message = text || response.statusText;
    try {
      message = (JSON.parse(text) as { error?: string }).error || message;
    } catch {
      /* not JSON */
    }
    throw new Error(message);
  }
  return response;
};

export const getRecordingCast = async (id: number) => (await fetchRecordingCast(id, false)).text();

export const downloadRecordingCast = async (id: number) => {
  const response = await fetchRecordingCast(id, true);
  const disposition = response.headers.get('content-disposition') || '';
  const filename = /filename="([^"]+)"/.exec(disposition)?.[1] ?? `recording-${id}.cast`;
  const url = URL.createObjectURL(await response.blob());
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};

// Admin sets a new password for a LOCAL user; by default the user must change
// it at next login. All of that user's sessions are signed out.
export const resetUserPassword = (userId: number, password: string, mustChange: boolean) =>
  apiRequest<{ status: string; mustChangePassword: boolean }>(`/api/admin/users/${userId}/reset-password`, {
    method: 'POST',
    body: JSON.stringify({ password, mustChange }),
  });

// ─── Saved views (2.14.0): stored per user on the server, shareable ─────────

export type ServerView = {
  id: number;
  name: string;
  owner: string;
  mine: boolean;
  clusterId: number;
  clusterName: string;
  namespace: string;
  tab: string;
  search: string;
  viewMode: 'card' | 'list';
  shared: boolean;
};

export const listViews = () => apiRequest<{ items: ServerView[] }>('/api/views');

export const saveView = (view: { name: string; namespace: string; tab: string; search: string; viewMode: string; shared?: boolean }) =>
  apiRequest<{ id: number }>('/api/views', { method: 'POST', body: JSON.stringify(view) });

export const shareView = (id: number, shared: boolean) =>
  apiRequest<{ status: string }>(`/api/views/${id}`, { method: 'PUT', body: JSON.stringify({ shared }) });

export const deleteView = (id: number) => apiRequest<{ status: string }>(`/api/views/${id}`, { method: 'DELETE' });

