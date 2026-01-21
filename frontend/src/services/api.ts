export type User = {
  id: number;
  username: string;
  mustChangePassword: boolean;
  isActive: boolean;
  isAdmin: boolean;
};

export type NamespacePermission = {
  id: number;
  roleId: number;
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

export const getPodEvents = (namespace: string, name: string) =>
  apiRequest<{ items: Array<Record<string, unknown>> }>(`/api/namespaces/${namespace}/pods/${name}/events`);

export const getDeploymentEvents = (namespace: string, name: string) =>
  apiRequest<{ items: Array<Record<string, unknown>> }>(`/api/namespaces/${namespace}/deployments/${name}/events`);

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

export const addRolePermission = (roleId: number, payload: { namespace: string; resource: string; action: string }) =>
  apiRequest(`/api/admin/roles/${roleId}/permissions`, {
    method: 'POST',
    body: JSON.stringify(payload)
  });

export const deletePermission = (id: number) =>
  apiRequest(`/api/admin/permissions/${id}`, { method: 'DELETE' });

export const getLDAP = () => apiRequest<LDAPConfig>('/api/admin/ldap');

export const updateLDAP = (payload: LDAPConfig) =>
  apiRequest('/api/admin/ldap', {
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

export const exportAuditLogs = (
  user = '',
  action = '',
  namespace = '',
  start = '',
  end = ''
) =>
  fetch(
    `/api/admin/audit-logs/export?user=${encodeURIComponent(user)}&action=${encodeURIComponent(action)}&namespace=${encodeURIComponent(namespace)}&start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}`
  );

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
