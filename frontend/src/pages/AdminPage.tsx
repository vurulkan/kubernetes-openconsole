import React, { useEffect, useState } from 'react';
import Layout from '../components/Layout';
import {
  Alert,
  Badge,
  Button,
  Checkbox,
  ChipInput,
  Input,
  MultiSelect,
  MultiSelectOption,
  NativeSelect,
  Spinner,
} from '../components/ui';
import {
  User,
  listUsers,
  createUser,
  updateUser,
  deleteUser,
  setUserGroups,
  getUserGroups,
  listGroups,
  createGroup,
  updateGroup,
  deleteGroup,
  setGroupRoles,
  getGroupRoles,
  listRoles,
  createRole,
  updateRole,
  deleteRole,
  listRolePermissions,
  addRolePermission,
  deletePermission,
  getLDAP,
  getAzureAD,
  updateLDAP,
  updateAzureAD,
  uploadLogo,
  deleteLogo,
  testLdapConnection,
  testAzureAdConnection,
  searchLdapUsers,
  importLdapUsers,
  getSession,
  updateSession,
  getCluster,
  updateCluster,
  validateCluster,
  listAuditLogs,
  exportAuditLogs,
  listNamespaces,
  checkHealth,
  hasToken,
  NamespacePermission,
} from '../services/api';
import { useNavigate } from 'react-router-dom';
import { X } from 'lucide-react';

// ─── Tab definitions ──────────────────────────────────────────────────────────

const ADMIN_TABS = [
  { label: 'Users', value: 'users' },
  { label: 'Groups', value: 'groups' },
  { label: 'Roles', value: 'roles' },
  { label: 'LDAP', value: 'ldap' },
  { label: 'Azure AD', value: 'azure-ad' },
  { label: 'Session', value: 'session' },
  { label: 'Cluster', value: 'cluster' },
  { label: 'Customization', value: 'customization' },
  { label: 'Audit Logs', value: 'audit' },
];

// ─── Section card ─────────────────────────────────────────────────────────────

const SectionCard: React.FC<{ title: string; children: React.ReactNode }> = ({
  title,
  children,
}) => (
  <div className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
    <h3 className="mb-4 text-sm font-semibold text-gray-900">{title}</h3>
    {children}
  </div>
);

// ─── Divider ─────────────────────────────────────────────────────────────────

const Divider: React.FC<{ className?: string }> = ({ className = '' }) => (
  <div className={`border-t border-gray-200 ${className}`} />
);

// ─── AdminPage ────────────────────────────────────────────────────────────────

const AdminPage: React.FC<{ user: User }> = ({ user }) => {
  const navigate = useNavigate();
  const [tab, setTab] = useState(() => localStorage.getItem('adminActiveTab') || 'users');
  const [error, setError] = useState<string | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [groups, setGroups] = useState<Array<{ id: number; name: string }>>([]);
  const [roles, setRoles] = useState<Array<{ id: number; name: string; description: string }>>([]);
  const [userGroups, setUserGroupsState] = useState<
    Record<number, Array<{ id: number; name: string }>>
  >({});
  const [groupRoles, setGroupRolesState] = useState<
    Record<number, Array<{ id: number; name: string }>>
  >({});
  const [namespaceOptions, setNamespaceOptions] = useState<string[]>([]);
  const [apiReachable, setApiReachable] = useState(true);
  const [authTokenPresent, setAuthTokenPresent] = useState(hasToken());
  const [selectedRoleId, setSelectedRoleId] = useState<number | null>(null);
  const [rolePermissions, setRolePermissions] = useState<NamespacePermission[]>([]);
  const [newPermissionNamespaces, setNewPermissionNamespaces] = useState<string[]>([]);
  const [permissionMatrix, setPermissionMatrix] = useState({
    pods: { list: true, get: true, logs: false },
    deployments: { list: true, get: true },
    services: { list: true, get: true },
    configmaps: { list: true, get: true },
    ingresses: { list: true, get: true },
    cronjobs: { list: true, get: true },
  });
  const [ldapConfig, setLdapConfig] = useState({
    enabled: false,
    url: '',
    host: '',
    port: 389,
    useSsl: false,
    startTls: false,
    sslSkipVerify: false,
    timeoutSeconds: 10,
    bindDn: '',
    bindPassword: '',
    userBaseDn: '',
    userBaseDns: [] as string[],
    userFilter: '',
    usernameAttribute: 'sAMAccountName',
    passwordConfigured: false,
  });
  const [azureAdConfig, setAzureAdConfig] = useState({
    enabled: false,
    tenantId: '',
    clientId: '',
    clientSecret: '',
    redirectUrl: '',
    passwordConfigured: false,
  });
  const [azureAdUpdateSecret, setAzureAdUpdateSecret] = useState(false);
  const [azureAdTestStatus, setAzureAdTestStatus] = useState<{
    status: 'success' | 'error';
    message: string;
  } | null>(null);
  const [ldapSearchQuery, setLdapSearchQuery] = useState('');
  const [ldapSearchResults, setLdapSearchResults] = useState<
    Array<{ username: string; dn: string }>
  >([]);
  const [ldapSelectedUsers, setLdapSelectedUsers] = useState<string[]>([]);
  const [ldapSearchLoading, setLdapSearchLoading] = useState(false);
  const [ldapTestStatus, setLdapTestStatus] = useState<{
    status: 'success' | 'error';
    message: string;
  } | null>(null);
  const [ldapSearchError, setLdapSearchError] = useState<string | null>(null);
  const [ldapUpdatePassword, setLdapUpdatePassword] = useState(false);
  const [sessionMinutes, setSessionMinutes] = useState(60);
  const [cluster, setCluster] = useState({
    method: '',
    server: '',
    active: false,
    ready: false,
    lastError: '',
  });
  const [auditLogs, setAuditLogs] = useState<Array<Record<string, unknown>>>([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditOffset, setAuditOffset] = useState(0);
  const [auditUserFilter, setAuditUserFilter] = useState('');
  const [auditActionFilter, setAuditActionFilter] = useState('');
  const [auditNamespaceFilter, setAuditNamespaceFilter] = useState('');
  const [auditStartDate, setAuditStartDate] = useState('');
  const [auditEndDate, setAuditEndDate] = useState('');
  const [clusterValidation, setClusterValidation] = useState<{
    status: 'success' | 'error';
    message: string;
  } | null>(null);
  const [kubeconfigFileName, setKubeconfigFileName] = useState('');
  const [caCertFileName, setCaCertFileName] = useState('');
  const [logoFile, setLogoFile] = useState<File | null>(null);
  const [logoPreviewUrl, setLogoPreviewUrl] = useState('/api/customization/logo');
  const [logoStatus, setLogoStatus] = useState<{
    status: 'success' | 'error';
    message: string;
  } | null>(null);
  const [lastAppliedCluster, setLastAppliedCluster] = useState(() => {
    const stored = localStorage.getItem('lastAppliedCluster');
    if (stored) {
      try {
        return JSON.parse(stored) as {
          method: string;
          server: string;
          kubeconfigFileName: string;
          caCertFileName: string;
          appliedAt: string;
          status: string;
          error: string;
          requestId?: string;
        };
      } catch (err) {
        return {
          method: '',
          server: '',
          kubeconfigFileName: '',
          caCertFileName: '',
          appliedAt: '',
          status: '',
          error: '',
          requestId: '',
        };
      }
    }
    return {
      method: '',
      server: '',
      kubeconfigFileName: '',
      caCertFileName: '',
      appliedAt: '',
      status: '',
      error: '',
      requestId: '',
    };
  });
  const [newUser, setNewUser] = useState({ username: '', password: '', isAdmin: false });
  const [newGroup, setNewGroup] = useState('');
  const [newRole, setNewRole] = useState({ name: '', description: '' });
  const [clusterConfig, setClusterConfig] = useState({
    method: 'kubeconfig',
    kubeconfigBase64: '',
    token: '',
    server: '',
    caCertBase64: '',
  });

  // ─── Effects ────────────────────────────────────────────────────────────────

  useEffect(() => {
    if (!user.isAdmin) navigate('/');
  }, [user, navigate]);

  useEffect(() => {
    setLogoPreviewUrl('/api/customization/logo');
  }, []);

  useEffect(() => {
    const run = async () => {
      const result = await checkHealth();
      setApiReachable(result.ok);
      setAuthTokenPresent(hasToken());
    };
    void run();
  }, []);

  useEffect(() => {
    localStorage.setItem('adminActiveTab', tab);
  }, [tab]);

  useEffect(() => {
    localStorage.setItem('lastAppliedCluster', JSON.stringify(lastAppliedCluster));
  }, [lastAppliedCluster]);

  useEffect(() => {
    if (tab === 'roles') {
      setSelectedRoleId(null);
      setRolePermissions([]);
    }
  }, [tab]);

  // ─── Handlers ───────────────────────────────────────────────────────────────

  const loadRolePermissions = async (roleId: number) => {
    if (Number.isNaN(roleId)) return;
    try {
      const result = await listRolePermissions(roleId);
      setRolePermissions(result.items ?? []);
    } catch (err) {
      setRolePermissions([]);
    }
  };

  const refresh = async () => {
    setError(null);
    const results = await Promise.allSettled([
      listUsers(),
      listGroups(),
      listRoles(),
      getLDAP(),
      getAzureAD(),
      getSession(),
      getCluster(),
      listAuditLogs(
        50,
        auditOffset,
        auditUserFilter,
        auditActionFilter,
        auditNamespaceFilter,
        auditStartDate,
        auditEndDate
      ),
      listNamespaces(),
    ]);

    const [
      usersResult,
      groupsResult,
      rolesResult,
      ldapResult,
      azureAdResult,
      sessionResult,
      clusterResult,
      auditResult,
      namespaceResult,
    ] = results;

    const usersItems = usersResult.status === 'fulfilled' ? (usersResult.value.items ?? []) : [];
    const groupsItems =
      groupsResult.status === 'fulfilled' ? (groupsResult.value.items ?? []) : [];
    const rolesItems = rolesResult.status === 'fulfilled' ? (rolesResult.value.items ?? []) : [];

    if (usersResult.status === 'fulfilled') setUsers(usersItems);
    if (groupsResult.status === 'fulfilled') setGroups(groupsItems);
    if (rolesResult.status === 'fulfilled') {
      setRoles(rolesItems);
      setSelectedRoleId(null);
      setRolePermissions([]);
    }
    if (ldapResult.status === 'fulfilled') {
      setLdapConfig({
        enabled: ldapResult.value.enabled ?? false,
        url: ldapResult.value.url ?? '',
        host: ldapResult.value.host ?? '',
        port: ldapResult.value.port ?? 389,
        useSsl: ldapResult.value.useSsl ?? false,
        startTls: ldapResult.value.startTls ?? false,
        sslSkipVerify: ldapResult.value.sslSkipVerify ?? false,
        timeoutSeconds: ldapResult.value.timeoutSeconds ?? 10,
        bindDn: ldapResult.value.bindDn ?? '',
        bindPassword: '',
        userBaseDn: ldapResult.value.userBaseDn ?? '',
        userBaseDns: ldapResult.value.userBaseDns ?? [],
        userFilter: ldapResult.value.userFilter ?? '',
        usernameAttribute: ldapResult.value.usernameAttribute ?? 'sAMAccountName',
        passwordConfigured: ldapResult.value.passwordConfigured ?? false,
      });
      setLdapUpdatePassword(false);
    }
    if (azureAdResult.status === 'fulfilled') {
      setAzureAdConfig({
        enabled: azureAdResult.value.enabled ?? false,
        tenantId: azureAdResult.value.tenantId ?? '',
        clientId: azureAdResult.value.clientId ?? '',
        clientSecret: '',
        redirectUrl: azureAdResult.value.redirectUrl ?? '',
        passwordConfigured: azureAdResult.value.passwordConfigured ?? false,
      });
      setAzureAdUpdateSecret(false);
    }
    if (sessionResult.status === 'fulfilled') setSessionMinutes(sessionResult.value.sessionMinutes);
    if (clusterResult.status === 'fulfilled') {
      const c = clusterResult.value;
      setCluster({
        method: c.method,
        server: c.server,
        active: c.active,
        ready: c.ready ?? false,
        lastError: c.lastError ?? '',
      });
    }
    if (auditResult.status === 'fulfilled') {
      setAuditLogs(auditResult.value.items ?? []);
      setAuditTotal(auditResult.value.total ?? 0);
      setAuditOffset(auditResult.value.offset ?? 0);
    }
    if (namespaceResult.status === 'fulfilled') {
      setNamespaceOptions(namespaceResult.value.namespaces ?? []);
    } else {
      setNamespaceOptions([]);
    }

    const failedCritical = [usersResult, groupsResult, rolesResult].some(
      (r) => r.status === 'rejected'
    );
    if (failedCritical) setError('Unable to load admin data.');

    if (usersResult.status === 'fulfilled' && groupsResult.status === 'fulfilled') {
      const groupMap = new Map(groupsItems.map((g) => [g.id, g.name]));
      const selections = await Promise.all(
        usersItems.map(async (u) => {
          try {
            const result = await getUserGroups(u.id);
            const selected = (result.groupIds ?? []).map((id) => ({
              id,
              name: groupMap.get(id) ?? `Group ${id}`,
            }));
            return [u.id, selected] as const;
          } catch (err) {
            return [u.id, []] as const;
          }
        })
      );
      setUserGroupsState(Object.fromEntries(selections));
    }

    if (groupsResult.status === 'fulfilled' && rolesResult.status === 'fulfilled') {
      const roleMap = new Map(rolesItems.map((r) => [r.id, r.name]));
      const selections = await Promise.all(
        groupsItems.map(async (g) => {
          try {
            const result = await getGroupRoles(g.id);
            const selected = (result.roleIds ?? []).map((id) => ({
              id,
              name: roleMap.get(id) ?? `Role ${id}`,
            }));
            return [g.id, selected] as const;
          } catch (err) {
            return [g.id, []] as const;
          }
        })
      );
      setGroupRolesState(Object.fromEntries(selections));
    }
  };

  useEffect(() => {
    void refresh();
  }, [
    auditOffset,
    auditUserFilter,
    auditActionFilter,
    auditNamespaceFilter,
    auditStartDate,
    auditEndDate,
  ]);

  const handleCreateUser = async () => {
    if (!newUser.username || !newUser.password) return;
    await createUser(newUser);
    setNewUser({ username: '', password: '', isAdmin: false });
    await refresh();
  };

  const handleCreateGroup = async () => {
    if (!newGroup) return;
    await createGroup(newGroup);
    setNewGroup('');
    await refresh();
  };

  const handleCreateRole = async () => {
    if (!newRole.name) return;
    await createRole(newRole);
    setNewRole({ name: '', description: '' });
    await refresh();
  };

  const handleSaveUserGroups = async (id: number) => {
    const ids = (userGroups[id] ?? []).map((item) => item.id);
    await setUserGroups(id, ids);
    await refresh();
  };

  const handleSaveGroupRoles = async (id: number) => {
    const ids = (groupRoles[id] ?? []).map((item) => item.id);
    await setGroupRoles(id, ids);
    await refresh();
  };

  const handleLoadRolePermissions = async (roleId: number) => {
    if (Number.isNaN(roleId)) return;
    setSelectedRoleId(roleId);
    await loadRolePermissions(roleId);
  };

  const handleRemovePermission = async (permissionId: number) => {
    await deletePermission(permissionId);
    if (selectedRoleId) await loadRolePermissions(selectedRoleId);
  };

  const handleRemoveNamespacePermissions = async (namespace: string) => {
    const ids = rolePermissions
      .filter((perm) => perm.namespace === namespace)
      .map((perm) => perm.id);
    for (const id of ids) {
      await deletePermission(id);
    }
    if (selectedRoleId) await loadRolePermissions(selectedRoleId);
  };

  const groupedPermissions = React.useMemo(() => {
    const map = new Map<string, NamespacePermission[]>();
    rolePermissions.forEach((perm) => {
      const list = map.get(perm.namespace) ?? [];
      list.push(perm);
      map.set(perm.namespace, list);
    });
    return Array.from(map.entries()).map(([namespace, permissions]) => ({
      namespace,
      permissions,
    }));
  }, [rolePermissions]);

  const handleAddPermission = async () => {
    if (!selectedRoleId || newPermissionNamespaces.length === 0) return;
    const existing = new Set(
      rolePermissions.map((perm) => `${perm.namespace}:${perm.resource}:${perm.action}`)
    );
    const requests: Array<{ resource: string; action: string }> = [];
    Object.entries(permissionMatrix).forEach(([resource, actions]) => {
      Object.entries(actions).forEach(([action, enabled]) => {
        if (enabled) requests.push({ resource, action });
      });
    });
    for (const namespace of newPermissionNamespaces) {
      if (!namespace) continue;
      for (const item of requests) {
        const key = `${namespace}:${item.resource}:${item.action}`;
        if (existing.has(key)) continue;
        await addRolePermission(selectedRoleId, {
          namespace,
          resource: item.resource,
          action: item.action,
        });
      }
    }
    await loadRolePermissions(selectedRoleId);
    setNewPermissionNamespaces([]);
    setPermissionMatrix({
      pods: { list: true, get: true, logs: false },
      deployments: { list: true, get: true },
      services: { list: true, get: true },
      configmaps: { list: true, get: true },
      ingresses: { list: true, get: true },
      cronjobs: { list: true, get: true },
    });
  };

  const handleFileUpload = (
    file: File | null,
    key: 'kubeconfigBase64' | 'caCertBase64'
  ) => {
    if (!file) {
      setClusterConfig({ ...clusterConfig, [key]: '' });
      if (key === 'kubeconfigBase64') setKubeconfigFileName('');
      else setCaCertFileName('');
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result?.toString() ?? '';
      const base64 = result.includes(',') ? result.split(',')[1] : result;
      setClusterConfig({ ...clusterConfig, [key]: base64 });
      if (key === 'kubeconfigBase64') setKubeconfigFileName(file.name);
      else setCaCertFileName(file.name);
    };
    reader.readAsDataURL(file);
  };

  const handleSaveLDAP = async () => {
    await updateLDAP({
      ...ldapConfig,
      bindPassword:
        ldapUpdatePassword || !(ldapConfig.passwordConfigured ?? false)
          ? ldapConfig.bindPassword
          : '',
      passwordConfigured: ldapConfig.passwordConfigured ?? false,
    });
    await refresh();
  };

  const handleTestLDAP = async () => {
    setLdapTestStatus(null);
    try {
      await testLdapConnection();
      setLdapTestStatus({ status: 'success', message: 'LDAP connection successful.' });
    } catch (err) {
      setLdapTestStatus({
        status: 'error',
        message: (err as Error).message || 'LDAP test failed.',
      });
    }
  };

  const handleSaveAzureAd = async () => {
    await updateAzureAD({
      ...azureAdConfig,
      clientSecret:
        azureAdUpdateSecret || !(azureAdConfig.passwordConfigured ?? false)
          ? azureAdConfig.clientSecret
          : '',
      passwordConfigured: azureAdConfig.passwordConfigured ?? false,
    });
    await refresh();
  };

  const handleTestAzureAd = async () => {
    setAzureAdTestStatus(null);
    try {
      await testAzureAdConnection();
      setAzureAdTestStatus({ status: 'success', message: 'Azure AD connection successful.' });
    } catch (err) {
      setAzureAdTestStatus({
        status: 'error',
        message: (err as Error).message || 'Azure AD test failed.',
      });
    }
  };

  const handleLdapSearch = async () => {
    setLdapSearchLoading(true);
    setLdapSearchError(null);
    try {
      const result = await searchLdapUsers(ldapSearchQuery);
      setLdapSearchResults(result.items ?? []);
      setLdapSelectedUsers([]);
    } catch (err) {
      setLdapSearchResults([]);
      setLdapSearchError((err as Error).message || 'LDAP search failed.');
    } finally {
      setLdapSearchLoading(false);
    }
  };

  const handleLdapImport = async () => {
    if (ldapSelectedUsers.length === 0) return;
    await importLdapUsers(ldapSelectedUsers);
    setLdapSearchQuery('');
    setLdapSelectedUsers([]);
    setLdapSearchResults([]);
    await refresh();
  };

  const handleAuditExport = async () => {
    const response = await exportAuditLogs(
      auditUserFilter,
      auditActionFilter,
      auditNamespaceFilter,
      auditStartDate,
      auditEndDate
    );
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'audit-logs.csv';
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  };

  const handleSaveSession = async () => {
    await updateSession({ sessionMinutes });
    await refresh();
  };

  const isClusterConfigValid = () => {
    if (clusterConfig.method === 'kubeconfig') return clusterConfig.kubeconfigBase64.length > 0;
    if (clusterConfig.method === 'token')
      return clusterConfig.token.length > 0 && clusterConfig.server.length > 0;
    return false;
  };

  const handleSaveCluster = async () => {
    setClusterValidation(null);
    if (!isClusterConfigValid()) {
      setClusterValidation({
        status: 'error',
        message: 'Please provide required cluster details before applying.',
      });
      return;
    }
    const requestId = `${Date.now()}`;
    const pending = {
      method: clusterConfig.method,
      server: clusterConfig.server,
      kubeconfigFileName,
      caCertFileName,
      appliedAt: new Date().toISOString(),
      status: 'sending',
      error: '',
      requestId,
    };
    setLastAppliedCluster(pending);
    const timeout = setTimeout(() => {
      setLastAppliedCluster((prev) => {
        if (prev.requestId !== requestId || prev.status === 'applied') return prev;
        return { ...prev, status: 'failed', error: 'Request timed out. No response from server.' };
      });
    }, 15000);
    try {
      const result = await updateCluster(clusterConfig);
      if (result.status === 'starting') {
        setClusterValidation({
          status: 'success',
          message: 'Connection syncing in background. Check Ready status shortly.',
        });
      }
      setLastAppliedCluster((prev) => ({ ...prev, status: 'applied', error: '' }));
      if (
        typeof result.active === 'boolean' ||
        typeof result.ready === 'boolean' ||
        result.lastError
      ) {
        setCluster((prev) => ({
          ...prev,
          active: result.active ?? prev.active,
          ready: result.ready ?? prev.ready,
          lastError: result.lastError ?? prev.lastError,
        }));
      }
      await refresh();
    } catch (err) {
      const message =
        (err as Error).message || 'Failed to apply cluster configuration.';
      setClusterValidation({ status: 'error', message });
      setLastAppliedCluster((prev) => ({ ...prev, status: 'failed', error: message }));
    } finally {
      clearTimeout(timeout);
    }
  };

  const handleValidateCluster = async () => {
    setClusterValidation(null);
    if (!isClusterConfigValid()) {
      setClusterValidation({
        status: 'error',
        message: 'Please provide required cluster details before validating.',
      });
      return;
    }
    try {
      await validateCluster(clusterConfig);
      setClusterValidation({ status: 'success', message: 'Kubeconfig validated successfully.' });
    } catch (err) {
      setClusterValidation({
        status: 'error',
        message: (err as Error).message || 'Validation failed.',
      });
    }
  };

  const handleUploadLogo = async () => {
    if (!logoFile) {
      setLogoStatus({ status: 'error', message: 'Please select a logo file to upload.' });
      return;
    }
    setLogoStatus(null);
    try {
      await uploadLogo(logoFile);
      setLogoStatus({ status: 'success', message: 'Logo uploaded successfully.' });
      setLogoPreviewUrl(`/api/customization/logo?ts=${Date.now()}`);
      setLogoFile(null);
    } catch (err) {
      setLogoStatus({
        status: 'error',
        message: (err as Error).message || 'Logo upload failed.',
      });
    }
  };

  const handleRemoveLogo = async () => {
    setLogoStatus(null);
    try {
      await deleteLogo();
      setLogoStatus({ status: 'success', message: 'Logo removed successfully.' });
      setLogoPreviewUrl('');
      setLogoFile(null);
    } catch (err) {
      setLogoStatus({
        status: 'error',
        message: (err as Error).message || 'Failed to remove logo.',
      });
    }
  };

  // ─── Render ───────────────────────────────────────────────────────────────

  return (
    <Layout user={user} namespaces={[]} activeNamespace={null} onNamespaceChange={() => undefined}>
      <h1 className="text-xl font-semibold text-gray-900">Admin Control Center</h1>
      <p className="mt-1 text-sm text-gray-500">
        Manage users, roles, LDAP, sessions, and cluster connections entirely from the UI.
      </p>

      {error && (
        <Alert severity="error" className="mt-4">
          {error}
        </Alert>
      )}

      <div className="mt-6 rounded-xl border border-gray-200 bg-white shadow-sm">
        {/* ── Tab bar ───────────────────────────────────────────────── */}
        <div className="flex overflow-x-auto border-b border-gray-200 px-2">
          {ADMIN_TABS.map((t) => (
            <button
              key={t.value}
              onClick={() => setTab(t.value)}
              className={`shrink-0 border-b-2 px-4 py-3 text-sm font-medium transition-colors focus:outline-none ${
                tab === t.value
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div className="p-5">
          {/* ─────────────────────────── USERS ──────────────────────── */}
          {tab === 'users' && (
            <div className="flex flex-col gap-5">
              <SectionCard title="Create User">
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                  <Input
                    label="Username"
                    value={newUser.username}
                    onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                  />
                  <Input
                    label="Password"
                    type="password"
                    value={newUser.password}
                    onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                  />
                  <div className="flex items-end pb-0.5">
                    <Checkbox
                      checked={newUser.isAdmin}
                      onChange={(v) => setNewUser({ ...newUser, isAdmin: v })}
                      label="Admin"
                    />
                  </div>
                </div>
                <Button variant="primary" size="sm" className="mt-4" onClick={handleCreateUser}>
                  Create User
                </Button>
              </SectionCard>

              <SectionCard title="Existing Users">
                <div className="flex flex-col gap-4">
                  {users.map((u) => (
                    <div
                      key={u.id}
                      className="rounded-lg border border-gray-100 p-4"
                    >
                      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                        <Input
                          label="Username"
                          value={u.username}
                          onChange={(e) =>
                            setUsers(
                              users.map((item) =>
                                item.id === u.id
                                  ? { ...item, username: e.target.value }
                                  : item
                              )
                            )
                          }
                        />
                        <div className="flex items-end gap-4 pb-0.5">
                          <Checkbox
                            checked={u.isActive}
                            onChange={(v) =>
                              setUsers(
                                users.map((item) =>
                                  item.id === u.id ? { ...item, isActive: v } : item
                                )
                              )
                            }
                            label="Active"
                          />
                          <Checkbox
                            checked={u.isAdmin}
                            onChange={(v) =>
                              setUsers(
                                users.map((item) =>
                                  item.id === u.id ? { ...item, isAdmin: v } : item
                                )
                              )
                            }
                            label="Admin"
                          />
                        </div>
                        <MultiSelect
                          label="Groups"
                          options={groups.map((g) => ({ id: g.id, label: g.name }))}
                          value={(userGroups[u.id] ?? []).map((g) => ({
                            id: g.id,
                            label: g.name,
                          }))}
                          onChange={(value: MultiSelectOption[]) =>
                            setUserGroupsState({
                              ...userGroups,
                              [u.id]: value.map((v) => ({
                                id: Number(v.id),
                                name: v.label,
                              })),
                            })
                          }
                          noOptionsText="No groups found"
                          placeholder="Assign groups..."
                        />
                        <div className="flex items-end gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() =>
                              updateUser(u.id, {
                                username: u.username,
                                isActive: u.isActive,
                                isAdmin: u.isAdmin,
                              })
                            }
                          >
                            Save
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleSaveUserGroups(u.id)}
                          >
                            Save Groups
                          </Button>
                          <Button
                            variant="danger"
                            size="sm"
                            onClick={async () => {
                              await deleteUser(u.id);
                              await refresh();
                            }}
                          >
                            Delete
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </SectionCard>
            </div>
          )}

          {/* ─────────────────────────── GROUPS ─────────────────────── */}
          {tab === 'groups' && (
            <div className="flex flex-col gap-5">
              <SectionCard title="Create Group">
                <div className="flex gap-3">
                  <Input
                    label="Group Name"
                    value={newGroup}
                    onChange={(e) => setNewGroup(e.target.value)}
                  />
                  <div className="flex items-end">
                    <Button variant="primary" size="sm" onClick={handleCreateGroup}>
                      Create
                    </Button>
                  </div>
                </div>
              </SectionCard>

              <SectionCard title="Existing Groups">
                <div className="flex flex-col gap-4">
                  {groups.map((group) => (
                    <div key={group.id} className="rounded-lg border border-gray-100 p-4">
                      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                        <Input
                          label="Name"
                          value={group.name}
                          onChange={(e) =>
                            setGroups(
                              groups.map((g) =>
                                g.id === group.id ? { ...g, name: e.target.value } : g
                              )
                            )
                          }
                        />
                        <MultiSelect
                          label="Roles"
                          options={roles.map((r) => ({ id: r.id, label: r.name }))}
                          value={(groupRoles[group.id] ?? []).map((r) => ({
                            id: r.id,
                            label: r.name,
                          }))}
                          onChange={(value: MultiSelectOption[]) =>
                            setGroupRolesState({
                              ...groupRoles,
                              [group.id]: value.map((v) => ({
                                id: Number(v.id),
                                name: v.label,
                              })),
                            })
                          }
                          noOptionsText="No roles found"
                          placeholder="Assign roles..."
                        />
                        <div className="flex items-end gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => updateGroup(group.id, group.name)}
                          >
                            Save
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleSaveGroupRoles(group.id)}
                          >
                            Save Roles
                          </Button>
                          <Button
                            variant="danger"
                            size="sm"
                            onClick={async () => {
                              await deleteGroup(group.id);
                              await refresh();
                            }}
                          >
                            Delete
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </SectionCard>
            </div>
          )}

          {/* ─────────────────────────── ROLES ──────────────────────── */}
          {tab === 'roles' && (
            <div className="flex flex-col gap-5">
              <SectionCard title="Create Role">
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <Input
                    label="Name"
                    value={newRole.name}
                    onChange={(e) => setNewRole({ ...newRole, name: e.target.value })}
                  />
                  <Input
                    label="Description"
                    value={newRole.description}
                    onChange={(e) => setNewRole({ ...newRole, description: e.target.value })}
                  />
                </div>
                <Button variant="primary" size="sm" className="mt-4" onClick={handleCreateRole}>
                  Create Role
                </Button>
              </SectionCard>

              <SectionCard title="Existing Roles">
                <div className="flex flex-col gap-3">
                  {roles.map((role) => (
                    <div key={role.id} className="rounded-lg border border-gray-100 p-4">
                      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                        <Input
                          label="Name"
                          value={role.name}
                          onChange={(e) =>
                            setRoles(
                              roles.map((r) =>
                                r.id === role.id ? { ...r, name: e.target.value } : r
                              )
                            )
                          }
                        />
                        <Input
                          label="Description"
                          value={role.description}
                          onChange={(e) =>
                            setRoles(
                              roles.map((r) =>
                                r.id === role.id ? { ...r, description: e.target.value } : r
                              )
                            )
                          }
                        />
                        <div className="flex items-end gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() =>
                              updateRole(role.id, {
                                name: role.name,
                                description: role.description,
                              })
                            }
                          >
                            Save
                          </Button>
                          <Button
                            variant="danger"
                            size="sm"
                            onClick={async () => {
                              await deleteRole(role.id);
                              await refresh();
                            }}
                          >
                            Delete
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </SectionCard>

              <SectionCard title="Role Permissions">
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <NativeSelect
                    label="Role"
                    value={selectedRoleId ?? ''}
                    onChange={(e) => {
                      const val = e.target.value;
                      if (!val) {
                        setSelectedRoleId(null);
                        setRolePermissions([]);
                        return;
                      }
                      void handleLoadRolePermissions(Number(val));
                    }}
                  >
                    <option value="">Select role...</option>
                    {roles.map((r) => (
                      <option key={r.id} value={r.id}>
                        {r.name}
                      </option>
                    ))}
                  </NativeSelect>

                  <ChipInput
                    label="Namespaces"
                    value={newPermissionNamespaces}
                    onChange={setNewPermissionNamespaces}
                    suggestions={namespaceOptions}
                    placeholder="Type or select namespaces..."
                  />
                </div>

                <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
                  {Object.entries(permissionMatrix).map(([resource, actions]) => (
                    <div
                      key={resource}
                      className="rounded-lg border border-gray-200 p-3"
                    >
                      <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-700">
                        {resource}
                      </p>
                      {Object.entries(actions).map(([action, enabled]) => (
                        <Checkbox
                          key={action}
                          checked={enabled}
                          onChange={(v) =>
                            setPermissionMatrix({
                              ...permissionMatrix,
                              [resource]: { ...actions, [action]: v },
                            })
                          }
                          label={action.toUpperCase()}
                          className="mb-1"
                        />
                      ))}
                    </div>
                  ))}
                </div>

                <Button
                  variant="primary"
                  size="sm"
                  className="mt-4"
                  onClick={handleAddPermission}
                >
                  Add Selected Permissions
                </Button>

                <div className="mt-4">
                  {!selectedRoleId && (
                    <p className="text-sm text-gray-400">Select a role to view its permissions.</p>
                  )}
                  {selectedRoleId && groupedPermissions.length === 0 && (
                    <p className="text-sm text-gray-400">No permissions assigned yet.</p>
                  )}
                  {selectedRoleId && groupedPermissions.length > 0 && (
                    <div className="overflow-auto rounded-lg border border-gray-200">
                      <table className="w-full text-sm">
                        <thead className="bg-gray-50">
                          <tr>
                            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-gray-600">
                              Namespace
                            </th>
                            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-gray-600">
                              Permissions
                            </th>
                            <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wide text-gray-600">
                              Actions
                            </th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-100">
                          {groupedPermissions.map((group) => (
                            <tr key={group.namespace}>
                              <td className="px-4 py-3 font-medium text-gray-900">
                                {group.namespace}
                              </td>
                              <td className="px-4 py-3">
                                <div className="flex flex-wrap gap-1.5">
                                  {group.permissions.map((perm) => (
                                    <span
                                      key={perm.id}
                                      className="group inline-flex items-center gap-1 rounded border border-gray-200 bg-white px-2 py-0.5 text-xs text-gray-700 hover:border-gray-300"
                                    >
                                      {perm.resource}:{perm.action}
                                      <button
                                        type="button"
                                        onClick={() => handleRemovePermission(perm.id)}
                                        className="text-gray-300 transition-opacity group-hover:text-red-400 focus:outline-none"
                                      >
                                        <X size={10} />
                                      </button>
                                    </span>
                                  ))}
                                </div>
                              </td>
                              <td className="px-4 py-3 text-right">
                                <Button
                                  variant="danger"
                                  size="sm"
                                  onClick={() =>
                                    handleRemoveNamespacePermissions(group.namespace)
                                  }
                                >
                                  Remove Namespace
                                </Button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </SectionCard>
            </div>
          )}

          {/* ─────────────────────────── LDAP ───────────────────────── */}
          {tab === 'ldap' && (
            <div className="flex flex-col gap-5">
              <SectionCard title="LDAP Configuration">
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
                  <Checkbox
                    checked={ldapConfig.enabled}
                    onChange={(v) => setLdapConfig({ ...ldapConfig, enabled: v })}
                    label="Enabled"
                  />
                  <Input
                    label="Host"
                    value={ldapConfig.host}
                    onChange={(e) => setLdapConfig({ ...ldapConfig, host: e.target.value })}
                  />
                  <Input
                    label="Port"
                    type="number"
                    value={ldapConfig.port}
                    onChange={(e) =>
                      setLdapConfig({ ...ldapConfig, port: Number(e.target.value) })
                    }
                  />
                  <Checkbox
                    checked={ldapConfig.useSsl}
                    onChange={(v) => setLdapConfig({ ...ldapConfig, useSsl: v })}
                    label="Use SSL"
                  />
                  <Checkbox
                    checked={ldapConfig.startTls}
                    onChange={(v) => setLdapConfig({ ...ldapConfig, startTls: v })}
                    label="StartTLS"
                  />
                  <Checkbox
                    checked={ldapConfig.sslSkipVerify}
                    onChange={(v) => setLdapConfig({ ...ldapConfig, sslSkipVerify: v })}
                    label="Skip Verify"
                  />
                  <Input
                    label="Timeout (seconds)"
                    type="number"
                    value={ldapConfig.timeoutSeconds}
                    onChange={(e) =>
                      setLdapConfig({ ...ldapConfig, timeoutSeconds: Number(e.target.value) })
                    }
                  />
                  <Input
                    label="Bind DN"
                    value={ldapConfig.bindDn}
                    onChange={(e) => setLdapConfig({ ...ldapConfig, bindDn: e.target.value })}
                  />
                  <Checkbox
                    checked={ldapUpdatePassword}
                    onChange={setLdapUpdatePassword}
                    label="Update Bind Password"
                  />
                  <Input
                    label="Bind Password"
                    type="password"
                    disabled={!ldapUpdatePassword && (ldapConfig.passwordConfigured ?? false)}
                    value={
                      !ldapUpdatePassword && (ldapConfig.passwordConfigured ?? false)
                        ? 'Configured'
                        : ldapConfig.bindPassword
                    }
                    onChange={(e) =>
                      setLdapConfig({ ...ldapConfig, bindPassword: e.target.value })
                    }
                  />
                  <Input
                    label="User Base DN (single)"
                    value={ldapConfig.userBaseDn}
                    onChange={(e) =>
                      setLdapConfig({ ...ldapConfig, userBaseDn: e.target.value })
                    }
                  />
                  <Input
                    label="User Base DNs (comma separated)"
                    value={ldapConfig.userBaseDns.join(',')}
                    onChange={(e) =>
                      setLdapConfig({
                        ...ldapConfig,
                        userBaseDns: e.target.value
                          .split(',')
                          .map((v) => v.trim())
                          .filter(Boolean),
                      })
                    }
                  />
                  <Input
                    label="User Filter"
                    value={ldapConfig.userFilter}
                    onChange={(e) =>
                      setLdapConfig({ ...ldapConfig, userFilter: e.target.value })
                    }
                  />
                  <Input
                    label="Username Attribute"
                    value={ldapConfig.usernameAttribute}
                    onChange={(e) =>
                      setLdapConfig({ ...ldapConfig, usernameAttribute: e.target.value })
                    }
                  />
                </div>
                <div className="mt-4 flex gap-2">
                  <Button variant="primary" size="sm" onClick={handleSaveLDAP}>
                    Save LDAP Settings
                  </Button>
                  <Button variant="outline" size="sm" onClick={handleTestLDAP}>
                    Test Connection
                  </Button>
                </div>
                {ldapTestStatus && (
                  <Alert severity={ldapTestStatus.status} className="mt-3">
                    {ldapTestStatus.message}
                  </Alert>
                )}
              </SectionCard>

              <SectionCard title="Import LDAP Users">
                <div className="flex flex-wrap gap-3">
                  <Input
                    label="Search Query"
                    value={ldapSearchQuery}
                    onChange={(e) => setLdapSearchQuery(e.target.value)}
                    className="w-60"
                  />
                  <div className="flex items-end">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleLdapSearch}
                      disabled={ldapSearchLoading}
                    >
                      {ldapSearchLoading ? (
                        <span className="flex items-center gap-2">
                          <Spinner size="sm" />
                          Searching...
                        </span>
                      ) : (
                        'Search'
                      )}
                    </Button>
                  </div>
                </div>

                {ldapSearchResults.length > 0 && (
                  <MultiSelect
                    label="LDAP Users"
                    className="mt-3"
                    options={ldapSearchResults.map((u) => ({
                      id: u.username,
                      label: `${u.username} (${u.dn})`,
                    }))}
                    value={ldapSearchResults
                      .filter((u) => ldapSelectedUsers.includes(u.username))
                      .map((u) => ({
                        id: u.username,
                        label: `${u.username} (${u.dn})`,
                      }))}
                    onChange={(value: MultiSelectOption[]) =>
                      setLdapSelectedUsers(value.map((v) => String(v.id)))
                    }
                    noOptionsText="No LDAP users found"
                    placeholder="Select users to import..."
                  />
                )}

                {ldapSearchError && (
                  <Alert severity="error" className="mt-3">
                    {ldapSearchError}
                  </Alert>
                )}
                <Button
                  variant="primary"
                  size="sm"
                  className="mt-3"
                  onClick={handleLdapImport}
                  disabled={ldapSelectedUsers.length === 0}
                >
                  Import Selected Users
                </Button>
              </SectionCard>
            </div>
          )}

          {/* ─────────────────────────── AZURE AD ───────────────────── */}
          {tab === 'azure-ad' && (
            <SectionCard title="Azure AD Configuration">
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <Checkbox
                  checked={azureAdConfig.enabled}
                  onChange={(v) => setAzureAdConfig({ ...azureAdConfig, enabled: v })}
                  label="Enabled"
                />
                <Input
                  label="Tenant ID"
                  value={azureAdConfig.tenantId}
                  onChange={(e) =>
                    setAzureAdConfig({ ...azureAdConfig, tenantId: e.target.value })
                  }
                />
                <Input
                  label="Client ID"
                  value={azureAdConfig.clientId}
                  onChange={(e) =>
                    setAzureAdConfig({ ...azureAdConfig, clientId: e.target.value })
                  }
                />
                <Input
                  label="Redirect URL"
                  value={azureAdConfig.redirectUrl}
                  onChange={(e) =>
                    setAzureAdConfig({ ...azureAdConfig, redirectUrl: e.target.value })
                  }
                  placeholder={`${window.location.origin}/api/auth/azure/callback`}
                />
                <Checkbox
                  checked={azureAdUpdateSecret}
                  onChange={setAzureAdUpdateSecret}
                  label="Update Client Secret"
                />
                <Input
                  label="Client Secret"
                  type="password"
                  disabled={!azureAdUpdateSecret && (azureAdConfig.passwordConfigured ?? false)}
                  value={
                    !azureAdUpdateSecret && (azureAdConfig.passwordConfigured ?? false)
                      ? 'Configured'
                      : azureAdConfig.clientSecret
                  }
                  onChange={(e) =>
                    setAzureAdConfig({ ...azureAdConfig, clientSecret: e.target.value })
                  }
                />
              </div>
              <div className="mt-4 flex gap-2">
                <Button variant="primary" size="sm" onClick={handleSaveAzureAd}>
                  Save Azure AD Settings
                </Button>
                <Button variant="outline" size="sm" onClick={handleTestAzureAd}>
                  Test Connection
                </Button>
              </div>
              {azureAdTestStatus && (
                <Alert severity={azureAdTestStatus.status} className="mt-3">
                  {azureAdTestStatus.message}
                </Alert>
              )}
            </SectionCard>
          )}

          {/* ─────────────────────────── SESSION ────────────────────── */}
          {tab === 'session' && (
            <SectionCard title="Session Settings">
              <Input
                label="Session Lifetime (minutes)"
                type="number"
                value={sessionMinutes}
                onChange={(e) => setSessionMinutes(Number(e.target.value))}
                className="w-60"
              />
              <Button variant="primary" size="sm" className="mt-4" onClick={handleSaveSession}>
                Save Session
              </Button>
            </SectionCard>
          )}

          {/* ─────────────────────────── CLUSTER ────────────────────── */}
          {tab === 'cluster' && (
            <SectionCard title="Cluster Connection">
              <div className="mb-4 flex flex-wrap gap-2">
                <Badge variant={cluster.active ? 'success' : 'default'}>
                  Active: {cluster.active ? 'Yes' : 'No'}
                </Badge>
                <Badge variant={cluster.ready ? 'success' : 'warning'}>
                  Ready: {cluster.ready ? 'Yes' : 'No'}
                </Badge>
                <Badge variant="default">Method: {cluster.method || 'Not set'}</Badge>
                <Badge variant={authTokenPresent ? 'success' : 'error'}>
                  Auth Token: {authTokenPresent ? 'Present' : 'Missing'}
                </Badge>
              </div>

              {cluster.server && (
                <p className="mb-2 text-sm text-gray-500">API Server: {cluster.server}</p>
              )}

              {!apiReachable && (
                <Alert severity="error" className="mb-4">
                  Backend is not reachable from the browser. Check that{' '}
                  <code>http://localhost:8080/healthz</code> responds.
                </Alert>
              )}
              {cluster.lastError && (
                <Alert severity="warning" className="mb-4">
                  {cluster.lastError}
                </Alert>
              )}

              {/* Last applied cluster info */}
              <div className="mb-4 rounded-lg border border-gray-200 p-4">
                <p className="mb-2 text-sm font-semibold text-gray-700">Last Applied Cluster</p>
                <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-gray-500">
                  <dt className="font-medium text-gray-600">Status</dt>
                  <dd>{lastAppliedCluster.status || 'N/A'}</dd>
                  <dt className="font-medium text-gray-600">Method</dt>
                  <dd>{lastAppliedCluster.method || 'N/A'}</dd>
                  <dt className="font-medium text-gray-600">API Server</dt>
                  <dd>{lastAppliedCluster.server || 'N/A'}</dd>
                  <dt className="font-medium text-gray-600">Kubeconfig File</dt>
                  <dd>{lastAppliedCluster.kubeconfigFileName || 'N/A'}</dd>
                  <dt className="font-medium text-gray-600">CA Cert File</dt>
                  <dd>{lastAppliedCluster.caCertFileName || 'N/A'}</dd>
                  <dt className="font-medium text-gray-600">Applied At</dt>
                  <dd>{lastAppliedCluster.appliedAt || 'N/A'}</dd>
                  {lastAppliedCluster.requestId && (
                    <>
                      <dt className="font-medium text-gray-600">Request ID</dt>
                      <dd>{lastAppliedCluster.requestId}</dd>
                    </>
                  )}
                </dl>
                {lastAppliedCluster.error && (
                  <Alert severity="error" className="mt-2">
                    {lastAppliedCluster.error}
                  </Alert>
                )}
              </div>

              {clusterValidation && (
                <Alert severity={clusterValidation.status} className="mb-4">
                  {clusterValidation.message}
                </Alert>
              )}

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <NativeSelect
                  label="Method"
                  value={clusterConfig.method}
                  onChange={(e) => {
                    setClusterConfig({
                      method: e.target.value,
                      kubeconfigBase64: '',
                      token: '',
                      server: '',
                      caCertBase64: '',
                    });
                  }}
                >
                  <option value="kubeconfig">Kubeconfig</option>
                  <option value="token">ServiceAccount Token</option>
                </NativeSelect>

                {clusterConfig.method === 'kubeconfig' && (
                  <div className="flex flex-col gap-1">
                    <span className="text-sm font-medium text-gray-700">Kubeconfig file</span>
                    <label className="inline-flex cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50">
                      Upload kubeconfig
                      <input
                        type="file"
                        className="hidden"
                        onChange={(e) =>
                          handleFileUpload(e.target.files?.[0] ?? null, 'kubeconfigBase64')
                        }
                      />
                    </label>
                    <span className="text-xs text-gray-400">
                      {kubeconfigFileName ? `Loaded: ${kubeconfigFileName}` : 'No kubeconfig selected'}
                    </span>
                  </div>
                )}

                {clusterConfig.method === 'token' && (
                  <>
                    <Input
                      label="Token"
                      value={clusterConfig.token}
                      onChange={(e) =>
                        setClusterConfig({ ...clusterConfig, token: e.target.value })
                      }
                    />
                    <Input
                      label="API Server"
                      value={clusterConfig.server}
                      onChange={(e) =>
                        setClusterConfig({ ...clusterConfig, server: e.target.value })
                      }
                    />
                    <div className="flex flex-col gap-1">
                      <span className="text-sm font-medium text-gray-700">CA Certificate</span>
                      <label className="inline-flex cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50">
                        Upload CA Cert
                        <input
                          type="file"
                          className="hidden"
                          onChange={(e) =>
                            handleFileUpload(e.target.files?.[0] ?? null, 'caCertBase64')
                          }
                        />
                      </label>
                      <span className="text-xs text-gray-400">
                        {caCertFileName ? `Loaded: ${caCertFileName}` : 'No CA cert selected'}
                      </span>
                    </div>
                  </>
                )}
              </div>

              <div className="mt-4 flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleValidateCluster}
                  disabled={!isClusterConfigValid()}
                >
                  Validate
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={handleSaveCluster}
                  disabled={!isClusterConfigValid()}
                >
                  Apply Cluster Connection
                </Button>
              </div>
            </SectionCard>
          )}

          {/* ─────────────────────────── CUSTOMIZATION ──────────────── */}
          {tab === 'customization' && (
            <SectionCard title="Login Logo">
              <p className="mb-4 text-sm text-gray-500">
                Upload a logo to display on the login screen. Recommended PNG/SVG with transparent
                background.
              </p>

              {logoPreviewUrl && (
                <div className="mb-4 w-full max-w-xs overflow-hidden rounded-lg border border-gray-200 p-2">
                  <img
                    src={logoPreviewUrl}
                    alt="Current logo"
                    onError={() => setLogoPreviewUrl('')}
                    className="h-auto w-full max-w-[320px] object-contain"
                  />
                </div>
              )}

              <div className="flex flex-wrap items-center gap-3">
                <label className="inline-flex cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50">
                  Select Logo
                  <input
                    type="file"
                    className="hidden"
                    accept="image/*,.svg"
                    onChange={(e) => setLogoFile(e.target.files?.[0] ?? null)}
                  />
                </label>
                <span className="text-sm text-gray-400">
                  {logoFile ? logoFile.name : 'No file selected'}
                </span>
                <Button variant="primary" size="sm" onClick={handleUploadLogo} disabled={!logoFile}>
                  Upload
                </Button>
                <Button variant="danger" size="sm" onClick={handleRemoveLogo}>
                  Remove Logo
                </Button>
              </div>

              {logoStatus && (
                <Alert severity={logoStatus.status} className="mt-3">
                  {logoStatus.message}
                </Alert>
              )}
            </SectionCard>
          )}

          {/* ─────────────────────────── AUDIT LOGS ─────────────────── */}
          {tab === 'audit' && (
            <SectionCard title="Audit Logs">
              <div className="mb-4 flex flex-wrap items-end gap-3">
                <Input
                  label="User"
                  value={auditUserFilter}
                  onChange={(e) => {
                    setAuditOffset(0);
                    setAuditUserFilter(e.target.value);
                  }}
                  className="w-40"
                />
                <Input
                  label="Action"
                  value={auditActionFilter}
                  onChange={(e) => {
                    setAuditOffset(0);
                    setAuditActionFilter(e.target.value);
                  }}
                  className="w-40"
                />
                <Input
                  label="Namespace"
                  value={auditNamespaceFilter}
                  onChange={(e) => {
                    setAuditOffset(0);
                    setAuditNamespaceFilter(e.target.value);
                  }}
                  className="w-40"
                />
                <Input
                  label="Start date"
                  type="date"
                  value={auditStartDate}
                  onChange={(e) => {
                    setAuditOffset(0);
                    setAuditStartDate(e.target.value);
                  }}
                />
                <Input
                  label="End date"
                  type="date"
                  value={auditEndDate}
                  onChange={(e) => {
                    setAuditOffset(0);
                    setAuditEndDate(e.target.value);
                  }}
                />
                <div className="flex items-end gap-3">
                  <span className="text-xs text-gray-400">
                    {auditOffset + 1}–{Math.min(auditOffset + 50, auditTotal)} of {auditTotal}
                  </span>
                  <Button variant="outline" size="sm" onClick={handleAuditExport}>
                    Export CSV
                  </Button>
                </div>
              </div>

              <div className="flex flex-col gap-2">
                {auditLogs.map((entry, index) => (
                  <div
                    key={index}
                    className="rounded-lg border border-gray-100 bg-white px-4 py-3"
                  >
                    <p className="text-sm font-semibold text-gray-900">
                      {(entry.user as string) ?? 'unknown'} —{' '}
                      <span className="font-normal text-gray-600">
                        {(entry.action as string) ?? ''}
                      </span>
                    </p>
                    <p className="mt-0.5 text-xs text-gray-400">
                      {(entry.timestampFormatted as string) ??
                        (entry.timestamp as string) ??
                        ''}
                    </p>
                    <p className="text-xs text-gray-500">
                      {(entry.namespace as string) ?? '-'} /{' '}
                      {(entry.resourceType as string) ?? ''} /{' '}
                      {(entry.resourceName as string) ?? ''}
                    </p>
                  </div>
                ))}
              </div>

              <div className="mt-4 flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={auditOffset === 0}
                  onClick={() => setAuditOffset(Math.max(0, auditOffset - 50))}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={auditOffset + 50 >= auditTotal}
                  onClick={() => setAuditOffset(auditOffset + 50)}
                >
                  Next
                </Button>
              </div>
            </SectionCard>
          )}
        </div>
      </div>
    </Layout>
  );
};

export default AdminPage;
