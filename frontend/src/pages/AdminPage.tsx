import React, { useEffect, useState } from 'react';
import Layout from '../components/Layout';
import {
  Alert,
  Badge,
  Button,
  Checkbox,
  Input,
  Modal,
  MultiSelect,
  MultiSelectOption,
  NativeSelect,
  Spinner,
} from '../components/ui';
import { UsersSection } from './admin/UsersSection';
import { GroupsSection } from './admin/GroupsSection';
import { SessionsSection } from './admin/SessionsSection';
import { RecordingSettingsPanel, RecordingsSection } from './admin/RecordingsSection';
import { RolePermissionsPanel } from './admin/RolePermissionsPanel';
import { useTranslation } from 'react-i18next';
import { RolesSection } from './admin/RolesSection';
import { useScopedShortcuts } from '../hooks/useScopedShortcuts';
import { confirm } from '../components/ConfirmDialog';
import {
  User,
  ClusterListItem,
  listClustersAdmin,
  createCluster,
  updateClusterRow,
  deleteClusterRow,
  activateCluster,
  deactivateCluster,
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
import {
  Boxes,
  Clock,
  FileText,
  Image as ImageIcon,
  KeyRound,
  Layers,
  Pencil,
  Plus,
  Power,
  PowerOff,
  Search,
  Settings,
  ShieldCheck,
  Trash2,
  UserPlus,
  Users as UsersIcon,
  Video,
  X,
} from 'lucide-react';

// ─── Tab definitions ──────────────────────────────────────────────────────────

const ADMIN_TABS: Array<{
  label: string;
  value: string;
  icon: React.ComponentType<{ size?: number | string; className?: string }>;
}> = [
  { label: 'Users', value: 'users', icon: UsersIcon },
  { label: 'Groups', value: 'groups', icon: Layers },
  { label: 'Roles', value: 'roles', icon: ShieldCheck },
  { label: 'LDAP', value: 'ldap', icon: UserPlus },
  { label: 'Azure AD', value: 'azure-ad', icon: KeyRound },
  { label: 'Session', value: 'session', icon: Clock },
  { label: 'Clusters', value: 'clusters', icon: Boxes },
  { label: 'Customization', value: 'customization', icon: ImageIcon },
  { label: 'Audit Logs', value: 'audit', icon: FileText },
  { label: 'Sessions', value: 'sessions', icon: KeyRound },
  { label: 'Recordings', value: 'recordings', icon: Video },
];

// Map tab slugs to admin.tabs.* i18n keys; a few older slugs don't line up
// 1:1 so a tiny lookup keeps the dictionary tidy.
const TAB_I18N_KEY: Record<string, string> = {
  users: 'users', groups: 'groups', roles: 'roles',
  ldap: 'ldap', 'azure-ad': 'azure', session: 'session',
  clusters: 'clusters', customization: 'customization',
  audit: 'audit', sessions: 'sessions', recordings: 'recordings',
};

// Classic role-permission form defaults; also what the form resets to after
// an add, so every resource row (and its edit toggle) survives the reset.
const DEFAULT_PERMISSION_MATRIX = {
  pods: { list: true, get: true, logs: false, exec: false, edit: false },
  deployments: { list: true, get: true, restart: false, scale: false, edit: false },
  daemonsets: { list: true, get: true, edit: false },
  statefulsets: { list: true, get: true, scale: false, edit: false },
  hpas: { list: true, get: true, edit: false },
  services: { list: true, get: true, edit: false },
  configmaps: { list: true, get: true, edit: false },
  // Off by default: the classic form should never grant secrets implicitly.
  secrets: { list: false, get: false, reveal: false, edit: false },
  ingresses: { list: true, get: true, edit: false },
  cronjobs: { list: true, get: true, edit: false },
  jobs: { list: true, get: true, edit: false },
};

// ─── Section card ─────────────────────────────────────────────────────────────

const SectionCard: React.FC<{ title: string; description?: string; children: React.ReactNode }> = ({
  title,
  description,
  children,
}) => (
  <section className="card-surface p-5">
    <header className="mb-4 flex items-start justify-between gap-3">
      <div>
        <h3 className="text-sm font-semibold tracking-tight text-slate-900 dark:text-slate-100">{title}</h3>
        {description && <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{description}</p>}
      </div>
    </header>
    {children}
  </section>
);

// ─── Divider ─────────────────────────────────────────────────────────────────

const Divider: React.FC<{ className?: string }> = ({ className = '' }) => (
  <div className={`border-t border-slate-200 dark:border-slate-800 ${className}`} />
);

// ─── AdminPage ────────────────────────────────────────────────────────────────

const AdminPage: React.FC<{ user: User }> = ({ user }) => {
  const navigate = useNavigate();
  const { t: tr } = useTranslation();
  const [tab, setTab] = useState(() => localStorage.getItem('adminActiveTab') || 'users');
  // Role Permissions UI switcher — new layout is default, classic persists via
  // localStorage. The toggle sits inside the Roles tab header; the classic
  // code path stays intact so a single click reverts the whole experience.
  const [rolePermissionsLayout, setRolePermissionsLayout] = useState<'new' | 'classic'>(() => {
    try {
      const v = localStorage.getItem('rolePermissionsLayout');
      return v === 'classic' ? 'classic' : 'new';
    } catch (err) {
      return 'new';
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem('rolePermissionsLayout', rolePermissionsLayout);
    } catch (err) {
      /* ignore */
    }
  }, [rolePermissionsLayout]);

  // Admin page shortcuts: [ / ] cycle sub-sections (physical key — works on
  // Turkish Q where the same keys produce ğ / ü).
  useScopedShortcuts(
    [
      {
        code: 'BracketLeft',
        handler: () => {
          const idx = ADMIN_TABS.findIndex((t) => t.value === tab);
          const next = ADMIN_TABS[(idx - 1 + ADMIN_TABS.length) % ADMIN_TABS.length];
          setTab(next.value);
        },
      },
      {
        code: 'BracketRight',
        handler: () => {
          const idx = ADMIN_TABS.findIndex((t) => t.value === tab);
          const next = ADMIN_TABS[(idx + 1) % ADMIN_TABS.length];
          setTab(next.value);
        },
      },
    ],
    true
  );
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
  // 0 means "all clusters" (wildcard).
  const [newPermissionClusterId, setNewPermissionClusterId] = useState<number>(0);
  const [permissionFormError, setPermissionFormError] = useState<string | null>(null);
  const [permissionMatrix, setPermissionMatrix] = useState(DEFAULT_PERMISSION_MATRIX);
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
  const [showCreateUser, setShowCreateUser] = useState(false);
  const [showCreateGroup, setShowCreateGroup] = useState(false);
  const [showCreateRole, setShowCreateRole] = useState(false);
  const [editingUser, setEditingUser] = useState<null | {
    id: number;
    username: string;
    isActive: boolean;
    isAdmin: boolean;
    groupIds: number[];
  }>(null);
  const [editingGroup, setEditingGroup] = useState<null | {
    id: number;
    name: string;
    roleIds: number[];
  }>(null);
  const [editingRole, setEditingRole] = useState<null | {
    id: number;
    name: string;
    description: string;
  }>(null);
  const [usersFilter, setUsersFilter] = useState('');
  const [groupsFilter, setGroupsFilter] = useState('');
  const [rolesFilter, setRolesFilter] = useState('');
  const [savingDrawer, setSavingDrawer] = useState(false);
  const [clustersList, setClustersList] = useState<ClusterListItem[]>([]);
  const [clustersStatus, setClustersStatus] = useState<{ status: 'success' | 'error'; message: string } | null>(null);
  const [newClusterName, setNewClusterName] = useState('');
  const [newClusterDesc, setNewClusterDesc] = useState('');
  const [newClusterMethod, setNewClusterMethod] = useState<'kubeconfig' | 'token'>('kubeconfig');
  const [newClusterKubeconfig, setNewClusterKubeconfig] = useState('');
  const [newClusterToken, setNewClusterToken] = useState('');
  const [newClusterServer, setNewClusterServer] = useState('');
  const [newClusterCA, setNewClusterCA] = useState('');
  const [newClusterKubeconfigName, setNewClusterKubeconfigName] = useState('');
  const [clusterBusy, setClusterBusy] = useState<number | 'create' | null>(null);
  const [editCluster, setEditCluster] = useState<{
    id: number;
    name: string;
    description: string;
    method: 'kubeconfig' | 'token';
    replaceSecrets: boolean;
    kubeconfigBase64: string;
    kubeconfigName: string;
    token: string;
    server: string;
    caCertBase64: string;
  } | null>(null);
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
    if (tab === 'clusters' || tab === 'roles') {
      // Roles tab also needs the cluster list so the permission form can offer
      // a per-cluster scope selector.
      listClustersAdmin()
        .then((r) => setClustersList(r.items ?? []))
        .catch(() => setClustersList([]));
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

  // Group a role's permissions by (cluster, namespace) so admins can read the
  // matrix at a glance even when the same namespace exists on several clusters.
  const groupedPermissions = React.useMemo(() => {
    const map = new Map<string, NamespacePermission[]>();
    rolePermissions.forEach((perm) => {
      const key = `${perm.clusterId}|${perm.namespace}`;
      const list = map.get(key) ?? [];
      list.push(perm);
      map.set(key, list);
    });
    return Array.from(map.entries()).map(([key, permissions]) => {
      const [clusterIdStr, namespace] = key.split('|');
      return {
        clusterId: Number(clusterIdStr),
        clusterName: permissions[0]?.clusterName ?? '',
        namespace,
        permissions,
      };
    });
  }, [rolePermissions]);

  const handleAddPermission = async () => {
    setPermissionFormError(null);
    if (!selectedRoleId) {
      setPermissionFormError('Select a role first.');
      return;
    }
    const sanitizedNamespaces = newPermissionNamespaces
      .map((n) => n.trim())
      .filter((n) => n.length > 0);
    if (sanitizedNamespaces.length === 0) {
      setPermissionFormError(
        'Enter at least one namespace. Use * to grant on every namespace.'
      );
      return;
    }
    const anyChecked = Object.values(permissionMatrix).some((actions) =>
      Object.values(actions).some(Boolean)
    );
    if (!anyChecked) {
      setPermissionFormError('Pick at least one action in the matrix below.');
      return;
    }
    const existing = new Set(
      rolePermissions.map((perm) => `${perm.clusterId}:${perm.namespace}:${perm.resource}:${perm.action}`)
    );
    const requests: Array<{ resource: string; action: string }> = [];
    Object.entries(permissionMatrix).forEach(([resource, actions]) => {
      Object.entries(actions).forEach(([action, enabled]) => {
        if (enabled) requests.push({ resource, action });
      });
    });
    for (const namespace of sanitizedNamespaces) {
      for (const item of requests) {
        const key = `${newPermissionClusterId}:${namespace}:${item.resource}:${item.action}`;
        if (existing.has(key)) continue;
        await addRolePermission(selectedRoleId, {
          clusterId: newPermissionClusterId || undefined,
          namespace,
          resource: item.resource,
          action: item.action,
        });
      }
    }
    await loadRolePermissions(selectedRoleId);
    setNewPermissionNamespaces([]);
    setPermissionMatrix(DEFAULT_PERMISSION_MATRIX);
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
      setLdapTestStatus({ status: 'success', message: tr('common.ldapTestOk') });
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
      setAzureAdTestStatus({ status: 'success', message: tr('common.azureTestOk') });
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
        message: tr('common.clusterNeedsFields'),
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
          message: tr('common.clusterSyncing'),
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
        message: tr('common.clusterValidateNeeds'),
      });
      return;
    }
    try {
      await validateCluster(clusterConfig);
      setClusterValidation({ status: 'success', message: tr('common.clusterValidated') });
    } catch (err) {
      setClusterValidation({
        status: 'error',
        message: (err as Error).message || 'Validation failed.',
      });
    }
  };

  const handleUploadLogo = async () => {
    if (!logoFile) {
      setLogoStatus({ status: 'error', message: tr('common.logoSelectFile') });
      return;
    }
    setLogoStatus(null);
    try {
      await uploadLogo(logoFile);
      setLogoStatus({ status: 'success', message: tr('common.logoUploaded') });
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
      setLogoStatus({ status: 'success', message: tr('common.logoRemoved') });
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
    <Layout
      user={user}
      panelTitle="Admin"
      panel={
        <nav className="flex flex-col gap-0.5 p-2">
          {ADMIN_TABS.map((entry) => {
            const Icon = entry.icon;
            const active = tab === entry.value;
            const label = tr(`admin.tabs.${TAB_I18N_KEY[entry.value] ?? entry.value}`, { defaultValue: entry.label });
            return (
              <button
                key={entry.value}
                onClick={() => setTab(entry.value)}
                className={`flex items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm transition-colors ${
                  active
                    ? 'bg-brand-50 dark:bg-brand-500/15 font-medium text-brand-700 dark:text-brand-200 ring-1 ring-inset ring-brand-200 dark:ring-brand-500/30'
                    : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 dark:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100 dark:text-slate-100'
                }`}
              >
                <Icon
                  size={15}
                  className={active ? 'text-brand-600 dark:text-brand-300' : 'text-slate-400 dark:text-slate-500'}
                />
                {label}
              </button>
            );
          })}
        </nav>
      }
    >
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-medium text-slate-500 dark:text-slate-400">
            <Settings size={14} className="text-brand-600 dark:text-brand-300" />
            <span className="uppercase tracking-wider">{tr("common.administration")}</span>
          </div>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">
            {(() => {
              const entry = ADMIN_TABS.find((t) => t.value === tab);
              if (!entry) return 'Admin';
              return tr(`admin.tabs.${TAB_I18N_KEY[entry.value] ?? entry.value}`, { defaultValue: entry.label });
            })()}
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            {tr('admin.cards.subtitle')}
          </p>
        </div>
      </div>

      {error && (
        <Alert severity="error" className="mt-4">
          {error}
        </Alert>
      )}

      <div className="card-surface mt-6 overflow-hidden">
        <div className="p-5">
          {/* ─────────────────────────── USERS ──────────────────────── */}
          {tab === 'users' && (
            <UsersSection
              users={users}
              groups={groups}
              userGroups={userGroups}
              filter={usersFilter}
              onFilter={setUsersFilter}
              onNew={() => {
                setNewUser({ username: '', password: '', isAdmin: false });
                setShowCreateUser(true);
              }}
              onEdit={(u) =>
                setEditingUser({
                  id: u.id,
                  username: u.username,
                  isActive: u.isActive,
                  isAdmin: u.isAdmin,
                  groupIds: (userGroups[u.id] ?? []).map((g) => g.id),
                })
              }
              onDelete={async (u) => {
                const ok = await confirm({
                  title: tr("common.deleteUser", { name: u.username }),
                  message:
                    'This removes the user. If they are the last active admin, the operation will be refused.',
                  confirmText: 'Delete',
                  variant: 'danger',
                });
                if (!ok) return;
                setError(null);
                try {
                  await deleteUser(u.id);
                  await refresh();
                } catch (err) {
                  setError((err as Error).message || 'Delete failed.');
                }
              }}
            />
          )}

          {/* ─────────────────────────── GROUPS ─────────────────────── */}
          {tab === 'groups' && (
            <GroupsSection
              groups={groups}
              roles={roles}
              groupRoles={groupRoles}
              users={users}
              userGroups={userGroups}
              filter={groupsFilter}
              onFilter={setGroupsFilter}
              onNew={() => {
                setNewGroup('');
                setShowCreateGroup(true);
              }}
              onEdit={(g) =>
                setEditingGroup({
                  id: g.id,
                  name: g.name,
                  roleIds: (groupRoles[g.id] ?? []).map((r) => r.id),
                })
              }
              onDelete={async (g) => {
                const ok = await confirm({
                  title: tr("common.deleteGroup", { name: g.name }),
                  message:
                    'Members of this group will lose any roles they inherited through it.',
                  confirmText: 'Delete',
                  variant: 'danger',
                });
                if (!ok) return;
                setError(null);
                try {
                  await deleteGroup(g.id);
                  await refresh();
                } catch (err) {
                  setError((err as Error).message || 'Delete failed.');
                }
              }}
            />
          )}

          {/* ─────────────────────────── ROLES ──────────────────────── */}
          {tab === 'roles' && (
            <div className="flex flex-col gap-5">
              <RolesSection
                roles={roles}
                groupRoles={groupRoles}
                filter={rolesFilter}
                onFilter={setRolesFilter}
                onNew={() => {
                  setNewRole({ name: '', description: '' });
                  setShowCreateRole(true);
                }}
                onEdit={(r) =>
                  setEditingRole({ id: r.id, name: r.name, description: r.description })
                }
                onDelete={async (r) => {
                  const ok = await confirm({
                    title: tr("common.deleteRole", { name: r.name }),
                    message:
                      'All permissions attached to this role and all group assignments pointing to it are removed.',
                    confirmText: 'Delete',
                    variant: 'danger',
                  });
                  if (!ok) return;
                  setError(null);
                  try {
                    await deleteRole(r.id);
                    await refresh();
                  } catch (err) {
                    setError((err as Error).message || 'Delete failed.');
                  }
                }}
              />

              {rolePermissionsLayout === 'new' ? (
                <SectionCard title={tr('admin.sections.rolePermissions')}>
                  <RolePermissionsPanel
                    roles={roles}
                    clusters={clustersList}
                    namespaces={namespaceOptions}
                    onError={setError}
                    onSwitchClassic={() => setRolePermissionsLayout('classic')}
                  />
                </SectionCard>
              ) : (
              <SectionCard title={tr('admin.sections.rolePermissions')}>
                <div className="mb-3 flex justify-end">
                  <button
                    type="button"
                    onClick={() => setRolePermissionsLayout('new')}
                    className="text-[11px] font-medium text-slate-500 underline-offset-4 hover:text-brand-600 hover:underline dark:text-slate-400 dark:hover:text-brand-300"
                  >
                    {tr('admin.switchToNew')}
                  </button>
                </div>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                  <NativeSelect
                    label={tr("common.role")}
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

                  <NativeSelect
                    label={tr("common.clusterScope")}
                    value={newPermissionClusterId}
                    onChange={(e) => setNewPermissionClusterId(Number(e.target.value))}
                  >
                    <option value={0}>{tr("common.allClusters")}</option>
                    {clustersList.map((c) => (
                      <option key={c.id} value={c.id}>
                        {c.name}
                      </option>
                    ))}
                  </NativeSelect>

                  <MultiSelect
                    label={tr("common.namespaces")}
                    options={[
                      { id: '*', label: '* (all namespaces)' },
                      ...namespaceOptions.map((ns) => ({ id: ns, label: ns })),
                    ]}
                    value={newPermissionNamespaces.map((ns) => ({
                      id: ns,
                      label: ns === '*' ? '* (all namespaces)' : ns,
                    }))}
                    onChange={(value: MultiSelectOption[]) =>
                      setNewPermissionNamespaces(value.map((v) => String(v.id)))
                    }
                    placeholder={tr("common.pickNsOrStar")}
                    noOptionsText={
                      namespaceOptions.length === 0
                        ? 'No namespaces visible — activate a cluster first.'
                        : 'No matching namespace.'
                    }
                  />
                </div>

                <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
                  {Object.entries(permissionMatrix).map(([resource, actions]) => (
                    <div
                      key={resource}
                      className="rounded-lg border border-slate-200 dark:border-slate-800 p-3"
                    >
                      <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-700 dark:text-slate-200">
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

                {permissionFormError && (
                  <Alert severity="warning" className="mt-4">
                    {permissionFormError}
                  </Alert>
                )}
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
                    <p className="text-sm text-slate-400 dark:text-slate-500">Select a role to view its permissions.</p>
                  )}
                  {selectedRoleId && groupedPermissions.length === 0 && (
                    <p className="text-sm text-slate-400 dark:text-slate-500">No permissions assigned yet.</p>
                  )}
                  {selectedRoleId && groupedPermissions.length > 0 && (
                    <div className="overflow-auto rounded-lg border border-slate-200 dark:border-slate-800">
                      <table className="w-full text-sm">
                        <thead className="bg-slate-50 dark:bg-slate-900">
                          <tr>
                            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-300">
                              Cluster
                            </th>
                            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-300">
                              Namespace
                            </th>
                            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-300">
                              Permissions
                            </th>
                            <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-300">
                              Actions
                            </th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                          {groupedPermissions.map((group) => (
                            <tr key={`${group.clusterId}:${group.namespace}`}>
                              <td className="px-4 py-3">
                                {group.clusterId === 0 ? (
                                  <Badge variant="info">{tr("common.allClusters")}</Badge>
                                ) : (
                                  <span className="font-mono text-xs text-slate-700 dark:text-slate-200">
                                    {group.clusterName || `#${group.clusterId}`}
                                  </span>
                                )}
                              </td>
                              <td className="px-4 py-3 font-medium text-slate-900 dark:text-slate-100">
                                {group.namespace}
                              </td>
                              <td className="px-4 py-3">
                                <div className="flex flex-wrap gap-1.5">
                                  {group.permissions.map((perm) => (
                                    <span
                                      key={perm.id}
                                      className="group inline-flex items-center gap-1 rounded border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-2 py-0.5 text-xs text-slate-700 dark:text-slate-200 hover:border-slate-300"
                                    >
                                      {perm.resource}:{perm.action}
                                      <button
                                        type="button"
                                        onClick={() => handleRemovePermission(perm.id)}
                                        className="text-slate-300 transition-opacity group-hover:text-red-400 focus:outline-none"
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
                                  onClick={() => {
                                    const ids = group.permissions.map((p) => p.id);
                                    ids.forEach((id) => void handleRemovePermission(id));
                                  }}
                                >
                                  Remove Row
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
              )}
            </div>
          )}

          {/* ─────────────────────────── LDAP ───────────────────────── */}
          {tab === 'ldap' && (
            <div className="flex flex-col gap-5">
              <SectionCard title={tr('admin.sections.ldap')}>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
                  <Checkbox
                    checked={ldapConfig.enabled}
                    onChange={(v) => setLdapConfig({ ...ldapConfig, enabled: v })}
                    label={tr("admin.ldap.enabled")}
                  />
                  <Input
                    label={tr("admin.ldap.host")}
                    value={ldapConfig.host}
                    onChange={(e) => setLdapConfig({ ...ldapConfig, host: e.target.value })}
                  />
                  <Input
                    label={tr("admin.ldap.port")}
                    type="number"
                    value={ldapConfig.port}
                    onChange={(e) =>
                      setLdapConfig({ ...ldapConfig, port: Number(e.target.value) })
                    }
                  />
                  <Checkbox
                    checked={ldapConfig.useSsl}
                    onChange={(v) => setLdapConfig({ ...ldapConfig, useSsl: v })}
                    label={tr("admin.ldap.useSsl")}
                  />
                  <Checkbox
                    checked={ldapConfig.startTls}
                    onChange={(v) => setLdapConfig({ ...ldapConfig, startTls: v })}
                    label={tr("admin.ldap.startTls")}
                  />
                  <Checkbox
                    checked={ldapConfig.sslSkipVerify}
                    onChange={(v) => setLdapConfig({ ...ldapConfig, sslSkipVerify: v })}
                    label={tr("admin.ldap.skipVerify")}
                  />
                  <Input
                    label={tr("admin.ldap.timeout")}
                    type="number"
                    value={ldapConfig.timeoutSeconds}
                    onChange={(e) =>
                      setLdapConfig({ ...ldapConfig, timeoutSeconds: Number(e.target.value) })
                    }
                  />
                  <Input
                    label={tr("admin.ldap.bindDn")}
                    value={ldapConfig.bindDn}
                    onChange={(e) => setLdapConfig({ ...ldapConfig, bindDn: e.target.value })}
                  />
                  <Checkbox
                    checked={ldapUpdatePassword}
                    onChange={setLdapUpdatePassword}
                    label={tr("common.updateBindPassword")}
                  />
                  <Input
                    label={tr("common.bindPassword")}
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
                    label={tr("common.userBaseDnSingle")}
                    value={ldapConfig.userBaseDn}
                    onChange={(e) =>
                      setLdapConfig({ ...ldapConfig, userBaseDn: e.target.value })
                    }
                  />
                  <Input
                    label={tr("common.userBaseDnMulti")}
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
                    label={tr("common.userFilter")}
                    value={ldapConfig.userFilter}
                    onChange={(e) =>
                      setLdapConfig({ ...ldapConfig, userFilter: e.target.value })
                    }
                  />
                  <Input
                    label={tr("common.usernameAttribute")}
                    value={ldapConfig.usernameAttribute}
                    onChange={(e) =>
                      setLdapConfig({ ...ldapConfig, usernameAttribute: e.target.value })
                    }
                  />
                </div>
                <div className="mt-4 flex gap-2">
                  <Button variant="primary" size="sm" onClick={handleSaveLDAP}>
                    {tr("admin.ldap.save")}
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

              <SectionCard title={tr('admin.cards.importLdapUsers')}>
                <div className="flex flex-wrap gap-3">
                  <Input
                    label={tr("common.searchQuery")}
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
                    label={tr("common.ldapUsers")}
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
                    placeholder={tr("common.selectToImport")}
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
            <SectionCard title={tr('admin.sections.azureAd')}>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <Checkbox
                  checked={azureAdConfig.enabled}
                  onChange={(v) => setAzureAdConfig({ ...azureAdConfig, enabled: v })}
                  label={tr("admin.ldap.enabled")}
                />
                <Input
                  label={tr("admin.azure.tenantId")}
                  value={azureAdConfig.tenantId}
                  onChange={(e) =>
                    setAzureAdConfig({ ...azureAdConfig, tenantId: e.target.value })
                  }
                />
                <Input
                  label={tr("admin.azure.clientId")}
                  value={azureAdConfig.clientId}
                  onChange={(e) =>
                    setAzureAdConfig({ ...azureAdConfig, clientId: e.target.value })
                  }
                />
                <Input
                  label={tr("admin.azure.redirectUrl")}
                  value={azureAdConfig.redirectUrl}
                  onChange={(e) =>
                    setAzureAdConfig({ ...azureAdConfig, redirectUrl: e.target.value })
                  }
                  placeholder={`${window.location.origin}/api/auth/azure/callback`}
                />
                <Checkbox
                  checked={azureAdUpdateSecret}
                  onChange={setAzureAdUpdateSecret}
                  label={tr("common.updateClientSecret")}
                />
                <Input
                  label={tr("common.clientSecret")}
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
                  {tr("admin.azure.save")}
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
            <SectionCard title={tr('admin.sections.sessionSettings')}>
              <Input
                label={tr("common.sessionLifetime")}
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

          {/* ─────────────────────────── CLUSTERS (multi) ───────────── */}
          {tab === 'clusters' && (
            <div className="flex flex-col gap-5">
              <SectionCard
                title={tr('admin.cards.configuredClusters')}
                description={tr('admin.cards.configuredClustersDesc')}
              >
                {clustersStatus && (
                  <Alert severity={clustersStatus.status} className="mb-4">
                    {clustersStatus.message}
                  </Alert>
                )}
                {clustersList.length === 0 ? (
                  <p className="text-sm text-slate-400">
                    No clusters saved yet. Add one below.
                  </p>
                ) : (
                  <div className="flex flex-col gap-2">
                    {clustersList.map((c) => (
                      <div
                        key={c.id}
                        className={`flex flex-wrap items-center justify-between gap-3 rounded-lg border p-3 ${
                          c.isActive
                            ? 'border-brand-200 bg-brand-50/40 dark:border-brand-500/30 dark:bg-brand-500/10'
                            : 'border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900/40'
                        }`}
                      >
                        <div className="flex min-w-0 items-center gap-3">
                          <div
                            className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-md ${
                              c.isActive
                                ? 'bg-brand-500 text-white'
                                : 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400'
                            }`}
                          >
                            <Boxes size={14} />
                          </div>
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="truncate font-mono text-sm font-semibold text-slate-900 dark:text-slate-100">
                                {c.name}
                              </span>
                              {c.isActive && <Badge variant="success">{tr("common.defaultCluster")}</Badge>}
                            </div>
                            <div className="truncate text-xs text-slate-500 dark:text-slate-400">
                              {c.description || c.server || tr('common.methodLabel', { method: c.method })}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          {c.isActive ? (
                            <Button
                              variant="outline"
                              size="sm"
                              disabled={clusterBusy !== null}
                              onClick={async () => {
                                const ok = await confirm({
                                  title: tr('common.deactivateTitle', { name: c.name }),
                                  message:
                                    tr('common.deactivateMessage'),
                                  confirmText: tr('common.deactivate'),
                                  variant: 'danger',
                                });
                                if (!ok) return;
                                setClusterBusy(c.id);
                                setClustersStatus(null);
                                try {
                                  await deactivateCluster(c.id);
                                  setClustersStatus({ status: 'success', message: tr('common.deactivated', { name: c.name }) });
                                  setTimeout(() => window.location.reload(), 600);
                                } catch (err) {
                                  setClustersStatus({ status: 'error', message: (err as Error).message || tr('common.deactivateFailed', { name: c.name }) });
                                } finally {
                                  setClusterBusy(null);
                                }
                              }}
                            >
                              <PowerOff size={13} />
                              {tr('common.deactivate')}
                            </Button>
                          ) : (
                            <Button
                              variant="outline"
                              size="sm"
                              disabled={clusterBusy !== null}
                              onClick={async () => {
                                setClusterBusy(c.id);
                                setClustersStatus(null);
                                try {
                                  await activateCluster(c.id);
                                  setClustersStatus({ status: 'success', message: tr('common.activated', { name: c.name }) });
                                  setTimeout(() => window.location.reload(), 600);
                                } catch (err) {
                                  setClustersStatus({ status: 'error', message: (err as Error).message || tr('common.activateFailed', { name: c.name }) });
                                } finally {
                                  setClusterBusy(null);
                                }
                              }}
                            >
                              <Power size={13} />
                              {tr('common.activate')}
                            </Button>
                          )}
                          <Button
                            variant="outline"
                            size="sm"
                            disabled={clusterBusy !== null}
                            onClick={() =>
                              setEditCluster({
                                id: c.id,
                                name: c.name,
                                description: c.description ?? '',
                                method: (c.method as 'kubeconfig' | 'token') || 'kubeconfig',
                                replaceSecrets: false,
                                kubeconfigBase64: '',
                                kubeconfigName: '',
                                token: '',
                                server: c.server ?? '',
                                caCertBase64: '',
                              })
                            }
                          >
                            <Pencil size={13} />
                            {tr('actions.edit')}
                          </Button>
                          <Button
                            variant="danger"
                            size="sm"
                            disabled={c.isActive || clusterBusy !== null}
                            onClick={async () => {
                              const ok = await confirm({
                                title: tr("common.deleteCluster", { name: c.name }),
                                message:
                                  'The cluster entry and its stored credentials are removed. If this cluster is active, deactivate it first.',
                                confirmText: 'Delete',
                                variant: 'danger',
                              });
                              if (!ok) return;
                              setClusterBusy(c.id);
                              setClustersStatus(null);
                              try {
                                await deleteClusterRow(c.id);
                                const refreshed = await listClustersAdmin();
                                setClustersList(refreshed.items ?? []);
                              } catch (err) {
                                setClustersStatus({ status: 'error', message: (err as Error).message || 'Delete failed.' });
                              } finally {
                                setClusterBusy(null);
                              }
                            }}
                          >
                            <Trash2 size={13} />
                            {tr('actions.delete')}
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </SectionCard>

              <SectionCard
                title={tr('admin.cards.addCluster')}
                description={tr('admin.cards.addClusterDesc')}
              >
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <Input
                    label={tr("common.name")}
                    value={newClusterName}
                    onChange={(e) => setNewClusterName(e.target.value)}
                    placeholder={tr('common.clusterNamePlaceholder')}
                  />
                  <Input
                    label={tr("common.description")}
                    value={newClusterDesc}
                    onChange={(e) => setNewClusterDesc(e.target.value)}
                    placeholder={tr("common.optional")}
                  />
                  <NativeSelect
                    label={tr("common.method")}
                    value={newClusterMethod}
                    onChange={(e) => setNewClusterMethod(e.target.value as 'kubeconfig' | 'token')}
                  >
                    <option value="kubeconfig">{tr("common.kubeconfig")}</option>
                    <option value="token">{tr("common.serviceAccountToken")}</option>
                  </NativeSelect>
                  {newClusterMethod === 'kubeconfig' && (
                    <div className="flex flex-col gap-1">
                      <span className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                        {tr('common.kubeconfigFile')}
                      </span>
                      <label className="inline-flex cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800">
                        {tr('common.uploadKubeconfig')}
                        <input
                          type="file"
                          className="hidden"
                          onChange={(e) => {
                            const file = e.target.files?.[0];
                            if (!file) {
                              setNewClusterKubeconfig('');
                              setNewClusterKubeconfigName('');
                              return;
                            }
                            const reader = new FileReader();
                            reader.onload = () => {
                              const result = reader.result?.toString() ?? '';
                              const base64 = result.includes(',') ? result.split(',')[1] : result;
                              setNewClusterKubeconfig(base64);
                              setNewClusterKubeconfigName(file.name);
                            };
                            reader.readAsDataURL(file);
                          }}
                        />
                      </label>
                      <span className="text-xs text-slate-400">
                        {newClusterKubeconfigName || tr('common.noFileSelected')}
                      </span>
                    </div>
                  )}
                  {newClusterMethod === 'token' && (
                    <>
                      <Input
                        label={tr("common.apiServer")}
                        value={newClusterServer}
                        onChange={(e) => setNewClusterServer(e.target.value)}
                        placeholder={tr("common.httpsExample")}
                      />
                      <Input
                        label={tr("common.token")}
                        value={newClusterToken}
                        onChange={(e) => setNewClusterToken(e.target.value)}
                      />
                      <Input
                        label={tr("common.caCert")}
                        value={newClusterCA}
                        onChange={(e) => setNewClusterCA(e.target.value)}
                      />
                    </>
                  )}
                </div>
                <Button
                  variant="primary"
                  size="sm"
                  className="mt-4"
                  disabled={clusterBusy !== null || !newClusterName}
                  onClick={async () => {
                    setClusterBusy('create');
                    setClustersStatus(null);
                    try {
                      await createCluster({
                        name: newClusterName,
                        description: newClusterDesc,
                        method: newClusterMethod,
                        kubeconfigBase64: newClusterKubeconfig || undefined,
                        token: newClusterToken || undefined,
                        server: newClusterServer || undefined,
                        caCertBase64: newClusterCA || undefined,
                      });
                      setNewClusterName('');
                      setNewClusterDesc('');
                      setNewClusterKubeconfig('');
                      setNewClusterKubeconfigName('');
                      setNewClusterToken('');
                      setNewClusterServer('');
                      setNewClusterCA('');
                      const refreshed = await listClustersAdmin();
                      setClustersList(refreshed.items ?? []);
                      setClustersStatus({ status: 'success', message: tr('common.clusterAdded') });
                    } catch (err) {
                      setClustersStatus({ status: 'error', message: (err as Error).message || 'Create failed.' });
                    } finally {
                      setClusterBusy(null);
                    }
                  }}
                >
                  {tr('common.saveCluster')}
                </Button>
              </SectionCard>
            </div>
          )}

          {/* ── Edit cluster modal ───────────────────────────────────── */}
          {editCluster && (
            <Modal
              open={editCluster !== null}
              onClose={() => setEditCluster(null)}
              title={`Edit cluster · ${editCluster.name}`}
              size="md"
              footer={
                <>
                  <Button variant="outline" size="sm" onClick={() => setEditCluster(null)}>
                    Cancel
                  </Button>
                  <Button
                    variant="primary"
                    size="sm"
                    disabled={clusterBusy !== null || !editCluster.name}
                    onClick={async () => {
                      if (!editCluster) return;
                      setClusterBusy(editCluster.id);
                      setClustersStatus(null);
                      try {
                        await updateClusterRow(editCluster.id, {
                          name: editCluster.name,
                          description: editCluster.description,
                          method: editCluster.method,
                          replaceSecrets: editCluster.replaceSecrets,
                          kubeconfigBase64: editCluster.replaceSecrets ? editCluster.kubeconfigBase64 || undefined : undefined,
                          token: editCluster.replaceSecrets ? editCluster.token || undefined : undefined,
                          server: editCluster.replaceSecrets ? editCluster.server || undefined : undefined,
                          caCertBase64: editCluster.replaceSecrets ? editCluster.caCertBase64 || undefined : undefined,
                        });
                        const refreshed = await listClustersAdmin();
                        setClustersList(refreshed.items ?? []);
                        setClustersStatus({ status: 'success', message: tr('common.clusterUpdated') });
                        setEditCluster(null);
                      } catch (err) {
                        setClustersStatus({ status: 'error', message: (err as Error).message || 'Update failed.' });
                      } finally {
                        setClusterBusy(null);
                      }
                    }}
                  >
                    Save Changes
                  </Button>
                </>
              }
            >
              <div className="flex flex-col gap-3">
                <Input
                  label={tr("common.name")}
                  value={editCluster.name}
                  onChange={(e) => setEditCluster({ ...editCluster, name: e.target.value })}
                />
                <Input
                  label={tr("common.description")}
                  value={editCluster.description}
                  onChange={(e) => setEditCluster({ ...editCluster, description: e.target.value })}
                />
                <Checkbox
                  checked={editCluster.replaceSecrets}
                  onChange={(v) => setEditCluster({ ...editCluster, replaceSecrets: v })}
                  label={tr("common.replaceCreds")}
                />
                {editCluster.replaceSecrets && (
                  <>
                    <NativeSelect
                      label={tr("common.method")}
                      value={editCluster.method}
                      onChange={(e) =>
                        setEditCluster({ ...editCluster, method: e.target.value as 'kubeconfig' | 'token' })
                      }
                    >
                      <option value="kubeconfig">{tr("common.kubeconfig")}</option>
                      <option value="token">{tr("common.serviceAccountToken")}</option>
                    </NativeSelect>
                    {editCluster.method === 'kubeconfig' && (
                      <div className="flex flex-col gap-1">
                        <span className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                          New Kubeconfig
                        </span>
                        <label className="inline-flex cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800">
                          {tr('common.uploadKubeconfig')}
                          <input
                            type="file"
                            className="hidden"
                            onChange={(e) => {
                              const file = e.target.files?.[0];
                              if (!file) {
                                setEditCluster({ ...editCluster, kubeconfigBase64: '', kubeconfigName: '' });
                                return;
                              }
                              const reader = new FileReader();
                              reader.onload = () => {
                                const result = reader.result?.toString() ?? '';
                                const base64 = result.includes(',') ? result.split(',')[1] : result;
                                setEditCluster({ ...editCluster, kubeconfigBase64: base64, kubeconfigName: file.name });
                              };
                              reader.readAsDataURL(file);
                            }}
                          />
                        </label>
                        <span className="text-xs text-slate-400">
                          {editCluster.kubeconfigName || tr('common.noFileSelected')}
                        </span>
                      </div>
                    )}
                    {editCluster.method === 'token' && (
                      <>
                        <Input
                          label={tr("common.apiServer")}
                          value={editCluster.server}
                          onChange={(e) => setEditCluster({ ...editCluster, server: e.target.value })}
                        />
                        <Input
                          label={tr("common.token")}
                          value={editCluster.token}
                          onChange={(e) => setEditCluster({ ...editCluster, token: e.target.value })}
                        />
                        <Input
                          label={tr("common.caCert")}
                          value={editCluster.caCertBase64}
                          onChange={(e) =>
                            setEditCluster({ ...editCluster, caCertBase64: e.target.value })
                          }
                        />
                      </>
                    )}
                  </>
                )}
              </div>
            </Modal>
          )}

          {/* ─────────────────────────── CUSTOMIZATION ──────────────── */}
          {tab === 'customization' && (
            <SectionCard title={tr('admin.cards.loginLogo')}>
              <p className="mb-4 text-sm text-slate-500 dark:text-slate-400">
                Upload a logo to display on the login screen. Recommended PNG/SVG with transparent
                background.
              </p>

              {logoPreviewUrl && (
                <div className="mb-4 w-full max-w-xs overflow-hidden rounded-lg border border-slate-200 dark:border-slate-800 p-2">
                  <img
                    src={logoPreviewUrl}
                    alt="Current logo"
                    onError={() => setLogoPreviewUrl('')}
                    className="h-auto w-full max-w-[320px] object-contain"
                  />
                </div>
              )}

              <div className="flex flex-wrap items-center gap-3">
                <label className="inline-flex cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-200 transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/60 dark:bg-slate-900">
                  Select Logo
                  <input
                    type="file"
                    className="hidden"
                    accept="image/*,.svg"
                    onChange={(e) => setLogoFile(e.target.files?.[0] ?? null)}
                  />
                </label>
                <span className="text-sm text-slate-400 dark:text-slate-500">
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
            <SectionCard title={tr('admin.sections.audit')}>
              <div className="mb-4 flex flex-wrap items-end gap-3">
                <Input
                  label={tr("admin.audit.filterUser")}
                  value={auditUserFilter}
                  onChange={(e) => {
                    setAuditOffset(0);
                    setAuditUserFilter(e.target.value);
                  }}
                  className="w-40"
                />
                <Input
                  label={tr("admin.audit.filterAction")}
                  value={auditActionFilter}
                  onChange={(e) => {
                    setAuditOffset(0);
                    setAuditActionFilter(e.target.value);
                  }}
                  className="w-40"
                />
                <Input
                  label={tr("admin.audit.filterNamespace")}
                  value={auditNamespaceFilter}
                  onChange={(e) => {
                    setAuditOffset(0);
                    setAuditNamespaceFilter(e.target.value);
                  }}
                  className="w-40"
                />
                <Input
                  label={tr("admin.audit.filterStart")}
                  type="date"
                  value={auditStartDate}
                  onChange={(e) => {
                    setAuditOffset(0);
                    setAuditStartDate(e.target.value);
                  }}
                />
                <Input
                  label={tr("admin.audit.filterEnd")}
                  type="date"
                  value={auditEndDate}
                  onChange={(e) => {
                    setAuditOffset(0);
                    setAuditEndDate(e.target.value);
                  }}
                />
                <div className="flex items-end gap-3">
                  <span className="text-xs text-slate-400 dark:text-slate-500">
                    {tr('admin.audit.pageOf', { from: auditOffset + 1, to: Math.min(auditOffset + 50, auditTotal), total: auditTotal })}
                  </span>
                  <Button variant="outline" size="sm" onClick={handleAuditExport}>
                    {tr('admin.audit.exportCsv')}
                  </Button>
                </div>
              </div>

              <div className="flex flex-col gap-2">
                {auditLogs.map((entry, index) => (
                  <div
                    key={index}
                    className="rounded-lg border border-slate-100 dark:border-slate-800 bg-white dark:bg-slate-900 px-4 py-3"
                  >
                    <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {(entry.user as string) ?? 'unknown'} —{' '}
                      <span className="font-normal text-slate-600 dark:text-slate-300">
                        {(entry.action as string) ?? ''}
                      </span>
                    </p>
                    <p className="mt-0.5 text-xs text-slate-400 dark:text-slate-500">
                      {(entry.timestampFormatted as string) ??
                        (entry.timestamp as string) ??
                        ''}
                    </p>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      {typeof entry.cluster === 'string' && entry.cluster !== '' && entry.cluster !== '-' && (
                        <span
                          className="mr-1.5 rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-600 dark:bg-slate-800 dark:text-slate-300"
                          title={tr('admin.audit.cluster')}
                        >
                          {entry.cluster}
                        </span>
                      )}
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
                  {tr('admin.audit.prev')}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={auditOffset + 50 >= auditTotal}
                  onClick={() => setAuditOffset(auditOffset + 50)}
                >
                  {tr('admin.audit.next')}
                </Button>
              </div>
            </SectionCard>
          )}

          {tab === 'sessions' && (
            <SectionCard
              title={tr('admin.sections.sessions')}
              description={tr('admin.cards.sessionsDesc')}
            >
              <SessionsSection currentUserId={user.id} />
            </SectionCard>
          )}

          {tab === 'recordings' && (
            <div className="flex flex-col gap-5">
              <SectionCard
                title={tr('admin.sections.recordingSettings')}
                description={tr('recordings.settingsDescription')}
              >
                <RecordingSettingsPanel />
              </SectionCard>
              <SectionCard
                title={tr('admin.sections.recordings')}
                description={tr('recordings.listDescription')}
              >
                <RecordingsSection />
              </SectionCard>
            </div>
          )}
        </div>
      </div>

      {/* ── Create User modal ─────────────────────────────────────── */}
      {(() => {
        const submit = async () => {
          if (!newUser.username || !newUser.password) return;
          setSavingDrawer(true);
          setError(null);
          try {
            await handleCreateUser();
            setShowCreateUser(false);
          } catch (err) {
            setError((err as Error).message || 'Create failed.');
          } finally {
            setSavingDrawer(false);
          }
        };
        return (
          <Modal
            open={showCreateUser}
            onClose={() => setShowCreateUser(false)}
            title={tr('admin.newUser')}
            size="sm"
            footer={
              <>
                <Button variant="outline" size="sm" onClick={() => setShowCreateUser(false)}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  disabled={savingDrawer || !newUser.username || !newUser.password}
                  onClick={submit}
                >
                  {savingDrawer ? 'Creating…' : 'Create user'}
                </Button>
              </>
            }
          >
            <form
              className="flex flex-col gap-4"
              onSubmit={(e) => {
                e.preventDefault();
                void submit();
              }}
            >
              <Input
                label={tr("common.username")}
                value={newUser.username}
                onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                autoFocus
              />
              <Input
                label={tr("common.password")}
                type="password"
                value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
              />
              <Checkbox
                checked={newUser.isAdmin}
                onChange={(v) => setNewUser({ ...newUser, isAdmin: v })}
                label={tr("common.grantAdmin")}
              />
              <button type="submit" className="hidden" aria-hidden="true" />
            </form>
          </Modal>
        );
      })()}

      {/* ── Edit User modal ───────────────────────────────────────── */}
      {editingUser && (() => {
        const submit = async () => {
          if (!editingUser) return;
          setSavingDrawer(true);
          setError(null);
          try {
            await updateUser(editingUser.id, {
              username: editingUser.username,
              isActive: editingUser.isActive,
              isAdmin: editingUser.isAdmin,
            });
            await setUserGroups(editingUser.id, editingUser.groupIds);
            await refresh();
            setEditingUser(null);
          } catch (err) {
            setError((err as Error).message || 'Save failed.');
          } finally {
            setSavingDrawer(false);
          }
        };
        return (
          <Modal
            open={editingUser !== null}
            onClose={() => setEditingUser(null)}
            title={`Edit · ${editingUser.username}`}
            size="md"
            footer={
              <>
                <Button variant="outline" size="sm" onClick={() => setEditingUser(null)}>
                  Cancel
                </Button>
                <Button variant="primary" size="sm" disabled={savingDrawer} onClick={submit}>
                  {savingDrawer ? tr('yamlEditor.saving') : tr('actions.save')}
                </Button>
              </>
            }
          >
            <form
              className="flex flex-col gap-4"
              onSubmit={(e) => {
                e.preventDefault();
                void submit();
              }}
            >
              <Input
                label={tr("common.username")}
                value={editingUser.username}
                onChange={(e) => setEditingUser({ ...editingUser, username: e.target.value })}
                autoFocus
              />
              <div className="flex items-center gap-5">
                <Checkbox
                  checked={editingUser.isActive}
                  onChange={(v) => setEditingUser({ ...editingUser, isActive: v })}
                  label={tr("common.active")}
                />
                <Checkbox
                  checked={editingUser.isAdmin}
                  onChange={(v) => setEditingUser({ ...editingUser, isAdmin: v })}
                  label={tr("common.admin")}
                />
              </div>
              <MultiSelect
                label={tr("common.groups")}
                options={groups.map((g) => ({ id: g.id, label: g.name }))}
                value={editingUser.groupIds.map((id) => {
                  const g = groups.find((grp) => grp.id === id);
                  return { id, label: g?.name ?? `Group ${id}` };
                })}
                onChange={(value: MultiSelectOption[]) =>
                  setEditingUser({
                    ...editingUser,
                    groupIds: value.map((v) => Number(v.id)),
                  })
                }
                placeholder={tr("common.assignGroups")}
                noOptionsText="No groups found"
              />
              <button type="submit" className="hidden" aria-hidden="true" />
            </form>
          </Modal>
        );
      })()}

      {/* ── Create Group modal ────────────────────────────────────── */}
      {(() => {
        const submit = async () => {
          if (!newGroup) return;
          setSavingDrawer(true);
          setError(null);
          try {
            await handleCreateGroup();
            setShowCreateGroup(false);
          } catch (err) {
            setError((err as Error).message || 'Create failed.');
          } finally {
            setSavingDrawer(false);
          }
        };
        return (
          <Modal
            open={showCreateGroup}
            onClose={() => setShowCreateGroup(false)}
            title={tr('admin.newGroup')}
            size="sm"
            footer={
              <>
                <Button variant="outline" size="sm" onClick={() => setShowCreateGroup(false)}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  disabled={savingDrawer || !newGroup}
                  onClick={submit}
                >
                  {savingDrawer ? 'Creating…' : 'Create group'}
                </Button>
              </>
            }
          >
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void submit();
              }}
            >
              <Input
                label={tr('common.groupName')}
                value={newGroup}
                onChange={(e) => setNewGroup(e.target.value)}
                autoFocus
              />
              <button type="submit" className="hidden" aria-hidden="true" />
            </form>
          </Modal>
        );
      })()}

      {/* ── Edit Group modal ──────────────────────────────────────── */}
      {editingGroup && (() => {
        const submit = async () => {
          if (!editingGroup) return;
          setSavingDrawer(true);
          setError(null);
          try {
            await updateGroup(editingGroup.id, editingGroup.name);
            await setGroupRoles(editingGroup.id, editingGroup.roleIds);
            await refresh();
            setEditingGroup(null);
          } catch (err) {
            setError((err as Error).message || 'Save failed.');
          } finally {
            setSavingDrawer(false);
          }
        };
        return (
          <Modal
            open={editingGroup !== null}
            onClose={() => setEditingGroup(null)}
            title={`Edit · ${editingGroup.name}`}
            size="md"
            footer={
              <>
                <Button variant="outline" size="sm" onClick={() => setEditingGroup(null)}>
                  Cancel
                </Button>
                <Button variant="primary" size="sm" disabled={savingDrawer} onClick={submit}>
                  {savingDrawer ? tr('yamlEditor.saving') : tr('actions.save')}
                </Button>
              </>
            }
          >
            <form
              className="flex flex-col gap-4"
              onSubmit={(e) => {
                e.preventDefault();
                void submit();
              }}
            >
              <Input
                label={tr("common.name")}
                value={editingGroup.name}
                onChange={(e) => setEditingGroup({ ...editingGroup, name: e.target.value })}
                autoFocus
              />
              <MultiSelect
                label={tr('admin.tabs.roles')}
                options={roles.map((r) => ({ id: r.id, label: r.name }))}
                value={editingGroup.roleIds.map((id) => {
                  const r = roles.find((rr) => rr.id === id);
                  return { id, label: r?.name ?? `Role ${id}` };
                })}
                onChange={(value: MultiSelectOption[]) =>
                  setEditingGroup({
                    ...editingGroup,
                    roleIds: value.map((v) => Number(v.id)),
                  })
                }
                placeholder="Assign roles…"
                noOptionsText="No roles found"
              />
              <button type="submit" className="hidden" aria-hidden="true" />
            </form>
          </Modal>
        );
      })()}

      {/* ── Create Role modal ─────────────────────────────────────── */}
      {(() => {
        const submit = async () => {
          if (!newRole.name) return;
          setSavingDrawer(true);
          setError(null);
          try {
            await handleCreateRole();
            setShowCreateRole(false);
          } catch (err) {
            setError((err as Error).message || 'Create failed.');
          } finally {
            setSavingDrawer(false);
          }
        };
        return (
          <Modal
            open={showCreateRole}
            onClose={() => setShowCreateRole(false)}
            title={tr('admin.newRole')}
            size="sm"
            footer={
              <>
                <Button variant="outline" size="sm" onClick={() => setShowCreateRole(false)}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  disabled={savingDrawer || !newRole.name}
                  onClick={submit}
                >
                  {savingDrawer ? 'Creating…' : 'Create role'}
                </Button>
              </>
            }
          >
            <form
              className="flex flex-col gap-4"
              onSubmit={(e) => {
                e.preventDefault();
                void submit();
              }}
            >
              <Input
                label={tr("common.name")}
                value={newRole.name}
                onChange={(e) => setNewRole({ ...newRole, name: e.target.value })}
                autoFocus
              />
              <Input
                label={tr("common.description")}
                value={newRole.description}
                onChange={(e) => setNewRole({ ...newRole, description: e.target.value })}
              />
              <button type="submit" className="hidden" aria-hidden="true" />
            </form>
          </Modal>
        );
      })()}

      {/* ── Edit Role modal ───────────────────────────────────────── */}
      {editingRole && (() => {
        const submit = async () => {
          if (!editingRole) return;
          setSavingDrawer(true);
          setError(null);
          try {
            await updateRole(editingRole.id, {
              name: editingRole.name,
              description: editingRole.description,
            });
            await refresh();
            setEditingRole(null);
          } catch (err) {
            setError((err as Error).message || 'Save failed.');
          } finally {
            setSavingDrawer(false);
          }
        };
        return (
          <Modal
            open={editingRole !== null}
            onClose={() => setEditingRole(null)}
            title={`Edit · ${editingRole.name}`}
            size="sm"
            footer={
              <>
                <Button variant="outline" size="sm" onClick={() => setEditingRole(null)}>
                  Cancel
                </Button>
                <Button variant="primary" size="sm" disabled={savingDrawer} onClick={submit}>
                  {savingDrawer ? tr('yamlEditor.saving') : tr('actions.save')}
                </Button>
              </>
            }
          >
            <form
              className="flex flex-col gap-4"
              onSubmit={(e) => {
                e.preventDefault();
                void submit();
              }}
            >
              <Input
                label={tr("common.name")}
                value={editingRole.name}
                onChange={(e) => setEditingRole({ ...editingRole, name: e.target.value })}
                autoFocus
              />
              <Input
                label={tr("common.description")}
                value={editingRole.description}
                onChange={(e) => setEditingRole({ ...editingRole, description: e.target.value })}
              />
              <button type="submit" className="hidden" aria-hidden="true" />
            </form>
          </Modal>
        );
      })()}
    </Layout>
  );
};

export default AdminPage;
