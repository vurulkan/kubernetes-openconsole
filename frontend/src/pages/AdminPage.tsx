import React, { useEffect, useState } from 'react';
import {
  Alert,
  Autocomplete,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  Divider,
  FormControl,
  FormControlLabel,
  InputLabel,
  MenuItem,
  Select,
  Tab,
  Tabs,
  TextField,
  Typography
} from '@mui/material';
import Layout from '../components/Layout';
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
  updateLDAP,
  testLdapConnection,
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
  NamespacePermission
} from '../services/api';
import { useNavigate } from 'react-router-dom';

const AdminPage: React.FC<{ user: User }> = ({ user }) => {
  const navigate = useNavigate();
  const [tab, setTab] = useState(() => localStorage.getItem('adminActiveTab') || 'users');
  const [error, setError] = useState<string | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [groups, setGroups] = useState<Array<{ id: number; name: string }>>([]);
  const [roles, setRoles] = useState<Array<{ id: number; name: string; description: string }>>([]);
  const [userGroups, setUserGroupsState] = useState<Record<number, Array<{ id: number; name: string }>>>({});
  const [groupRoles, setGroupRolesState] = useState<Record<number, Array<{ id: number; name: string }>>>({});
  const [namespaceOptions, setNamespaceOptions] = useState<string[]>([]);
  const [apiReachable, setApiReachable] = useState(true);
  const [authTokenPresent, setAuthTokenPresent] = useState(hasToken());
  const [selectedRoleId, setSelectedRoleId] = useState<number | null>(null);
  const [rolePermissions, setRolePermissions] = useState<NamespacePermission[]>([]);
  const [newPermissionNamespace, setNewPermissionNamespace] = useState('');
  const [permissionMatrix, setPermissionMatrix] = useState({
    pods: { list: true, get: true, logs: false },
    deployments: { list: true, get: true },
    services: { list: true, get: true },
    configmaps: { list: true, get: true }
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
    userBaseDns: [],
    userFilter: '',
    usernameAttribute: 'sAMAccountName'
  });
  const [ldapSearchQuery, setLdapSearchQuery] = useState('');
  const [ldapSearchResults, setLdapSearchResults] = useState<Array<{ username: string; dn: string }>>([]);
  const [ldapSelectedUsers, setLdapSelectedUsers] = useState<string[]>([]);
  const [ldapSearchLoading, setLdapSearchLoading] = useState(false);
  const [ldapTestStatus, setLdapTestStatus] = useState<{ status: 'success' | 'error'; message: string } | null>(null);
  const [ldapSearchError, setLdapSearchError] = useState<string | null>(null);
  const [ldapUpdatePassword, setLdapUpdatePassword] = useState(false);
  const [sessionMinutes, setSessionMinutes] = useState(60);
  const [cluster, setCluster] = useState({ method: '', server: '', active: false, ready: false, lastError: '' });
  const [auditLogs, setAuditLogs] = useState<Array<Record<string, unknown>>>([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditOffset, setAuditOffset] = useState(0);
  const [auditUserFilter, setAuditUserFilter] = useState('');
  const [auditActionFilter, setAuditActionFilter] = useState('');
  const [auditNamespaceFilter, setAuditNamespaceFilter] = useState('');
  const [auditStartDate, setAuditStartDate] = useState('');
  const [auditEndDate, setAuditEndDate] = useState('');
  const [clusterValidation, setClusterValidation] = useState<{ status: 'success' | 'error'; message: string } | null>(null);
  const [kubeconfigFileName, setKubeconfigFileName] = useState('');
  const [caCertFileName, setCaCertFileName] = useState('');
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
          requestId: ''
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
      requestId: ''
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
    caCertBase64: ''
  });

  useEffect(() => {
    if (!user.isAdmin) {
      navigate('/');
    }
  }, [user, navigate]);

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

  const refresh = async () => {
    setError(null);
    const results = await Promise.allSettled([
      listUsers(),
      listGroups(),
      listRoles(),
      getLDAP(),
      getSession(),
      getCluster(),
      listAuditLogs(50, auditOffset, auditUserFilter, auditActionFilter, auditNamespaceFilter, auditStartDate, auditEndDate),
      listNamespaces()
    ]);

    const [
      usersResult,
      groupsResult,
      rolesResult,
      ldapResult,
      sessionResult,
      clusterResult,
      auditResult,
      namespaceResult
    ] = results;

    const usersItems = usersResult.status === 'fulfilled' ? (usersResult.value.items ?? []) : [];
    const groupsItems = groupsResult.status === 'fulfilled' ? (groupsResult.value.items ?? []) : [];
    const rolesItems = rolesResult.status === 'fulfilled' ? (rolesResult.value.items ?? []) : [];

    if (usersResult.status === 'fulfilled') {
      setUsers(usersItems);
    }
    if (groupsResult.status === 'fulfilled') {
      setGroups(groupsItems);
    }
    if (rolesResult.status === 'fulfilled') {
      setRoles(rolesItems);
      setSelectedRoleId((prev) => prev ?? rolesItems?.[0]?.id ?? null);
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
        passwordConfigured: ldapResult.value.passwordConfigured ?? false
      });
      setLdapUpdatePassword(false);
    }
    if (sessionResult.status === 'fulfilled') {
      setSessionMinutes(sessionResult.value.sessionMinutes);
    }
    if (clusterResult.status === 'fulfilled') {
      setCluster(clusterResult.value);
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
      (result) => result.status === 'rejected'
    );
    if (failedCritical) {
      setError('Unable to load admin data.');
    }

    if (usersResult.status === 'fulfilled' && groupsResult.status === 'fulfilled') {
      const groupMap = new Map(groupsItems.map((group) => [group.id, group.name]));
      const selections = await Promise.all(
        usersItems.map(async (user) => {
          try {
            const result = await getUserGroups(user.id);
            const selected = (result.groupIds ?? []).map((id) => ({ id, name: groupMap.get(id) ?? `Group ${id}` }));
            return [user.id, selected] as const;
          } catch (err) {
            return [user.id, []] as const;
          }
        })
      );
      setUserGroupsState(Object.fromEntries(selections));
    }

    if (groupsResult.status === 'fulfilled' && rolesResult.status === 'fulfilled') {
      const roleMap = new Map(rolesItems.map((role) => [role.id, role.name]));
      const selections = await Promise.all(
        groupsItems.map(async (group) => {
          try {
            const result = await getGroupRoles(group.id);
            const selected = (result.roleIds ?? []).map((id) => ({ id, name: roleMap.get(id) ?? `Role ${id}` }));
            return [group.id, selected] as const;
          } catch (err) {
            return [group.id, []] as const;
          }
        })
      );
      setGroupRolesState(Object.fromEntries(selections));
    }
  };

  useEffect(() => {
    void refresh();
  }, [auditOffset, auditUserFilter, auditActionFilter, auditNamespaceFilter, auditStartDate, auditEndDate]);

  const handleCreateUser = async () => {
    if (!newUser.username || !newUser.password) {
      return;
    }
    await createUser(newUser);
    setNewUser({ username: '', password: '', isAdmin: false });
    await refresh();
  };

  const handleCreateGroup = async () => {
    if (!newGroup) {
      return;
    }
    await createGroup(newGroup);
    setNewGroup('');
    await refresh();
  };

  const handleCreateRole = async () => {
    if (!newRole.name) {
      return;
    }
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
    if (Number.isNaN(roleId)) {
      return;
    }
    setSelectedRoleId(roleId);
    try {
      const result = await listRolePermissions(roleId);
      setRolePermissions(result.items ?? []);
    } catch (err) {
      setRolePermissions([]);
    }
  };

  const handleAddPermission = async () => {
    if (!selectedRoleId || !newPermissionNamespace) {
      return;
    }
    const existing = new Set(
      rolePermissions.map((perm) => `${perm.namespace}:${perm.resource}:${perm.action}`)
    );
    const requests: Array<{ resource: string; action: string }> = [];
    Object.entries(permissionMatrix).forEach(([resource, actions]) => {
      Object.entries(actions).forEach(([action, enabled]) => {
        if (enabled) {
          requests.push({ resource, action });
        }
      });
    });
    for (const item of requests) {
      const key = `${newPermissionNamespace}:${item.resource}:${item.action}`;
      if (existing.has(key)) {
        continue;
      }
      await addRolePermission(selectedRoleId, {
        namespace: newPermissionNamespace,
        resource: item.resource,
        action: item.action
      });
    }
    await handleLoadRolePermissions(selectedRoleId);
    setNewPermissionNamespace('');
    setPermissionMatrix({
      pods: { list: true, get: true, logs: false },
      deployments: { list: true, get: true },
      services: { list: true, get: true },
      configmaps: { list: true, get: true }
    });
  };

  const handleFileUpload = (file: File | null, key: 'kubeconfigBase64' | 'caCertBase64') => {
    if (!file) {
      setClusterConfig({ ...clusterConfig, [key]: '' });
      if (key === 'kubeconfigBase64') {
        setKubeconfigFileName('');
      } else {
        setCaCertFileName('');
      }
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result?.toString() ?? '';
      const base64 = result.includes(',') ? result.split(',')[1] : result;
      setClusterConfig({ ...clusterConfig, [key]: base64 });
      if (key === 'kubeconfigBase64') {
        setKubeconfigFileName(file.name);
      } else {
        setCaCertFileName(file.name);
      }
    };
    reader.readAsDataURL(file);
  };

  const handleSaveLDAP = async () => {
    await updateLDAP({
      ...ldapConfig,
      bindPassword: ldapUpdatePassword || !(ldapConfig.passwordConfigured ?? false) ? ldapConfig.bindPassword : '',
      passwordConfigured: ldapConfig.passwordConfigured ?? false
    });
    await refresh();
  };

  const handleTestLDAP = async () => {
    setLdapTestStatus(null);
    try {
      await testLdapConnection();
      setLdapTestStatus({ status: 'success', message: 'LDAP connection successful.' });
    } catch (err) {
      setLdapTestStatus({ status: 'error', message: (err as Error).message || 'LDAP test failed.' });
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
    if (ldapSelectedUsers.length === 0) {
      return;
    }
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
    if (clusterConfig.method === 'kubeconfig') {
      return clusterConfig.kubeconfigBase64.length > 0;
    }
    if (clusterConfig.method === 'token') {
      return clusterConfig.token.length > 0 && clusterConfig.server.length > 0;
    }
    return false;
  };

  const handleSaveCluster = async () => {
    setClusterValidation(null);
    if (!isClusterConfigValid()) {
      setClusterValidation({ status: 'error', message: 'Please provide required cluster details before applying.' });
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
      requestId
    };
    setLastAppliedCluster(pending);
    const timeout = setTimeout(() => {
      setLastAppliedCluster((prev) => {
        if (prev.requestId !== requestId || prev.status === 'applied') {
          return prev;
        }
        return { ...prev, status: 'failed', error: 'Request timed out. No response from server.' };
      });
    }, 15000);
    try {
      const result = await updateCluster(clusterConfig);
      if (result.status === 'starting') {
        setClusterValidation({ status: 'success', message: 'Connection syncing in background. Check Ready status shortly.' });
      }
      setLastAppliedCluster((prev) => ({
        ...prev,
        status: 'applied',
        error: ''
      }));
      if (typeof result.active === 'boolean' || typeof result.ready === 'boolean' || result.lastError) {
        setCluster((prev) => ({
          ...prev,
          active: result.active ?? prev.active,
          ready: result.ready ?? prev.ready,
          lastError: result.lastError ?? prev.lastError
        }));
      }
      await refresh();
    } catch (err) {
      const message = (err as Error).message || 'Failed to apply cluster configuration.';
      setClusterValidation({ status: 'error', message: (err as Error).message || 'Failed to apply cluster configuration.' });
      setLastAppliedCluster((prev) => ({
        ...prev,
        status: 'failed',
        error: message
      }));
    } finally {
      clearTimeout(timeout);
    }
  };

  const handleValidateCluster = async () => {
    setClusterValidation(null);
    if (!isClusterConfigValid()) {
      setClusterValidation({ status: 'error', message: 'Please provide required cluster details before validating.' });
      return;
    }
    try {
      await validateCluster(clusterConfig);
      setClusterValidation({ status: 'success', message: 'Kubeconfig validated successfully.' });
    } catch (err) {
      setClusterValidation({ status: 'error', message: (err as Error).message || 'Validation failed.' });
    }
  };

  return (
    <Layout user={user} namespaces={[]} activeNamespace={null} onNamespaceChange={() => undefined}>
      <Typography variant="h5" fontWeight={600} gutterBottom>
        Admin Control Center
      </Typography>
      <Typography variant="body2" color="text.secondary" gutterBottom>
        Manage users, roles, LDAP, sessions, and cluster connections entirely from the UI.
      </Typography>
      {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}

      <Card sx={{ mt: 3, boxShadow: 2 }}>
        <CardContent>
          <Tabs value={tab} onChange={(_, value) => setTab(value)}>
            <Tab label="Users" value="users" />
            <Tab label="Groups" value="groups" />
            <Tab label="Roles" value="roles" />
            <Tab label="LDAP" value="ldap" />
            <Tab label="Session" value="session" />
            <Tab label="Cluster" value="cluster" />
            <Tab label="Audit Logs" value="audit" />
          </Tabs>
          <Divider sx={{ my: 2 }} />

          {tab === 'users' && (
            <Box display="grid" gap={3}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight={600} gutterBottom>Create User</Typography>
                  <Box display="grid" gap={2} gridTemplateColumns="repeat(auto-fit, minmax(220px, 1fr))">
                    <TextField label="Username" value={newUser.username} onChange={(e) => setNewUser({ ...newUser, username: e.target.value })} />
                    <TextField label="Password" type="password" value={newUser.password} onChange={(e) => setNewUser({ ...newUser, password: e.target.value })} />
                    <FormControlLabel
                      control={<Checkbox checked={newUser.isAdmin} onChange={(e) => setNewUser({ ...newUser, isAdmin: e.target.checked })} />}
                      label="Admin"
                    />
                  </Box>
                  <Box mt={2}>
                    <Button variant="contained" onClick={handleCreateUser}>Create User</Button>
                  </Box>
                </CardContent>
              </Card>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight={600} gutterBottom>Existing Users</Typography>
                  <Box display="grid" gap={2}>
                    {users.map((u) => (
                      <Box key={u.id} display="grid" gap={1} gridTemplateColumns="repeat(auto-fit, minmax(200px, 1fr))">
                        <TextField label="Username" value={u.username} onChange={(e) => setUsers(users.map((item) => item.id === u.id ? { ...item, username: e.target.value } : item))} />
                        <FormControlLabel
                          control={<Checkbox checked={u.isActive} onChange={(e) => setUsers(users.map((item) => item.id === u.id ? { ...item, isActive: e.target.checked } : item))} />}
                          label="Active"
                        />
                        <FormControlLabel
                          control={<Checkbox checked={u.isAdmin} onChange={(e) => setUsers(users.map((item) => item.id === u.id ? { ...item, isAdmin: e.target.checked } : item))} />}
                          label="Admin"
                        />
                        <Button variant="outlined" onClick={() => updateUser(u.id, { username: u.username, isActive: u.isActive, isAdmin: u.isAdmin })}>Save</Button>
                        <Autocomplete
                          multiple
                          options={groups}
                          getOptionLabel={(option) => option.name}
                          value={userGroups[u.id] ?? []}
                          onChange={(_, value) => setUserGroupsState({ ...userGroups, [u.id]: value })}
                          noOptionsText="No groups found"
                          renderInput={(params) => <TextField {...params} label="Groups" />}
                        />
                        <Button variant="outlined" onClick={() => handleSaveUserGroups(u.id)}>
                          Save Groups
                        </Button>
                        <Button variant="text" color="error" onClick={async () => { await deleteUser(u.id); await refresh(); }}>
                          Delete User
                        </Button>
                      </Box>
                    ))}
                  </Box>
                </CardContent>
              </Card>
            </Box>
          )}

          {tab === 'groups' && (
            <Box display="grid" gap={3}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight={600} gutterBottom>Create Group</Typography>
                  <Box display="flex" gap={2}>
                    <TextField label="Group Name" value={newGroup} onChange={(e) => setNewGroup(e.target.value)} />
                    <Button variant="contained" onClick={handleCreateGroup}>Create</Button>
                  </Box>
                </CardContent>
              </Card>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight={600} gutterBottom>Existing Groups</Typography>
                  <Box display="grid" gap={2}>
                    {groups.map((group) => (
                      <Box key={group.id} display="grid" gap={2} gridTemplateColumns="repeat(auto-fit, minmax(200px, 1fr))">
                        <TextField label="Name" value={group.name} onChange={(e) => setGroups(groups.map((g) => g.id === group.id ? { ...g, name: e.target.value } : g))} />
                        <Button variant="outlined" onClick={() => updateGroup(group.id, group.name)}>Save</Button>
                        <Autocomplete
                          multiple
                          options={roles}
                          getOptionLabel={(option) => option.name}
                          value={groupRoles[group.id] ?? []}
                          onChange={(_, value) => setGroupRolesState({ ...groupRoles, [group.id]: value })}
                          noOptionsText="No roles found"
                          renderInput={(params) => <TextField {...params} label="Roles" />}
                        />
                        <Button variant="outlined" onClick={() => handleSaveGroupRoles(group.id)}>
                          Save Roles
                        </Button>
                        <Button variant="text" color="error" onClick={async () => { await deleteGroup(group.id); await refresh(); }}>
                          Delete Group
                        </Button>
                      </Box>
                    ))}
                  </Box>
                </CardContent>
              </Card>
            </Box>
          )}

          {tab === 'roles' && (
            <Box display="grid" gap={3}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight={600} gutterBottom>Create Role</Typography>
                  <Box display="grid" gap={2} gridTemplateColumns="repeat(auto-fit, minmax(220px, 1fr))">
                    <TextField label="Name" value={newRole.name} onChange={(e) => setNewRole({ ...newRole, name: e.target.value })} />
                    <TextField label="Description" value={newRole.description} onChange={(e) => setNewRole({ ...newRole, description: e.target.value })} />
                  </Box>
                  <Box mt={2}>
                    <Button variant="contained" onClick={handleCreateRole}>Create Role</Button>
                  </Box>
                </CardContent>
              </Card>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight={600} gutterBottom>Existing Roles</Typography>
                  <Box display="grid" gap={2}>
                    {roles.map((role) => (
                      <Box key={role.id} display="grid" gap={2} gridTemplateColumns="repeat(auto-fit, minmax(220px, 1fr))">
                        <TextField label="Name" value={role.name} onChange={(e) => setRoles(roles.map((r) => r.id === role.id ? { ...r, name: e.target.value } : r))} />
                        <TextField label="Description" value={role.description} onChange={(e) => setRoles(roles.map((r) => r.id === role.id ? { ...r, description: e.target.value } : r))} />
                        <Button variant="outlined" onClick={() => updateRole(role.id, { name: role.name, description: role.description })}>Save</Button>
                        <Button variant="text" color="error" onClick={async () => { await deleteRole(role.id); await refresh(); }}>
                          Delete Role
                        </Button>
                      </Box>
                    ))}
                  </Box>
                </CardContent>
              </Card>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight={600} gutterBottom>Role Permissions</Typography>
                  <Box display="grid" gap={2} gridTemplateColumns="repeat(auto-fit, minmax(220px, 1fr))">
                    <Autocomplete
                      options={roles}
                      getOptionLabel={(option) => option.name}
                      value={roles.find((role) => role.id === selectedRoleId) ?? null}
                      onChange={(_, value) => handleLoadRolePermissions(value?.id ?? Number.NaN)}
                      noOptionsText="No roles found"
                      renderInput={(params) => <TextField {...params} label="Role" />}
                    />
                    <Autocomplete
                      freeSolo
                      options={namespaceOptions}
                      value={newPermissionNamespace}
                      onInputChange={(_, value) => setNewPermissionNamespace(value)}
                      renderInput={(params) => <TextField {...params} label="Namespace" />}
                    />
                  </Box>
                  <Box mt={2} display="grid" gap={2} gridTemplateColumns="repeat(auto-fit, minmax(220px, 1fr))">
                    {Object.entries(permissionMatrix).map(([resource, actions]) => (
                      <Box key={resource} sx={{ p: 2, borderRadius: 2, border: '1px solid #e0e5f2' }}>
                        <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                          {resource.toUpperCase()}
                        </Typography>
                        {Object.entries(actions).map(([action, enabled]) => (
                          <FormControlLabel
                            key={action}
                            control={
                              <Checkbox
                                checked={enabled}
                                onChange={(e) =>
                                  setPermissionMatrix({
                                    ...permissionMatrix,
                                    [resource]: { ...actions, [action]: e.target.checked }
                                  })
                                }
                              />
                            }
                            label={action.toUpperCase()}
                          />
                        ))}
                      </Box>
                    ))}
                  </Box>
                  <Box mt={2}>
                    <Button variant="contained" onClick={handleAddPermission}>Add Selected Permissions</Button>
                  </Box>
                  <Box mt={2} display="grid" gap={1}>
                    {rolePermissions.map((perm) => (
                      <Box key={perm.id} display="flex" gap={2} alignItems="center">
                        <Typography variant="body2">
                          {perm.namespace} - {perm.resource}:{perm.action}
                        </Typography>
                        <Button variant="text" color="error" onClick={async () => { await deletePermission(perm.id); if (selectedRoleId) { await handleLoadRolePermissions(selectedRoleId); } }}>
                          Remove
                        </Button>
                      </Box>
                    ))}
                  </Box>
                </CardContent>
              </Card>
            </Box>
          )}

          {tab === 'ldap' && (
            <Card variant="outlined">
              <CardContent>
                <Typography variant="subtitle1" fontWeight={600} gutterBottom>LDAP Configuration</Typography>
                <Box display="grid" gap={2} gridTemplateColumns="repeat(auto-fit, minmax(240px, 1fr))">
                  <FormControlLabel
                    control={<Checkbox checked={ldapConfig.enabled} onChange={(e) => setLdapConfig({ ...ldapConfig, enabled: e.target.checked })} />}
                    label="Enabled"
                  />
                  <TextField label="Host" value={ldapConfig.host} onChange={(e) => setLdapConfig({ ...ldapConfig, host: e.target.value })} />
                  <TextField label="Port" type="number" value={ldapConfig.port} onChange={(e) => setLdapConfig({ ...ldapConfig, port: Number(e.target.value) })} />
                  <FormControlLabel
                    control={<Checkbox checked={ldapConfig.useSsl} onChange={(e) => setLdapConfig({ ...ldapConfig, useSsl: e.target.checked })} />}
                    label="Use SSL"
                  />
                  <FormControlLabel
                    control={<Checkbox checked={ldapConfig.startTls} onChange={(e) => setLdapConfig({ ...ldapConfig, startTls: e.target.checked })} />}
                    label="StartTLS"
                  />
                  <FormControlLabel
                    control={<Checkbox checked={ldapConfig.sslSkipVerify} onChange={(e) => setLdapConfig({ ...ldapConfig, sslSkipVerify: e.target.checked })} />}
                    label="Skip Verify"
                  />
                  <TextField label="Timeout (seconds)" type="number" value={ldapConfig.timeoutSeconds} onChange={(e) => setLdapConfig({ ...ldapConfig, timeoutSeconds: Number(e.target.value) })} />
                  <TextField label="Bind DN" value={ldapConfig.bindDn} onChange={(e) => setLdapConfig({ ...ldapConfig, bindDn: e.target.value })} />
                  <FormControlLabel
                    control={<Checkbox checked={ldapUpdatePassword} onChange={(e) => setLdapUpdatePassword(e.target.checked)} />}
                    label="Update Bind Password"
                  />
                  <TextField
                    label="Bind Password"
                    type="password"
                    disabled={!ldapUpdatePassword && (ldapConfig.passwordConfigured ?? false)}
                    value={
                      !ldapUpdatePassword && (ldapConfig.passwordConfigured ?? false)
                        ? 'Configured'
                        : ldapConfig.bindPassword
                    }
                    onChange={(e) => setLdapConfig({ ...ldapConfig, bindPassword: e.target.value })}
                  />
                  <TextField label="User Base DN (single)" value={ldapConfig.userBaseDn} onChange={(e) => setLdapConfig({ ...ldapConfig, userBaseDn: e.target.value })} />
                  <TextField
                    label="User Base DNs (comma separated)"
                    value={ldapConfig.userBaseDns.join(',')}
                    onChange={(e) => setLdapConfig({ ...ldapConfig, userBaseDns: e.target.value.split(',').map((value) => value.trim()).filter(Boolean) })}
                  />
                  <TextField label="User Filter" value={ldapConfig.userFilter} onChange={(e) => setLdapConfig({ ...ldapConfig, userFilter: e.target.value })} />
                  <TextField label="Username Attribute" value={ldapConfig.usernameAttribute} onChange={(e) => setLdapConfig({ ...ldapConfig, usernameAttribute: e.target.value })} />
                </Box>
                <Box mt={2} display="flex" gap={2}>
                  <Button variant="contained" onClick={handleSaveLDAP}>Save LDAP Settings</Button>
                  <Button variant="outlined" onClick={handleTestLDAP}>Test Connection</Button>
                </Box>
                {ldapTestStatus && (
                  <Alert severity={ldapTestStatus.status} sx={{ mt: 2 }}>
                    {ldapTestStatus.message}
                  </Alert>
                )}
                <Divider sx={{ my: 3 }} />
                <Typography variant="subtitle1" fontWeight={600} gutterBottom>Import LDAP Users</Typography>
                <Box display="grid" gap={2} gridTemplateColumns="repeat(auto-fit, minmax(240px, 1fr))">
                  <TextField label="Search Query" value={ldapSearchQuery} onChange={(e) => setLdapSearchQuery(e.target.value)} />
                  <Button variant="outlined" onClick={handleLdapSearch} disabled={ldapSearchLoading}>
                    {ldapSearchLoading ? 'Searching...' : 'Search'}
                  </Button>
                </Box>
                <Box mt={2}>
                  <Autocomplete
                    multiple
                    options={ldapSearchResults}
                    getOptionLabel={(option) => `${option.username} (${option.dn})`}
                    value={ldapSearchResults.filter((item) => ldapSelectedUsers.includes(item.username))}
                    onChange={(_, value) => setLdapSelectedUsers(value.map((item) => item.username))}
                    noOptionsText="No LDAP users found"
                    renderInput={(params) => <TextField {...params} label="LDAP Users" />}
                  />
                </Box>
                {ldapSearchError && (
                  <Alert severity="error" sx={{ mt: 2 }}>
                    {ldapSearchError}
                  </Alert>
                )}
                <Box mt={2}>
                  <Button variant="contained" onClick={handleLdapImport} disabled={ldapSelectedUsers.length === 0}>
                    Import Selected Users
                  </Button>
                </Box>
              </CardContent>
            </Card>
          )}

          {tab === 'session' && (
            <Card variant="outlined">
              <CardContent>
                <Typography variant="subtitle1" fontWeight={600} gutterBottom>Session Settings</Typography>
                <TextField label="Session Lifetime (minutes)" value={sessionMinutes} onChange={(e) => setSessionMinutes(Number(e.target.value))} />
                <Box mt={2}>
                  <Button variant="contained" onClick={handleSaveSession}>Save Session</Button>
                </Box>
              </CardContent>
            </Card>
          )}

          {tab === 'cluster' && (
            <Card variant="outlined">
              <CardContent>
                <Typography variant="subtitle1" fontWeight={600} gutterBottom>Cluster Connection</Typography>
                <Typography variant="body2" color="text.secondary">
                  Active: {cluster.active ? 'Yes' : 'No'} | Ready: {cluster.ready ? 'Yes' : 'No'} | Method: {cluster.method || 'Not set'}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Auth Token: {authTokenPresent ? 'Present' : 'Missing'}
                </Typography>
                {!apiReachable && (
                  <Alert severity="error" sx={{ mt: 2 }}>
                    Backend is not reachable from the browser. Check that `http://localhost:8080/healthz` responds.
                  </Alert>
                )}
                {cluster.server && (
                  <Typography variant="body2" color="text.secondary">API Server: {cluster.server}</Typography>
                )}
                {cluster.lastError && (
                  <Alert severity="warning" sx={{ mt: 2 }}>{cluster.lastError}</Alert>
                )}
                <Box mt={2} sx={{ p: 2, borderRadius: 2, border: '1px solid #e0e5f2', background: '#fff' }}>
                  <Typography variant="subtitle2" fontWeight={600} gutterBottom>Last Applied Cluster</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Status: {lastAppliedCluster.status || 'N/A'}
                  </Typography>
                  {lastAppliedCluster.requestId && (
                    <Typography variant="caption" color="text.secondary">
                      Request ID: {lastAppliedCluster.requestId}
                    </Typography>
                  )}
                  <Typography variant="body2" color="text.secondary">
                    Method: {lastAppliedCluster.method || 'N/A'}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    API Server: {lastAppliedCluster.server || 'N/A'}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Kubeconfig File: {lastAppliedCluster.kubeconfigFileName || 'N/A'}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    CA Cert File: {lastAppliedCluster.caCertFileName || 'N/A'}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Applied At: {lastAppliedCluster.appliedAt || 'N/A'}
                  </Typography>
                  {lastAppliedCluster.error && (
                    <Alert severity="error" sx={{ mt: 1 }}>
                      {lastAppliedCluster.error}
                    </Alert>
                  )}
                </Box>
                {clusterValidation && (
                  <Alert severity={clusterValidation.status} sx={{ mt: 2 }}>{clusterValidation.message}</Alert>
                )}
                <Box mt={2} display="grid" gap={2} gridTemplateColumns="repeat(auto-fit, minmax(240px, 1fr))">
                  <FormControl fullWidth>
                    <InputLabel>Method</InputLabel>
                    <Select
                      label="Method"
                      value={clusterConfig.method}
                      onChange={(e) => {
                        const value = e.target.value;
                        if (value === 'kubeconfig') {
                          setClusterConfig({
                            method: value,
                            kubeconfigBase64: '',
                            token: '',
                            server: '',
                            caCertBase64: ''
                          });
                        } else {
                          setClusterConfig({
                            method: value,
                            kubeconfigBase64: '',
                            token: '',
                            server: '',
                            caCertBase64: ''
                          });
                        }
                      }}
                    >
                      <MenuItem value="kubeconfig">Kubeconfig</MenuItem>
                      <MenuItem value="token">ServiceAccount Token</MenuItem>
                    </Select>
                  </FormControl>
                  {clusterConfig.method === 'kubeconfig' && (
                  <Box display="flex" flexDirection="column" gap={1}>
                    <Button variant="outlined" component="label">
                      Upload kubeconfig
                      <input
                        type="file"
                        hidden
                        onChange={(e) => handleFileUpload(e.target.files?.[0] ?? null, 'kubeconfigBase64')}
                      />
                    </Button>
                    <Typography variant="caption" color="text.secondary">
                      {kubeconfigFileName ? `Loaded: ${kubeconfigFileName}` : 'No kubeconfig selected'}
                    </Typography>
                  </Box>
                  )}
                  {clusterConfig.method === 'token' && (
                    <>
                      <TextField label="Token" value={clusterConfig.token} onChange={(e) => setClusterConfig({ ...clusterConfig, token: e.target.value })} />
                      <TextField label="API Server" value={clusterConfig.server} onChange={(e) => setClusterConfig({ ...clusterConfig, server: e.target.value })} />
                    <Box display="flex" flexDirection="column" gap={1}>
                      <Button variant="outlined" component="label">
                        Upload CA Cert
                        <input
                          type="file"
                          hidden
                          onChange={(e) => handleFileUpload(e.target.files?.[0] ?? null, 'caCertBase64')}
                        />
                      </Button>
                      <Typography variant="caption" color="text.secondary">
                        {caCertFileName ? `Loaded: ${caCertFileName}` : 'No CA cert selected'}
                      </Typography>
                    </Box>
                    </>
                  )}
                </Box>
                <Box mt={2} display="flex" gap={2}>
                  <Button variant="outlined" onClick={handleValidateCluster} disabled={!isClusterConfigValid()}>
                    Validate
                  </Button>
                  <Button variant="contained" onClick={handleSaveCluster} disabled={!isClusterConfigValid()}>
                    Apply Cluster Connection
                  </Button>
                </Box>
              </CardContent>
            </Card>
          )}

          {tab === 'audit' && (
            <Card variant="outlined">
              <CardContent>
                <Typography variant="subtitle1" fontWeight={600} gutterBottom>Audit Logs</Typography>
                <Box display="flex" gap={2} alignItems="center" mb={2}>
                  <TextField
                    label="Search by user"
                    value={auditUserFilter}
                    onChange={(e) => {
                      setAuditOffset(0);
                      setAuditUserFilter(e.target.value);
                    }}
                  />
                  <TextField
                    label="Action"
                    value={auditActionFilter}
                    onChange={(e) => {
                      setAuditOffset(0);
                      setAuditActionFilter(e.target.value);
                    }}
                  />
                  <TextField
                    label="Namespace"
                    value={auditNamespaceFilter}
                    onChange={(e) => {
                      setAuditOffset(0);
                      setAuditNamespaceFilter(e.target.value);
                    }}
                  />
                  <TextField
                    label="Start date"
                    type="date"
                    value={auditStartDate}
                    onChange={(e) => {
                      setAuditOffset(0);
                      setAuditStartDate(e.target.value);
                    }}
                    InputLabelProps={{ shrink: true }}
                  />
                  <TextField
                    label="End date"
                    type="date"
                    value={auditEndDate}
                    onChange={(e) => {
                      setAuditOffset(0);
                      setAuditEndDate(e.target.value);
                    }}
                    InputLabelProps={{ shrink: true }}
                  />
                  <Typography variant="body2" color="text.secondary">
                    Showing {auditOffset + 1} - {Math.min(auditOffset + 50, auditTotal)} of {auditTotal}
                  </Typography>
                  <Button variant="outlined" onClick={handleAuditExport}>
                    Export CSV
                  </Button>
                </Box>
                <Box display="grid" gap={2}>
                  {auditLogs.map((entry, index) => (
                    <Box key={index} sx={{ p: 2, borderRadius: 2, border: '1px solid #e0e5f2', background: '#fff' }}>
                      <Typography variant="subtitle2" fontWeight={600}>
                        {(entry.user as string) ?? 'unknown'} - {(entry.action as string) ?? ''}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {(entry.timestampFormatted as string) ?? (entry.timestamp as string) ?? ''}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {(entry.namespace as string) ?? '-'} / {(entry.resourceType as string) ?? ''} / {(entry.resourceName as string) ?? ''}
                      </Typography>
                    </Box>
                  ))}
                </Box>
                <Box mt={2} display="flex" gap={2}>
                  <Button
                    variant="outlined"
                    disabled={auditOffset === 0}
                    onClick={() => setAuditOffset(Math.max(0, auditOffset - 50))}
                  >
                    Previous
                  </Button>
                  <Button
                    variant="outlined"
                    disabled={auditOffset + 50 >= auditTotal}
                    onClick={() => setAuditOffset(auditOffset + 50)}
                  >
                    Next
                  </Button>
                </Box>
              </CardContent>
            </Card>
          )}
        </CardContent>
      </Card>
    </Layout>
  );
};

export default AdminPage;
