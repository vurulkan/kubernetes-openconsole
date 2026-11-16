import React, { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { X } from 'lucide-react';
import { Alert, Badge, Button, Checkbox, MultiSelect, MultiSelectOption, NativeSelect } from '../../components/ui';
import {
  addRolePermission,
  deletePermission,
  listRolePermissions,
  type ClusterListItem,
  type NamespacePermission,
  type Role,
} from '../../services/api';

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

/** Admin → Roles, the classic Role Permissions layout (role picker, checkbox matrix, table). */
export const ClassicRolePermissions: React.FC<{
  roles: Role[];
  clusters: ClusterListItem[];
  namespaces: string[];
  onSwitchNew: () => void;
}> = ({ roles, clusters, namespaces, onSwitchNew }) => {
  const { t: tr } = useTranslation();
  const [selectedRoleId, setSelectedRoleId] = useState<number | null>(null);
  const [rolePermissions, setRolePermissions] = useState<NamespacePermission[]>([]);
  const [newPermissionNamespaces, setNewPermissionNamespaces] = useState<string[]>([]);
  // 0 means "all clusters" (wildcard).
  const [newPermissionClusterId, setNewPermissionClusterId] = useState<number>(0);
  const [permissionFormError, setPermissionFormError] = useState<string | null>(null);
  const [permissionMatrix, setPermissionMatrix] = useState(DEFAULT_PERMISSION_MATRIX);

  // A reloaded role list drops the selection.
  useEffect(() => {
    setSelectedRoleId(null);
    setRolePermissions([]);
  }, [roles]);

  const loadRolePermissions = async (roleId: number) => {
    if (Number.isNaN(roleId)) return;
    try {
      const result = await listRolePermissions(roleId);
      setRolePermissions(result.items ?? []);
    } catch {
      setRolePermissions([]);
    }
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

  // Group a role's permissions by (cluster, namespace) so admins can read the
  // matrix at a glance even when the same namespace exists on several clusters.
  const groupedPermissions = useMemo(() => {
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
      setPermissionFormError(tr('admin.roles.pickRoleFirst'));
      return;
    }
    const sanitizedNamespaces = newPermissionNamespaces.map((n) => n.trim()).filter((n) => n.length > 0);
    if (sanitizedNamespaces.length === 0) {
      setPermissionFormError(tr('admin.roles.enterNamespace'));
      return;
    }
    const anyChecked = Object.values(permissionMatrix).some((actions) => Object.values(actions).some(Boolean));
    if (!anyChecked) {
      setPermissionFormError(tr('admin.roles.pickAction'));
      return;
    }
    const existing = new Set(
      rolePermissions.map((perm) => `${perm.clusterId}:${perm.namespace}:${perm.resource}:${perm.action}`),
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

  return (
    <>
      <div className="mb-3 flex justify-end">
        <button
          type="button"
          onClick={onSwitchNew}
          className="text-[11px] font-medium text-slate-500 underline-offset-4 hover:text-brand-600 hover:underline dark:text-slate-400 dark:hover:text-brand-300"
        >
          {tr('admin.switchToNew')}
        </button>
      </div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <NativeSelect
          label={tr('common.role')}
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
          <option value="">{tr('admin.roles.selectRole')}</option>
          {roles.map((r) => (
            <option key={r.id} value={r.id}>
              {r.name}
            </option>
          ))}
        </NativeSelect>

        <NativeSelect
          label={tr('common.clusterScope')}
          value={newPermissionClusterId}
          onChange={(e) => setNewPermissionClusterId(Number(e.target.value))}
        >
          <option value={0}>{tr('common.allClusters')}</option>
          {clusters.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}
            </option>
          ))}
        </NativeSelect>

        <MultiSelect
          label={tr('common.namespaces')}
          options={[{ id: '*', label: '* (all namespaces)' }, ...namespaces.map((ns) => ({ id: ns, label: ns }))]}
          value={newPermissionNamespaces.map((ns) => ({
            id: ns,
            label: ns === '*' ? '* (all namespaces)' : ns,
          }))}
          onChange={(value: MultiSelectOption[]) => setNewPermissionNamespaces(value.map((v) => String(v.id)))}
          placeholder={tr('common.pickNsOrStar')}
          noOptionsText={namespaces.length === 0 ? tr('admin.roles.noNamespaces') : tr('admin.roles.noMatchingNamespace')}
        />
      </div>

      <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {Object.entries(permissionMatrix).map(([resource, actions]) => (
          <div key={resource} className="rounded-lg border border-slate-200 dark:border-slate-800 p-3">
            <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-700 dark:text-slate-200">{resource}</p>
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
      <Button variant="primary" size="sm" className="mt-4" onClick={handleAddPermission}>
        {tr('admin.roles.addSelected')}
      </Button>

      <div className="mt-4">
        {!selectedRoleId && <p className="text-sm text-slate-500 dark:text-slate-400">{tr('admin.roles.selectToView')}</p>}
        {selectedRoleId && groupedPermissions.length === 0 && (
          <p className="text-sm text-slate-500 dark:text-slate-400">{tr('admin.roles.noPermissions')}</p>
        )}
        {selectedRoleId && groupedPermissions.length > 0 && (
          <div className="overflow-auto rounded-lg border border-slate-200 dark:border-slate-800">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 dark:bg-slate-900">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-300">
                    {tr('admin.roles.colCluster')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-300">
                    {tr('admin.roles.colNamespace')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-slate-600 dark:text-slate-300">
                    {tr('admin.roles.colPermissions')}
                  </th>
                  <th className="px-4 py-3 text-right text-xs font-semibold text-slate-600 dark:text-slate-300">
                    {tr('admin.roles.colActions')}
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {groupedPermissions.map((group) => (
                  <tr key={`${group.clusterId}:${group.namespace}`}>
                    <td className="px-4 py-3">
                      {group.clusterId === 0 ? (
                        <Badge variant="info">{tr('common.allClusters')}</Badge>
                      ) : (
                        <span className="font-mono text-xs text-slate-700 dark:text-slate-200">
                          {group.clusterName || `#${group.clusterId}`}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 font-medium text-slate-900 dark:text-slate-100">{group.namespace}</td>
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
                        {tr('admin.roles.removeRow')}
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
};

export default ClassicRolePermissions;
