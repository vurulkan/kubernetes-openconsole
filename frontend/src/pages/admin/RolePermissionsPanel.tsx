import React, { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import {
  Copy,
  MoreHorizontal,
  Pencil,
  Plus,
  Search as SearchIcon,
  Trash2,
  X,
} from 'lucide-react';
import { createPortal } from 'react-dom';
import { Alert, Badge, Button, Checkbox, Input, Modal, NativeSelect } from '../../components/ui';
import { confirm } from '../../components/ConfirmDialog';
import {
  ClusterListItem,
  NamespacePermission,
  addRolePermission,
  deletePermission,
  listRolePermissions,
} from '../../services/api';

// ─── Catalog ────────────────────────────────────────────────────────────────
//
// The set of resource/action pairs that mean something on this backend. The
// admin bypass list in handleNamespacePermissions is the source of truth; keep
// these in sync (small list, hand-edited).

type ActionFamily = 'read' | 'write' | 'destructive';
type ActionDef = { key: string; family: ActionFamily };

// `edit` is destructive (full YAML write via server dry-run + apply). Scale /
// restart are "write" because they only change the obvious thing. logs/exec
// stay as read/destructive — exec can still mutate pod state via a shell.
const RESOURCE_CATALOG: Array<{ resource: string; actions: ActionDef[] }> = [
  { resource: 'pods', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
    { key: 'logs', family: 'read' },
    { key: 'exec', family: 'destructive' },
    { key: 'edit', family: 'destructive' },
  ]},
  { resource: 'deployments', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
    { key: 'restart', family: 'write' },
    { key: 'scale', family: 'write' },
    { key: 'edit', family: 'destructive' },
  ]},
  { resource: 'daemonsets', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
    { key: 'edit', family: 'destructive' },
  ]},
  { resource: 'statefulsets', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
    { key: 'scale', family: 'write' },
    { key: 'edit', family: 'destructive' },
  ]},
  { resource: 'hpas', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
    { key: 'edit', family: 'destructive' },
  ]},
  { resource: 'services', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
    { key: 'edit', family: 'destructive' },
  ]},
  { resource: 'configmaps', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
    { key: 'edit', family: 'destructive' },
  ]},
  { resource: 'ingresses', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
    { key: 'edit', family: 'destructive' },
  ]},
  { resource: 'cronjobs', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
    { key: 'edit', family: 'destructive' },
  ]},
  { resource: 'jobs', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
    { key: 'edit', family: 'destructive' },
  ]},
];

const FAMILY_CLASS: Record<ActionFamily, string> = {
  read:
    'bg-slate-100 text-slate-700 ring-1 ring-inset ring-slate-200 dark:bg-slate-800 dark:text-slate-200 dark:ring-slate-700',
  write:
    'bg-amber-50 text-amber-800 ring-1 ring-inset ring-amber-200 dark:bg-amber-500/15 dark:text-amber-200 dark:ring-amber-500/30',
  destructive:
    'bg-rose-50 text-rose-700 ring-1 ring-inset ring-rose-200 dark:bg-rose-500/15 dark:text-rose-200 dark:ring-rose-500/30',
};

// Templates seed the add-permissions modal. "Admin" selects everything; the
// rest are opinionated starting points that reflect common on-call shapes.
type Template = 'viewer' | 'developer' | 'sre' | 'admin';

const TEMPLATE_LABELS: Record<Template, string> = {
  viewer: 'Viewer (read-only)',
  developer: 'Developer (read + restart/scale)',
  sre: 'SRE (developer + pod exec)',
  admin: 'Admin (everything)',
};

function buildTemplateMatrix(template: Template): Record<string, Record<string, boolean>> {
  const out: Record<string, Record<string, boolean>> = {};
  for (const { resource, actions } of RESOURCE_CATALOG) {
    out[resource] = {};
    for (const a of actions) {
      let on = false;
      if (template === 'admin') on = true;
      else if (template === 'viewer') on = a.family === 'read' && a.key !== 'logs';
      else if (template === 'developer') {
        on = a.family === 'read' || (resource === 'deployments' && (a.key === 'restart' || a.key === 'scale'))
          || (resource === 'statefulsets' && a.key === 'scale');
      } else if (template === 'sre') {
        // SRE template now also grants edit on common workloads so YAML
        // adjustments (changing an env var, bumping a limit) are possible
        // without escalating to Admin.
        on = a.family === 'read'
          || (resource === 'deployments' && (a.key === 'restart' || a.key === 'scale' || a.key === 'edit'))
          || (resource === 'statefulsets' && (a.key === 'scale' || a.key === 'edit'))
          || (resource === 'configmaps' && a.key === 'edit')
          || (resource === 'pods' && a.key === 'exec');
      }
      out[resource][a.key] = on;
    }
  }
  return out;
}

const emptyMatrix = (): Record<string, Record<string, boolean>> =>
  Object.fromEntries(
    RESOURCE_CATALOG.map((r) => [r.resource, Object.fromEntries(r.actions.map((a) => [a.key, false]))])
  );

// ─── Props ──────────────────────────────────────────────────────────────────

type RoleRow = { id: number; name: string; description: string };

type Props = {
  roles: RoleRow[];
  clusters: ClusterListItem[];
  namespaces: string[];
  onError: (msg: string | null) => void;
  onSwitchClassic: () => void;
};

// ─── Component ──────────────────────────────────────────────────────────────

export const RolePermissionsPanel: React.FC<Props> = ({
  roles,
  clusters,
  namespaces,
  onError,
  onSwitchClassic,
}) => {
  const [roleSearch, setRoleSearch] = useState('');
  const [selectedRoleId, setSelectedRoleId] = useState<number | null>(() => roles[0]?.id ?? null);
  const [permissions, setPermissions] = useState<NamespacePermission[]>([]);
  const [loading, setLoading] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const [copyOpen, setCopyOpen] = useState(false);
  const [addSeed, setAddSeed] = useState<{
    clusterId: number;
    namespaces: string[];
    matrix: Record<string, Record<string, boolean>>;
    mode: 'add' | 'edit';
    // When mode === 'edit', diff the submission against this group's
    // existing rows so we can also DELETE rows the user unticked.
    editingGroup?: {
      namespaces: string[];
      allPermissions: NamespacePermission[];
    };
  } | null>(null);

  useEffect(() => {
    if (!selectedRoleId && roles[0]) setSelectedRoleId(roles[0].id);
  }, [roles, selectedRoleId]);

  const refresh = useCallback(async (roleId: number) => {
    setLoading(true);
    try {
      const { items } = await listRolePermissions(roleId);
      setPermissions(items ?? []);
    } catch (err) {
      onError(err instanceof Error ? err.message : 'Failed to load permissions');
    } finally {
      setLoading(false);
    }
  }, [onError]);

  useEffect(() => {
    if (selectedRoleId) void refresh(selectedRoleId);
    else setPermissions([]);
  }, [selectedRoleId, refresh]);

  // Role sidebar summary: #perms, distinct namespaces, distinct clusters.
  const [roleSummaries, setRoleSummaries] = useState<Record<number, { count: number; ns: number; cl: number }>>({});
  useEffect(() => {
    // Preload summaries for all roles in parallel. Keeps the sidebar numbers
    // honest without clicking into each role; small cost on page open.
    (async () => {
      const summaries: Record<number, { count: number; ns: number; cl: number }> = {};
      await Promise.all(roles.map(async (r) => {
        try {
          const { items } = await listRolePermissions(r.id);
          const ns = new Set<string>();
          const cl = new Set<number>();
          (items ?? []).forEach((p) => { ns.add(p.namespace); cl.add(p.clusterId ?? 0); });
          summaries[r.id] = { count: items?.length ?? 0, ns: ns.size, cl: cl.size };
        } catch { /* ignore */ }
      }));
      setRoleSummaries(summaries);
    })();
  }, [roles]);

  const selectedRole = roles.find((r) => r.id === selectedRoleId) ?? null;

  // Group grants in two passes:
  //   pass 1: (cluster, namespace) → list of permissions
  //   pass 2: namespaces whose (resource, action) set is IDENTICAL within the
  //           same cluster collapse into a single card listed with multiple
  //           namespace chips in its header. "developer role on ns=a and ns=b
  //           with the same grants" is now one card, not two.
  const groups = useMemo(() => {
    // Pass 1
    const byNs = new Map<string, {
      clusterId: number;
      clusterName: string;
      namespace: string;
      permissions: NamespacePermission[];
    }>();
    permissions.forEach((p) => {
      const key = `${p.clusterId}:${p.namespace}`;
      const clusterName = p.clusterName || clusters.find((c) => c.id === p.clusterId)?.name || '';
      const bucket = byNs.get(key);
      if (bucket) bucket.permissions.push(p);
      else byNs.set(key, { clusterId: p.clusterId, clusterName, namespace: p.namespace, permissions: [p] });
    });

    // Signature for identity-based merging: cluster + sorted "resource:action"
    // tuples. Permissions themselves keep their individual ids so delete still
    // targets the right rows.
    type MergedGroup = {
      clusterId: number;
      clusterName: string;
      namespaces: string[];
      // one representative permission list (grants on the first ns); every
      // other ns in `namespaces` has the same set, so this is enough for the
      // chip grid. `allPermissions` carries every actual row for operations
      // that need to delete across the whole group.
      permissions: NamespacePermission[];
      allPermissions: NamespacePermission[];
    };
    const byIdentity = new Map<string, MergedGroup>();
    for (const bucket of byNs.values()) {
      const sig = `${bucket.clusterId}|${bucket.permissions
        .map((p) => `${p.resource}:${p.action}`)
        .sort()
        .join(',')}`;
      const existing = byIdentity.get(sig);
      if (existing) {
        existing.namespaces.push(bucket.namespace);
        existing.allPermissions.push(...bucket.permissions);
      } else {
        byIdentity.set(sig, {
          clusterId: bucket.clusterId,
          clusterName: bucket.clusterName,
          namespaces: [bucket.namespace],
          permissions: bucket.permissions,
          allPermissions: [...bucket.permissions],
        });
      }
    }

    const arr = Array.from(byIdentity.values());
    arr.forEach((g) => g.namespaces.sort());
    arr.sort((a, b) => {
      if (a.clusterId !== b.clusterId) return (a.clusterId || 0) - (b.clusterId || 0);
      return a.namespaces[0].localeCompare(b.namespaces[0]);
    });
    return arr;
  }, [permissions, clusters]);

  const filteredRoles = useMemo(() => {
    const q = roleSearch.trim().toLowerCase();
    if (!q) return roles;
    return roles.filter((r) => r.name.toLowerCase().includes(q));
  }, [roles, roleSearch]);

  const handleClearGroup = async (group: { clusterId: number; namespaces: string[]; allPermissions: NamespacePermission[] }) => {
    const nsLabel = group.namespaces.length === 1
      ? `namespace "${group.namespaces[0]}"`
      : `${group.namespaces.length} namespaces (${group.namespaces.slice(0, 3).join(', ')}${group.namespaces.length > 3 ? ', …' : ''})`;
    const ok = await confirm({
      title: 'Clear all permissions for this card?',
      message: `This removes every (resource, action) grant on cluster ${group.clusterId === 0 ? 'all' : group.clusterId}, ${nsLabel}.`,
      confirmText: 'Clear card',
      variant: 'danger',
    });
    if (!ok) return;
    try {
      await Promise.all(group.allPermissions.map((p) => deletePermission(p.id)));
      if (selectedRoleId) await refresh(selectedRoleId);
    } catch (err) {
      onError(err instanceof Error ? err.message : 'Clear failed');
    }
  };

  const existingKeySet = useMemo(() => {
    const s = new Set<string>();
    permissions.forEach((p) => s.add(`${p.clusterId}:${p.namespace}:${p.resource}:${p.action}`));
    return s;
  }, [permissions]);

  const openAddModal = (seed?: Partial<{
    clusterId: number;
    namespaces: string[];
    matrix: ReturnType<typeof emptyMatrix>;
    mode: 'add' | 'edit';
    editingGroup: { namespaces: string[]; allPermissions: NamespacePermission[] };
  }>) => {
    setAddSeed({
      clusterId: seed?.clusterId ?? 0,
      namespaces: seed?.namespaces ?? [],
      matrix: seed?.matrix ?? emptyMatrix(),
      mode: seed?.mode ?? 'add',
      editingGroup: seed?.editingGroup,
    });
    setAddOpen(true);
  };

  const applyAdd = async (payload: {
    clusterId: number;
    namespaces: string[];
    matrix: Record<string, Record<string, boolean>>;
    mode: 'add' | 'edit';
    editingGroup?: { namespaces: string[]; allPermissions: NamespacePermission[] };
  }) => {
    if (!selectedRoleId) return;

    // Desired set as "ns:resource:action" keys.
    const desired = new Set<string>();
    for (const ns of payload.namespaces) {
      for (const [resource, actions] of Object.entries(payload.matrix)) {
        for (const [action, on] of Object.entries(actions)) {
          if (on) desired.add(`${ns}:${resource}:${action}`);
        }
      }
    }

    const toAdd: Array<{ clusterId: number; namespace: string; resource: string; action: string }> = [];
    const toDelete: number[] = [];

    if (payload.mode === 'edit' && payload.editingGroup) {
      // Diff against the group's current rows (not the whole role) so unrelated
      // grants on other cards stay put.
      const idByKey = new Map<string, number>();
      const currentKeys = new Set<string>();
      payload.editingGroup.allPermissions.forEach((p) => {
        const k = `${p.namespace}:${p.resource}:${p.action}`;
        currentKeys.add(k);
        idByKey.set(k, p.id);
      });
      currentKeys.forEach((k) => {
        if (!desired.has(k)) {
          const id = idByKey.get(k);
          if (id !== undefined) toDelete.push(id);
        }
      });
      desired.forEach((k) => {
        if (!currentKeys.has(k)) {
          const [ns, resource, action] = k.split(':');
          toAdd.push({ clusterId: payload.clusterId, namespace: ns, resource, action });
        }
      });
    } else {
      // Add mode: skip anything the role already has anywhere (prevents dup
      // writes), using the whole-role existing key set.
      desired.forEach((k) => {
        const [ns, resource, action] = k.split(':');
        const fullKey = `${payload.clusterId}:${ns}:${resource}:${action}`;
        if (!existingKeySet.has(fullKey)) {
          toAdd.push({ clusterId: payload.clusterId, namespace: ns, resource, action });
        }
      });
    }

    if (toAdd.length === 0 && toDelete.length === 0) {
      setAddOpen(false);
      return;
    }
    try {
      // Deletes first; the UI then shows the final state in a single refresh.
      await Promise.all(toDelete.map((id) => deletePermission(id)));
      await Promise.all(toAdd.map((r) => addRolePermission(selectedRoleId, r)));
      await refresh(selectedRoleId);
      setAddOpen(false);
    } catch (err) {
      onError(err instanceof Error ? err.message : 'Save failed');
    }
  };

  // Remove every permission in `group` matching (resource, action). Called
  // from the chip's X or shift-click — the chip represents the pair across
  // every namespace listed in the card's header.
  const handleRemoveFromGroup = async (
    group: { allPermissions: NamespacePermission[] },
    resource: string,
    action: string,
  ) => {
    const ids = group.allPermissions
      .filter((p) => p.resource === resource && p.action === action)
      .map((p) => p.id);
    try {
      await Promise.all(ids.map((id) => deletePermission(id)));
      if (selectedRoleId) await refresh(selectedRoleId);
    } catch (err) {
      onError(err instanceof Error ? err.message : 'Remove failed');
    }
  };

  const applyCopyFromRole = async (sourceRoleId: number) => {
    if (!selectedRoleId || sourceRoleId === selectedRoleId) return;
    try {
      const { items } = await listRolePermissions(sourceRoleId);
      const rows = (items ?? []).filter((p) => !existingKeySet.has(`${p.clusterId}:${p.namespace}:${p.resource}:${p.action}`));
      if (rows.length === 0) {
        setCopyOpen(false);
        return;
      }
      await Promise.all(rows.map((p) =>
        addRolePermission(selectedRoleId, {
          clusterId: p.clusterId,
          namespace: p.namespace,
          resource: p.resource,
          action: p.action,
        })
      ));
      await refresh(selectedRoleId);
      setCopyOpen(false);
    } catch (err) {
      onError(err instanceof Error ? err.message : 'Copy failed');
    }
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Pick a role, review what it grants, and bulk-add or copy permissions.
        </p>
        <button
          type="button"
          onClick={onSwitchClassic}
          className="text-[11px] font-medium text-slate-500 underline-offset-4 hover:text-brand-600 hover:underline dark:text-slate-400 dark:hover:text-brand-300"
        >
          Switch to classic view
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[260px_1fr]">
        {/* ── Role sidebar ───────────────────────────────────────── */}
        <aside className="rounded-lg border border-slate-200 bg-white p-2 dark:border-slate-800 dark:bg-slate-900">
          <div className="relative mb-2">
            <SearchIcon
              size={12}
              className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-slate-400"
            />
            <input
              type="text"
              value={roleSearch}
              onChange={(e) => setRoleSearch(e.target.value)}
              placeholder="Search roles…"
              className="w-full rounded-md border border-slate-200 bg-white py-1.5 pl-7 pr-2 text-xs text-slate-900 placeholder:text-slate-400 focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500/15 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:placeholder:text-slate-500"
            />
          </div>
          <ul className="flex max-h-[560px] flex-col gap-0.5 overflow-y-auto pr-1">
            {filteredRoles.map((r) => {
              const summary = roleSummaries[r.id];
              const active = r.id === selectedRoleId;
              return (
                <li key={r.id}>
                  <button
                    type="button"
                    onClick={() => setSelectedRoleId(r.id)}
                    className={`flex w-full flex-col items-start gap-0.5 rounded-md px-2.5 py-1.5 text-left transition-colors ${
                      active
                        ? 'bg-brand-50 ring-1 ring-inset ring-brand-200 dark:bg-brand-500/15 dark:ring-brand-500/30'
                        : 'hover:bg-slate-50 dark:hover:bg-slate-800'
                    }`}
                  >
                    <span className={`text-xs font-medium ${active ? 'text-brand-700 dark:text-brand-200' : 'text-slate-800 dark:text-slate-100'}`}>
                      {r.name}
                    </span>
                    {summary && (
                      <span className="text-[10px] text-slate-500 dark:text-slate-400">
                        {summary.count} perms · {summary.ns} ns · {summary.cl} cluster{summary.cl === 1 ? '' : 's'}
                      </span>
                    )}
                  </button>
                </li>
              );
            })}
            {filteredRoles.length === 0 && (
              <li className="px-2.5 py-4 text-center text-[11px] text-slate-400 dark:text-slate-500">
                No roles.
              </li>
            )}
          </ul>
        </aside>

        {/* ── Main pane ─────────────────────────────────────────── */}
        <section className="flex flex-col gap-3">
          {!selectedRole && (
            <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 p-6 text-center text-sm text-slate-400 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-500">
              Select a role on the left.
            </div>
          )}
          {selectedRole && (
            <>
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-200 bg-white px-4 py-3 dark:border-slate-800 dark:bg-slate-900">
                <div>
                  <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                    {selectedRole.name}
                  </div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400">
                    {selectedRole.description || 'No description.'}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button variant="outline" size="sm" onClick={() => setCopyOpen(true)}>
                    <Copy size={13} />
                    Copy from role
                  </Button>
                  <Button variant="primary" size="sm" onClick={() => openAddModal()}>
                    <Plus size={13} />
                    Add permissions
                  </Button>
                </div>
              </div>

              {loading && (
                <div className="text-xs text-slate-400 dark:text-slate-500">Loading…</div>
              )}

              {!loading && groups.length === 0 && (
                <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 p-6 text-center text-sm text-slate-400 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-500">
                  No permissions yet. Pick a template from "Add permissions" to seed this role.
                </div>
              )}

              <div className="flex flex-col gap-3">
                {groups.map((g) => (
                  <GrantCard
                    key={`${g.clusterId}:${g.namespaces.join(',')}`}
                    clusterId={g.clusterId}
                    clusterName={g.clusterName}
                    namespaces={g.namespaces}
                    permissions={g.permissions}
                    onRemoveAction={(resource, action) => handleRemoveFromGroup(g, resource, action)}
                    onClearCard={() => handleClearGroup(g)}
                    onEdit={() => {
                      // Seed the modal with THIS card's current state so the
                      // user can tick/untick and the diff is applied on save.
                      const matrix = emptyMatrix();
                      g.permissions.forEach((p) => {
                        if (matrix[p.resource]) matrix[p.resource][p.action] = true;
                      });
                      openAddModal({
                        clusterId: g.clusterId,
                        namespaces: g.namespaces,
                        matrix,
                        mode: 'edit',
                        editingGroup: { namespaces: g.namespaces, allPermissions: g.allPermissions },
                      });
                    }}
                    onDuplicateTo={() => {
                      const matrix = emptyMatrix();
                      g.permissions.forEach((p) => {
                        if (matrix[p.resource]) matrix[p.resource][p.action] = true;
                      });
                      // Duplicate = fresh add; namespaces left empty so the
                      // operator picks the targets.
                      openAddModal({ clusterId: g.clusterId, namespaces: [], matrix, mode: 'add' });
                    }}
                  />
                ))}
              </div>
            </>
          )}
        </section>
      </div>

      {addOpen && addSeed && selectedRoleId && (
        <AddPermissionsModal
          seed={addSeed}
          clusters={clusters}
          namespaces={namespaces}
          existing={existingKeySet}
          onCancel={() => setAddOpen(false)}
          onApply={applyAdd}
        />
      )}

      {copyOpen && selectedRole && (
        <CopyFromRoleModal
          currentRoleId={selectedRole.id}
          roles={roles}
          onCancel={() => setCopyOpen(false)}
          onPick={applyCopyFromRole}
        />
      )}
    </div>
  );
};

// ─── Namespaces strip (header of GrantCard) ────────────────────────────────
//
// Keeps the chip row on a single line to protect the card header's rhythm.
// After the visible cap, remaining namespaces collapse into a "+N more"
// badge that reveals them in a portaled popover on hover/focus — portal so
// the popover escapes the card's overflow:hidden boundary.

const NAMESPACE_VISIBLE = 5;

const NamespacesStrip: React.FC<{ namespaces: string[] }> = ({ namespaces }) => {
  const [hovered, setHovered] = useState(false);
  const anchor = useRef<HTMLButtonElement | null>(null);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);

  const visible = namespaces.slice(0, NAMESPACE_VISIBLE);
  const hiddenCount = Math.max(0, namespaces.length - NAMESPACE_VISIBLE);

  useLayoutEffect(() => {
    if (!hovered || !anchor.current) return;
    const r = anchor.current.getBoundingClientRect();
    setPos({ top: r.bottom + 4, left: r.left });
  }, [hovered]);

  return (
    <div className="flex min-w-0 flex-1 items-center gap-1 overflow-hidden">
      {visible.map((ns) => (
        <span
          key={ns}
          className="shrink-0 truncate rounded bg-brand-50 px-1.5 py-0.5 font-mono text-[11px] font-medium text-brand-700 ring-1 ring-inset ring-brand-100 dark:bg-brand-500/15 dark:text-brand-200 dark:ring-brand-500/30"
          title={ns}
        >
          {ns}
        </span>
      ))}
      {hiddenCount > 0 && (
        <button
          type="button"
          ref={anchor}
          onMouseEnter={() => setHovered(true)}
          onMouseLeave={() => setHovered(false)}
          onFocus={() => setHovered(true)}
          onBlur={() => setHovered(false)}
          className="shrink-0 rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-600 ring-1 ring-inset ring-slate-200 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:ring-slate-700 dark:hover:bg-slate-700"
          aria-label={`${hiddenCount} more namespaces`}
        >
          +{hiddenCount} more
        </button>
      )}
      {namespaces.length > 1 && (
        <span className="ml-1 hidden shrink-0 rounded bg-slate-50 px-1.5 py-0.5 font-mono text-[10px] text-slate-500 dark:bg-slate-900/60 dark:text-slate-400 sm:inline">
          same grants
        </span>
      )}
      {hovered && pos && createPortal(
        <div
          className="pointer-events-none fixed z-[60] max-w-sm rounded-lg border border-slate-200 bg-white p-2 shadow-elevated dark:border-slate-700 dark:bg-slate-900"
          style={{ top: pos.top, left: pos.left }}
        >
          <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
            {namespaces.length} namespaces
          </div>
          <div className="flex flex-wrap gap-1">
            {namespaces.map((ns) => (
              <span
                key={ns}
                className="rounded bg-brand-50 px-1.5 py-0.5 font-mono text-[11px] text-brand-700 dark:bg-brand-500/15 dark:text-brand-200"
              >
                {ns}
              </span>
            ))}
          </div>
        </div>,
        document.body,
      )}
    </div>
  );
};

// ─── Grant card ─────────────────────────────────────────────────────────────

const GrantCard: React.FC<{
  clusterId: number;
  clusterName: string;
  /** The card represents one OR more namespaces that share the identical set
   *  of (resource, action) grants on the same cluster. */
  namespaces: string[];
  permissions: NamespacePermission[];
  /** Remove a (resource, action) pair from EVERY namespace in this card. */
  onRemoveAction: (resource: string, action: string) => void | Promise<void>;
  onClearCard: () => void;
  onEdit: () => void;
  onDuplicateTo: () => void;
}> = ({ clusterId, clusterName, namespaces, permissions, onRemoveAction, onClearCard, onEdit, onDuplicateTo }) => {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuAnchor = React.useRef<HTMLButtonElement | null>(null);
  const [menuPos, setMenuPos] = useState<{ top: number; right: number } | null>(null);

  useEffect(() => {
    if (!menuOpen || !menuAnchor.current) return;
    const r = menuAnchor.current.getBoundingClientRect();
    setMenuPos({ top: r.bottom + 4, right: window.innerWidth - r.right });
    const close = (e: MouseEvent) => {
      if ((e.target as HTMLElement).closest('[data-grant-menu]')) return;
      setMenuOpen(false);
    };
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, [menuOpen]);

  // Group this card's permissions by resource so the row for 'pods' shows
  // every granted action side-by-side instead of a flat sorted pill soup.
  const byResource = useMemo(() => {
    const m = new Map<string, NamespacePermission[]>();
    permissions.forEach((p) => {
      const arr = m.get(p.resource) ?? [];
      arr.push(p);
      m.set(p.resource, arr);
    });
    return RESOURCE_CATALOG
      .map((cat) => ({ resource: cat.resource, actions: cat.actions, grants: m.get(cat.resource) ?? [] }))
      .filter((r) => r.grants.length > 0);
  }, [permissions]);

  return (
    <article className="rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      <header className="flex items-center justify-between gap-3 border-b border-slate-100 px-4 py-2.5 dark:border-slate-800/70">
        <div className="flex min-w-0 flex-1 items-center gap-x-2 overflow-hidden">
          {clusterId === 0 ? (
            <Badge variant="info" className="h-5 shrink-0 text-[10px]">all clusters</Badge>
          ) : (
            <span className="shrink-0 rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-700 dark:bg-slate-800 dark:text-slate-200">
              {clusterName || `#${clusterId}`}
            </span>
          )}
          <span className="shrink-0 text-slate-300 dark:text-slate-700">/</span>
          <NamespacesStrip namespaces={namespaces} />
        </div>
        <button
          type="button"
          ref={menuAnchor}
          onClick={(e) => { e.stopPropagation(); setMenuOpen((v) => !v); }}
          className="shrink-0 rounded p-1 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
          aria-label="Card actions"
        >
          <MoreHorizontal size={14} />
        </button>
      </header>
      <ul className="divide-y divide-slate-100 dark:divide-slate-800/70">
        {byResource.map(({ resource, actions, grants }) => (
          <li key={resource} className="flex items-center gap-3 px-4 py-2">
            <span className="w-32 shrink-0 font-mono text-[12px] text-slate-700 dark:text-slate-200">
              {resource}
            </span>
            <div className="flex flex-wrap gap-1.5">
              {actions.map((a) => {
                const grant = grants.find((g) => g.action === a.key);
                if (!grant) return null;
                return (
                  <span
                    key={a.key}
                    className={`group inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-mono text-[10px] font-medium uppercase tracking-wide ${FAMILY_CLASS[a.family]}`}
                    title={namespaces.length > 1
                      ? `Shift-click removes ${resource}:${a.key} from ALL ${namespaces.length} namespaces in this card · ${a.family}`
                      : `Shift-click to remove · ${a.family}`}
                    onClick={(e) => {
                      if (e.shiftKey) {
                        e.preventDefault();
                        void onRemoveAction(resource, a.key);
                      }
                    }}
                  >
                    {a.key}
                    <button
                      type="button"
                      onClick={() => onRemoveAction(resource, a.key)}
                      className="opacity-0 transition-opacity hover:text-rose-600 focus:opacity-100 group-hover:opacity-100"
                      aria-label={`Remove ${resource}:${a.key}`}
                    >
                      <X size={10} />
                    </button>
                  </span>
                );
              })}
            </div>
          </li>
        ))}
      </ul>
      {menuOpen && menuPos && createPortal(
        <div
          data-grant-menu
          className="fixed z-50 w-52 overflow-hidden rounded-lg border border-slate-200 bg-white py-1 shadow-elevated dark:border-slate-800 dark:bg-slate-900"
          style={{ top: menuPos.top, right: menuPos.right }}
        >
          <button
            type="button"
            className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-800"
            onClick={() => { setMenuOpen(false); onEdit(); }}
          >
            <Pencil size={13} />
            Edit permissions…
          </button>
          <button
            type="button"
            className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-800"
            onClick={() => { setMenuOpen(false); onDuplicateTo(); }}
          >
            <Copy size={13} />
            Duplicate to another namespace…
          </button>
          <button
            type="button"
            className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-rose-600 hover:bg-rose-50 dark:text-rose-300 dark:hover:bg-rose-500/15"
            onClick={() => { setMenuOpen(false); void onClearCard(); }}
          >
            <Trash2 size={13} />
            Clear card
          </button>
        </div>,
        document.body
      )}
    </article>
  );
};

// ─── Add permissions modal ──────────────────────────────────────────────────

const AddPermissionsModal: React.FC<{
  seed: {
    clusterId: number;
    namespaces: string[];
    matrix: Record<string, Record<string, boolean>>;
    mode: 'add' | 'edit';
    editingGroup?: { namespaces: string[]; allPermissions: NamespacePermission[] };
  };
  clusters: ClusterListItem[];
  namespaces: string[];
  existing: Set<string>;
  onCancel: () => void;
  onApply: (payload: {
    clusterId: number;
    namespaces: string[];
    matrix: Record<string, Record<string, boolean>>;
    mode: 'add' | 'edit';
    editingGroup?: { namespaces: string[]; allPermissions: NamespacePermission[] };
  }) => void | Promise<void>;
}> = ({ seed, clusters, namespaces, existing, onCancel, onApply }) => {
  const [clusterId, setClusterId] = useState(seed.clusterId);
  const [selectedNs, setSelectedNs] = useState<string[]>(seed.namespaces);
  const [matrix, setMatrix] = useState(seed.matrix);
  const [template, setTemplate] = useState<Template | null>(null);
  const [applying, setApplying] = useState(false);
  const [nsFilter, setNsFilter] = useState('');
  const isEdit = seed.mode === 'edit';

  const applyTemplate = (t: Template) => {
    setTemplate(t);
    setMatrix(buildTemplateMatrix(t));
  };

  const toggle = (resource: string, action: string) => {
    setTemplate(null);
    setMatrix((m) => ({
      ...m,
      [resource]: { ...m[resource], [action]: !m[resource]?.[action] },
    }));
  };

  const toggleResource = (resource: string, on: boolean) => {
    setTemplate(null);
    setMatrix((m) => {
      const row = { ...m[resource] };
      Object.keys(row).forEach((k) => { row[k] = on; });
      return { ...m, [resource]: row };
    });
  };

  // Preview counter.
  //   add mode: how many brand-new rows will be inserted; "skipped" counts
  //             rows the role already has elsewhere (collision-free).
  //   edit mode: how many rows will be ADDED vs REMOVED relative to the
  //              group's current state. The group is the only thing the diff
  //              is scoped to, so unrelated role grants aren't touched.
  const preview = useMemo(() => {
    const desired = new Set<string>();
    for (const ns of selectedNs) {
      for (const [resource, actions] of Object.entries(matrix)) {
        for (const [action, on] of Object.entries(actions)) {
          if (on) desired.add(`${ns}:${resource}:${action}`);
        }
      }
    }
    if (isEdit && seed.editingGroup) {
      const current = new Set<string>();
      seed.editingGroup.allPermissions.forEach((p) =>
        current.add(`${p.namespace}:${p.resource}:${p.action}`)
      );
      let adds = 0;
      let dels = 0;
      desired.forEach((k) => { if (!current.has(k)) adds++; });
      current.forEach((k) => { if (!desired.has(k)) dels++; });
      return { mode: 'edit' as const, adds, dels };
    }
    let total = 0;
    let skipped = 0;
    desired.forEach((k) => {
      const [ns, resource, action] = k.split(':');
      const fullKey = `${clusterId}:${ns}:${resource}:${action}`;
      if (existing.has(fullKey)) skipped++;
      else total++;
    });
    return { mode: 'add' as const, total, skipped };
  }, [clusterId, selectedNs, matrix, existing, isEdit, seed.editingGroup]);

  const filteredNamespaces = useMemo(() => {
    const q = nsFilter.trim().toLowerCase();
    return q ? namespaces.filter((n) => n.toLowerCase().includes(q)) : namespaces;
  }, [namespaces, nsFilter]);

  return (
    <Modal
      open
      size="lg"
      onClose={applying ? () => {} : onCancel}
      title={isEdit ? 'Edit permissions' : 'Add permissions'}
      footer={
        <>
          <Button variant="outline" size="sm" onClick={onCancel} disabled={applying}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            disabled={
              applying ||
              (preview.mode === 'add'
                ? preview.total === 0
                : preview.adds === 0 && preview.dels === 0)
            }
            onClick={async () => {
              setApplying(true);
              try {
                await onApply({
                  clusterId,
                  namespaces: selectedNs,
                  matrix,
                  mode: seed.mode,
                  editingGroup: seed.editingGroup,
                });
              } finally {
                setApplying(false);
              }
            }}
          >
            {applying
              ? 'Saving…'
              : preview.mode === 'edit'
              ? `Save (${preview.adds} added, ${preview.dels} removed)`
              : `Add ${preview.total} permission${preview.total === 1 ? '' : 's'}`}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label className="mb-1 block text-[10px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
              Cluster
            </label>
            <NativeSelect
              value={String(clusterId)}
              onChange={(e) => setClusterId(Number(e.target.value))}
            >
              <option value="0">All clusters (wildcard)</option>
              {clusters.map((c) => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </NativeSelect>
          </div>
          <div>
            <label className="mb-1 block text-[10px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
              Namespaces · {selectedNs.length} selected
            </label>
            <Input
              placeholder="Filter namespaces…"
              value={nsFilter}
              onChange={(e) => setNsFilter(e.target.value)}
            />
            <div className="mt-2 flex max-h-32 flex-wrap gap-1 overflow-auto rounded-md border border-slate-200 p-2 dark:border-slate-700">
              {filteredNamespaces.map((n) => {
                const picked = selectedNs.includes(n);
                return (
                  <button
                    key={n}
                    type="button"
                    onClick={() =>
                      setSelectedNs((prev) =>
                        prev.includes(n) ? prev.filter((x) => x !== n) : [...prev, n]
                      )
                    }
                    className={`rounded px-2 py-0.5 font-mono text-[11px] transition-colors ${
                      picked
                        ? 'bg-brand-500 text-white'
                        : 'bg-slate-100 text-slate-700 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700'
                    }`}
                  >
                    {n}
                  </button>
                );
              })}
              {filteredNamespaces.length === 0 && (
                <span className="text-xs text-slate-400 dark:text-slate-500">No match.</span>
              )}
            </div>
          </div>
        </div>

        <div>
          <label className="mb-1 block text-[10px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
            Template
          </label>
          <div className="flex flex-wrap gap-1.5">
            {(Object.keys(TEMPLATE_LABELS) as Template[]).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => applyTemplate(t)}
                className={`rounded-md border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                  template === t
                    ? 'border-brand-400 bg-brand-50 text-brand-700 dark:border-brand-500/50 dark:bg-brand-500/15 dark:text-brand-200'
                    : 'border-slate-200 text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800'
                }`}
              >
                {TEMPLATE_LABELS[t]}
              </button>
            ))}
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-[10px] font-semibold uppercase tracking-wide text-slate-500 dark:bg-slate-900/70 dark:text-slate-400">
              <tr>
                <th className="px-3 py-2">Resource</th>
                <th className="px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {RESOURCE_CATALOG.map(({ resource, actions }) => {
                const allOn = actions.every((a) => matrix[resource]?.[a.key]);
                const anyOn = actions.some((a) => matrix[resource]?.[a.key]);
                return (
                  <tr key={resource} className="border-t border-slate-100 dark:border-slate-800">
                    <td className="px-3 py-2">
                      <label className="flex cursor-pointer items-center gap-2">
                        <Checkbox
                          checked={allOn}
                          indeterminate={anyOn && !allOn}
                          onChange={(v) => toggleResource(resource, v)}
                        />
                        <span className="font-mono text-[12px] text-slate-800 dark:text-slate-100">
                          {resource}
                        </span>
                      </label>
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap justify-end gap-1.5">
                        {actions.map((a) => {
                          const on = !!matrix[resource]?.[a.key];
                          // highlight rows where EVERY selected ns already has this (resource, action)
                          const everywhereExists =
                            selectedNs.length > 0 &&
                            selectedNs.every((ns) =>
                              existing.has(`${clusterId}:${ns}:${resource}:${a.key}`)
                            );
                          return (
                            <button
                              key={a.key}
                              type="button"
                              onClick={() => toggle(resource, a.key)}
                              className={`inline-flex items-center gap-1 rounded px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide transition-all ${
                                on
                                  ? FAMILY_CLASS[a.family]
                                  : 'bg-white text-slate-400 ring-1 ring-inset ring-slate-200 hover:bg-slate-50 dark:bg-slate-900 dark:text-slate-500 dark:ring-slate-700 dark:hover:bg-slate-800'
                              } ${everywhereExists ? 'opacity-50 line-through' : ''}`}
                              title={everywhereExists ? 'Already granted on every selected namespace — will be skipped' : a.family}
                            >
                              {a.key}
                            </button>
                          );
                        })}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {preview.mode === 'edit' ? (
          <Alert severity={preview.adds === 0 && preview.dels === 0 ? 'info' : 'success'}>
            {preview.adds === 0 && preview.dels === 0
              ? 'No changes. Toggle a chip or add/remove a namespace to make an edit.'
              : `${preview.adds} grant${preview.adds === 1 ? '' : 's'} will be added · ${preview.dels} will be removed.`}
          </Alert>
        ) : (
          <Alert severity={preview.total === 0 ? 'info' : 'success'}>
            {preview.total === 0
              ? 'Nothing to add. Pick a namespace and at least one action.'
              : `Will create ${preview.total} new permission${preview.total === 1 ? '' : 's'}${
                  preview.skipped > 0 ? ` · ${preview.skipped} already granted, will be skipped` : ''
                }.`}
          </Alert>
        )}
      </div>
    </Modal>
  );
};

// ─── Copy from role modal ───────────────────────────────────────────────────

const CopyFromRoleModal: React.FC<{
  currentRoleId: number;
  roles: RoleRow[];
  onCancel: () => void;
  onPick: (sourceRoleId: number) => void | Promise<void>;
}> = ({ currentRoleId, roles, onCancel, onPick }) => {
  const [picked, setPicked] = useState<number | null>(null);
  const [applying, setApplying] = useState(false);
  return (
    <Modal
      open
      size="sm"
      onClose={applying ? () => {} : onCancel}
      title="Copy permissions from another role"
      footer={
        <>
          <Button variant="outline" size="sm" onClick={onCancel} disabled={applying}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            disabled={!picked || applying}
            onClick={async () => {
              if (!picked) return;
              setApplying(true);
              try {
                await onPick(picked);
              } finally {
                setApplying(false);
              }
            }}
          >
            {applying ? 'Copying…' : 'Copy'}
          </Button>
        </>
      }
    >
      <p className="mb-3 text-xs text-slate-500 dark:text-slate-400">
        Rows that already exist on this role are skipped.
      </p>
      <ul className="flex flex-col gap-1">
        {roles
          .filter((r) => r.id !== currentRoleId)
          .map((r) => (
            <li key={r.id}>
              <button
                type="button"
                onClick={() => setPicked(r.id)}
                className={`flex w-full items-center justify-between rounded-md border px-3 py-2 text-left text-sm transition-colors ${
                  picked === r.id
                    ? 'border-brand-400 bg-brand-50 dark:border-brand-500/50 dark:bg-brand-500/15'
                    : 'border-slate-200 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800'
                }`}
              >
                <span className="font-mono text-xs text-slate-800 dark:text-slate-100">{r.name}</span>
                <span className="text-[10px] text-slate-400 dark:text-slate-500">{r.description || '—'}</span>
              </button>
            </li>
          ))}
      </ul>
    </Modal>
  );
};

export default RolePermissionsPanel;
