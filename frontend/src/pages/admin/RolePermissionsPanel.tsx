import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Copy,
  MoreHorizontal,
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

const RESOURCE_CATALOG: Array<{ resource: string; actions: ActionDef[] }> = [
  { resource: 'pods', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
    { key: 'logs', family: 'read' },
    { key: 'exec', family: 'destructive' },
  ]},
  { resource: 'deployments', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
    { key: 'restart', family: 'write' },
    { key: 'scale', family: 'write' },
  ]},
  { resource: 'daemonsets', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
  ]},
  { resource: 'statefulsets', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
    { key: 'scale', family: 'write' },
  ]},
  { resource: 'hpas', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
  ]},
  { resource: 'services', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
  ]},
  { resource: 'configmaps', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
  ]},
  { resource: 'ingresses', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
  ]},
  { resource: 'cronjobs', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
  ]},
  { resource: 'jobs', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
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
        on = a.family === 'read'
          || (resource === 'deployments' && (a.key === 'restart' || a.key === 'scale'))
          || (resource === 'statefulsets' && a.key === 'scale')
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

  // Group grants by (cluster, namespace) → list of permissions.
  const groups = useMemo(() => {
    const map = new Map<string, {
      clusterId: number;
      clusterName: string;
      namespace: string;
      permissions: NamespacePermission[];
    }>();
    permissions.forEach((p) => {
      const key = `${p.clusterId}:${p.namespace}`;
      const bucket = map.get(key);
      const clusterName = p.clusterName || clusters.find((c) => c.id === p.clusterId)?.name || '';
      if (bucket) bucket.permissions.push(p);
      else map.set(key, { clusterId: p.clusterId, clusterName, namespace: p.namespace, permissions: [p] });
    });
    const arr = Array.from(map.values());
    arr.sort((a, b) => {
      if (a.clusterId !== b.clusterId) return (a.clusterId || 0) - (b.clusterId || 0);
      return a.namespace.localeCompare(b.namespace);
    });
    return arr;
  }, [permissions, clusters]);

  const filteredRoles = useMemo(() => {
    const q = roleSearch.trim().toLowerCase();
    if (!q) return roles;
    return roles.filter((r) => r.name.toLowerCase().includes(q));
  }, [roles, roleSearch]);

  const handleRemovePermission = async (id: number) => {
    try {
      await deletePermission(id);
      if (selectedRoleId) await refresh(selectedRoleId);
    } catch (err) {
      onError(err instanceof Error ? err.message : 'Delete failed');
    }
  };

  const handleClearRow = async (clusterId: number, namespace: string) => {
    const ok = await confirm({
      title: 'Clear all permissions for this row?',
      message: `This removes every (resource, action) grant for cluster ${clusterId === 0 ? 'all' : clusterId}, namespace "${namespace}".`,
      confirmText: 'Clear row',
      variant: 'danger',
    });
    if (!ok) return;
    try {
      await Promise.all(
        groups
          .find((g) => g.clusterId === clusterId && g.namespace === namespace)?.permissions
          .map((p) => deletePermission(p.id)) ?? []
      );
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

  const openAddModal = (seed?: Partial<{ clusterId: number; namespaces: string[]; matrix: ReturnType<typeof emptyMatrix> }>) => {
    setAddSeed({
      clusterId: seed?.clusterId ?? 0,
      namespaces: seed?.namespaces ?? [],
      matrix: seed?.matrix ?? emptyMatrix(),
    });
    setAddOpen(true);
  };

  const applyAdd = async (payload: { clusterId: number; namespaces: string[]; matrix: Record<string, Record<string, boolean>> }) => {
    if (!selectedRoleId) return;
    const rows: Array<{ clusterId: number; namespace: string; resource: string; action: string }> = [];
    for (const ns of payload.namespaces) {
      for (const [resource, actions] of Object.entries(payload.matrix)) {
        for (const [action, on] of Object.entries(actions)) {
          if (!on) continue;
          const key = `${payload.clusterId}:${ns}:${resource}:${action}`;
          if (existingKeySet.has(key)) continue;
          rows.push({ clusterId: payload.clusterId, namespace: ns, resource, action });
        }
      }
    }
    if (rows.length === 0) {
      setAddOpen(false);
      return;
    }
    try {
      await Promise.all(rows.map((r) => addRolePermission(selectedRoleId, r)));
      await refresh(selectedRoleId);
      setAddOpen(false);
    } catch (err) {
      onError(err instanceof Error ? err.message : 'Add failed');
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
                    key={`${g.clusterId}:${g.namespace}`}
                    clusterId={g.clusterId}
                    clusterName={g.clusterName}
                    namespace={g.namespace}
                    permissions={g.permissions}
                    onRemove={handleRemovePermission}
                    onClearRow={() => handleClearRow(g.clusterId, g.namespace)}
                    onDuplicateTo={() => {
                      const matrix = emptyMatrix();
                      g.permissions.forEach((p) => {
                        if (matrix[p.resource]) matrix[p.resource][p.action] = true;
                      });
                      openAddModal({ clusterId: g.clusterId, matrix });
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

// ─── Grant card ─────────────────────────────────────────────────────────────

const GrantCard: React.FC<{
  clusterId: number;
  clusterName: string;
  namespace: string;
  permissions: NamespacePermission[];
  onRemove: (id: number) => void | Promise<void>;
  onClearRow: () => void;
  onDuplicateTo: () => void;
}> = ({ clusterId, clusterName, namespace, permissions, onRemove, onClearRow, onDuplicateTo }) => {
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
        <div className="flex items-center gap-2">
          {clusterId === 0 ? (
            <Badge variant="info" className="h-5 text-[10px]">all clusters</Badge>
          ) : (
            <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-700 dark:bg-slate-800 dark:text-slate-200">
              {clusterName || `#${clusterId}`}
            </span>
          )}
          <span className="text-slate-300 dark:text-slate-700">/</span>
          <span className="font-mono text-xs font-medium text-slate-900 dark:text-slate-100">{namespace}</span>
        </div>
        <button
          type="button"
          ref={menuAnchor}
          onClick={(e) => { e.stopPropagation(); setMenuOpen((v) => !v); }}
          className="rounded p-1 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
          aria-label="Row actions"
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
                    title={`Shift-click to remove · ${a.family}`}
                    onClick={(e) => {
                      if (e.shiftKey) {
                        e.preventDefault();
                        void onRemove(grant.id);
                      }
                    }}
                  >
                    {a.key}
                    <button
                      type="button"
                      onClick={() => onRemove(grant.id)}
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
            onClick={() => { setMenuOpen(false); onDuplicateTo(); }}
          >
            <Copy size={13} />
            Duplicate to another namespace…
          </button>
          <button
            type="button"
            className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-rose-600 hover:bg-rose-50 dark:text-rose-300 dark:hover:bg-rose-500/15"
            onClick={() => { setMenuOpen(false); void onClearRow(); }}
          >
            <Trash2 size={13} />
            Clear row
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
  };
  clusters: ClusterListItem[];
  namespaces: string[];
  existing: Set<string>;
  onCancel: () => void;
  onApply: (payload: { clusterId: number; namespaces: string[]; matrix: Record<string, Record<string, boolean>> }) => void | Promise<void>;
}> = ({ seed, clusters, namespaces, existing, onCancel, onApply }) => {
  const [clusterId, setClusterId] = useState(seed.clusterId);
  const [selectedNs, setSelectedNs] = useState<string[]>(seed.namespaces);
  const [matrix, setMatrix] = useState(seed.matrix);
  const [template, setTemplate] = useState<Template | null>(null);
  const [applying, setApplying] = useState(false);
  const [nsFilter, setNsFilter] = useState('');

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

  // Preview counter: how many NEW rows will be created, net of overlaps with
  // what the role already has.
  const preview = useMemo(() => {
    let total = 0;
    let skipped = 0;
    for (const ns of selectedNs) {
      for (const [resource, actions] of Object.entries(matrix)) {
        for (const [action, on] of Object.entries(actions)) {
          if (!on) continue;
          const key = `${clusterId}:${ns}:${resource}:${action}`;
          if (existing.has(key)) skipped++;
          else total++;
        }
      }
    }
    return { total, skipped };
  }, [clusterId, selectedNs, matrix, existing]);

  const filteredNamespaces = useMemo(() => {
    const q = nsFilter.trim().toLowerCase();
    return q ? namespaces.filter((n) => n.toLowerCase().includes(q)) : namespaces;
  }, [namespaces, nsFilter]);

  return (
    <Modal
      open
      size="full"
      onClose={applying ? () => {} : onCancel}
      title="Add permissions"
      footer={
        <>
          <Button variant="outline" size="sm" onClick={onCancel} disabled={applying}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            disabled={applying || preview.total === 0}
            onClick={async () => {
              setApplying(true);
              try {
                await onApply({ clusterId, namespaces: selectedNs, matrix });
              } finally {
                setApplying(false);
              }
            }}
          >
            {applying ? 'Adding…' : `Add ${preview.total} permission${preview.total === 1 ? '' : 's'}`}
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
                return (
                  <tr key={resource} className="border-t border-slate-100 dark:border-slate-800">
                    <td className="px-3 py-2">
                      <label className="flex cursor-pointer items-center gap-2">
                        <Checkbox
                          checked={allOn}
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

        <Alert severity={preview.total === 0 ? 'info' : 'success'}>
          {preview.total === 0
            ? 'Nothing to add. Pick a namespace and at least one action.'
            : `Will create ${preview.total} new permission${preview.total === 1 ? '' : 's'}${
                preview.skipped > 0 ? ` · ${preview.skipped} already granted, will be skipped` : ''
              }.`}
        </Alert>
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
