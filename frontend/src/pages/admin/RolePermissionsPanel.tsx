import React, { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { ApiAccess } from '../../services/api';
import { RoleApiAccessLine } from './ApiAccessParts';
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
import { Badge, Button, Modal } from '../../components/ui';
import { confirm } from '../../components/ConfirmDialog';
import { FAMILY_CLASS, RESOURCE_CATALOG, emptyMatrix } from '../../components/PermissionMatrix';
import { AddPermissionsModal, type PermissionSeed } from './AddPermissionsModal';
import {
  ClusterListItem,
  NamespacePermission,
  addRolePermission,
  deletePermission,
  listRolePermissions,
} from '../../services/api';

// ─── Props ──────────────────────────────────────────────────────────────────

type RoleRow = { id: number; name: string; description: string; apiAccess?: ApiAccess };

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
  const { t } = useTranslation();
  const [roleSearch, setRoleSearch] = useState('');
  const [selectedRoleId, setSelectedRoleId] = useState<number | null>(() => roles[0]?.id ?? null);
  const [permissions, setPermissions] = useState<NamespacePermission[]>([]);
  const [loading, setLoading] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const [copyOpen, setCopyOpen] = useState(false);
  // When mode === 'edit', the submission is diffed against the card's
  // existing rows so rows the user unticked are deleted too.
  const [addSeed, setAddSeed] = useState<PermissionSeed | null>(null);

  useEffect(() => {
    if (!selectedRoleId && roles[0]) setSelectedRoleId(roles[0].id);
  }, [roles, selectedRoleId]);

  const refresh = useCallback(async (roleId: number) => {
    setLoading(true);
    try {
      const { items } = await listRolePermissions(roleId);
      setPermissions(items ?? []);
    } catch (err) {
      onError((err as Error).message || t('rolePermissions.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [onError, t]);

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
    const cluster = group.clusterId === 0 ? t('rolePermissions.allClustersShort') : String(group.clusterId);
    const list = group.namespaces.slice(0, 3).join(', ') + (group.namespaces.length > 3 ? ', …' : '');
    const ok = await confirm({
      title: t('rolePermissions.clearTitle'),
      message:
        group.namespaces.length === 1
          ? t('rolePermissions.clearMessageOne', { cluster, namespace: group.namespaces[0] })
          : t('rolePermissions.clearMessageMany', { cluster, count: group.namespaces.length, list }),
      confirmText: t('rolePermissions.clearCard'),
      variant: 'danger',
    });
    if (!ok) return;
    try {
      await Promise.all(group.allPermissions.map((p) => deletePermission(p.id)));
      if (selectedRoleId) await refresh(selectedRoleId);
    } catch (err) {
      onError((err as Error).message || t('rolePermissions.clearFailed'));
    }
  };

  const existingKeySet = useMemo(() => {
    const s = new Set<string>();
    permissions.forEach((p) => s.add(`${p.clusterId}:${p.namespace}:${p.resource}:${p.action}`));
    return s;
  }, [permissions]);

  const openAddModal = (seed?: Partial<PermissionSeed>) => {
    setAddSeed({
      clusterId: seed?.clusterId ?? 0,
      namespaces: seed?.namespaces ?? [],
      matrix: seed?.matrix ?? emptyMatrix(),
      mode: seed?.mode ?? 'add',
      editingGroup: seed?.editingGroup,
    });
    setAddOpen(true);
  };

  const applyAdd = async (payload: PermissionSeed) => {
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
      onError((err as Error).message || t('common.saveFailed'));
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
      onError((err as Error).message || t('rolePermissions.removeFailed'));
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
      onError((err as Error).message || t('rolePermissions.copyFailed'));
    }
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs text-slate-500 dark:text-slate-400">
          {t('rolePermissions.description')}
        </p>
        <button
          type="button"
          onClick={onSwitchClassic}
          className="text-[11px] font-medium text-slate-500 underline-offset-4 hover:text-brand-600 hover:underline dark:text-slate-400 dark:hover:text-brand-300"
        >
          {t('admin.switchToClassic')}
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
              placeholder={t('rolePermissions.searchRoles')}
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
                      <span className={`text-[10px] ${active ? 'text-slate-600 dark:text-slate-300' : 'text-slate-500 dark:text-slate-400'}`}>
                        {t('rolePermissions.summary', { perms: summary.count, namespaces: summary.ns, count: summary.cl })}
                      </span>
                    )}
                  </button>
                </li>
              );
            })}
            {filteredRoles.length === 0 && (
              <li className="px-2.5 py-4 text-center text-[11px] text-slate-500 dark:text-slate-400">
                {t('rolePermissions.noRoles')}
              </li>
            )}
          </ul>
        </aside>

        {/* ── Main pane ─────────────────────────────────────────── */}
        <section className="flex flex-col gap-3">
          {!selectedRole && (
            <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 p-6 text-center text-sm text-slate-500 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
              {t('rolePermissions.pickRole')}
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
                    {selectedRole.description || t('rolePermissions.noDescription')}
                  </div>
                  {selectedRole.apiAccess && (
                    <div className="mt-1.5">
                      <RoleApiAccessLine value={selectedRole.apiAccess} />
                    </div>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <Button variant="outline" size="sm" onClick={() => setCopyOpen(true)}>
                    <Copy size={13} />
                    {t('rolePermissions.copyFromRole')}
                  </Button>
                  <Button variant="primary" size="sm" onClick={() => openAddModal()}>
                    <Plus size={13} />
                    {t('rolePermissions.addPermissions')}
                  </Button>
                </div>
              </div>

              {loading && (
                <div className="text-xs text-slate-500 dark:text-slate-400">{t('common.loading')}</div>
              )}

              {!loading && groups.length === 0 && (
                <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 p-6 text-center text-sm text-slate-500 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                  {t('rolePermissions.noPerms')}
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
  const { t } = useTranslation();
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
            <Badge variant="info" className="h-5 shrink-0 text-[10px]">{t('rolePermissions.allClusters')}</Badge>
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
          aria-label={t('rolePermissions.cardActions')}
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
            {t('rolePermissions.editPermissions')}
          </button>
          <button
            type="button"
            className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-800"
            onClick={() => { setMenuOpen(false); onDuplicateTo(); }}
          >
            <Copy size={13} />
            {t('rolePermissions.duplicateTo')}
          </button>
          <button
            type="button"
            className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-rose-600 hover:bg-rose-50 dark:text-rose-300 dark:hover:bg-rose-500/15"
            onClick={() => { setMenuOpen(false); void onClearCard(); }}
          >
            <Trash2 size={13} />
            {t('rolePermissions.clearCard')}
          </button>
        </div>,
        document.body
      )}
    </article>
  );
};

// ─── Copy from role modal ───────────────────────────────────────────────────

const CopyFromRoleModal: React.FC<{
  currentRoleId: number;
  roles: RoleRow[];
  onCancel: () => void;
  onPick: (sourceRoleId: number) => void | Promise<void>;
}> = ({ currentRoleId, roles, onCancel, onPick }) => {
  const { t: tr } = useTranslation();
  const [picked, setPicked] = useState<number | null>(null);
  const [applying, setApplying] = useState(false);
  return (
    <Modal
      open
      size="sm"
      onClose={applying ? () => {} : onCancel}
      title={tr('rolePermissions.copyTitle')}
      footer={
        <>
          <Button variant="outline" size="sm" onClick={onCancel} disabled={applying}>
            {tr('actions.cancel')}
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
            {applying ? tr('rolePermissions.copying') : tr('rolePermissions.copy')}
          </Button>
        </>
      }
    >
      <p className="mb-3 text-xs text-slate-500 dark:text-slate-400">
        {tr('rolePermissions.copySubtitle')}
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
                <span className="text-[10px] text-slate-500 dark:text-slate-400">{r.description || '—'}</span>
              </button>
            </li>
          ))}
      </ul>
    </Modal>
  );
};

export default RolePermissionsPanel;
