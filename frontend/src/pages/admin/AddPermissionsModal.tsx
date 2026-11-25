import React, { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Input, Modal, NativeSelect } from '../../components/ui';
import { PermissionMatrix, RESOURCE_CATALOG } from '../../components/PermissionMatrix';
import { clusterNamespaces, type ClusterListItem, type NamespacePermission } from '../../services/api';

/**
 * What the modal starts from and hands back: "add" creates the picked grants
 * the role doesn't have yet; "edit" diffs against one card's grants
 * (editingGroup) so unticked ones are removed too.
 */
export type PermissionSeed = {
  clusterId: number;
  namespaces: string[];
  matrix: Record<string, Record<string, boolean>>;
  mode: 'add' | 'edit';
  editingGroup?: { namespaces: string[]; allPermissions: NamespacePermission[] };
};

// Templates seed the add-permissions modal. "Admin" selects everything; the
// rest are opinionated starting points that reflect common on-call shapes.
type Template = 'viewer' | 'developer' | 'sre' | 'admin';

const TEMPLATES: Template[] = ['viewer', 'developer', 'sre', 'admin'];

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

// ─── Add permissions modal ──────────────────────────────────────────────────
//
// Admin → Roles → Role Permissions: pick a cluster, namespaces and a matrix
// (or a template); shows how many grants will be added / skipped / removed.
// `existing` = the role's "clusterId:namespace:resource:action" keys.

export const AddPermissionsModal: React.FC<{
  seed: PermissionSeed;
  clusters: ClusterListItem[];
  namespaces: string[];
  existing: Set<string>;
  onCancel: () => void;
  onApply: (payload: PermissionSeed) => void | Promise<void>;
}> =({ seed, clusters, namespaces, existing, onCancel, onApply }) => {
  const { t: tr } = useTranslation();
  const [clusterId, setClusterId] = useState(seed.clusterId);
  const [selectedNs, setSelectedNs] = useState<string[]>(seed.namespaces);
  const [matrix, setMatrix] = useState(seed.matrix);
  const [template, setTemplate] = useState<Template | null>(null);
  const [applying, setApplying] = useState(false);
  const [nsFilter, setNsFilter] = useState('');
  const isEdit = seed.mode === 'edit';

  const applyTemplate = (tplKey: Template) => {
    setTemplate(tplKey);
    setMatrix(buildTemplateMatrix(tplKey));
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

  // The picked cluster's namespaces (every cluster's for "All clusters"); `namespaces` (the tab's
  // cluster) until they arrive. A picked one stays listed even if the cluster doesn't have it.
  const [clusterNs, setClusterNs] = useState<string[] | null>(null);
  useEffect(() => {
    let stale = false;
    const ids = clusterId ? [clusterId] : clusters.map((c) => c.id);
    void Promise.all(ids.map((id) => clusterNamespaces(id).then((r) => r.namespaces ?? [], () => [] as string[]))).then(
      (lists) => !stale && setClusterNs(lists.flat()),
    );
    return () => {
      stale = true;
    };
  }, [clusterId, clusters]);
  const available = useMemo(
    () => [...new Set([...(clusterNs ?? namespaces), ...selectedNs])].sort(),
    [clusterNs, namespaces, selectedNs],
  );

  const filteredNamespaces = useMemo(() => {
    const q = nsFilter.trim().toLowerCase();
    return q ? available.filter((n) => n.toLowerCase().includes(q)) : available;
  }, [available, nsFilter]);

  return (
    <Modal
      open
      size="lg"
      onClose={applying ? () => {} : onCancel}
      title={isEdit ? tr('rolePermissions.editPermissions') : tr('rolePermissions.addPermissions')}
      footer={
        <>
          <Button variant="outline" size="sm" onClick={onCancel} disabled={applying}>
            {tr('actions.cancel')}
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
              ? tr('yamlEditor.saving')
              : preview.mode === 'edit'
              ? tr('rolePermissions.saveNadded', { adds: preview.adds, dels: preview.dels })
              : tr('rolePermissions.addN', { count: preview.total })}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label className="mb-1 block text-[10px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
              {tr('rolePermissions.cluster')}
            </label>
            <NativeSelect
              aria-label={tr('rolePermissions.cluster')}
              value={String(clusterId)}
              onChange={(e) => setClusterId(Number(e.target.value))}
            >
              <option value="0">{tr('rolePermissions.allClusters')}</option>
              {clusters.map((c) => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </NativeSelect>
          </div>
          <div>
            <label className="mb-1 block text-[10px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
              {tr('rolePermissions.namespacesLabel', { count: selectedNs.length })}
            </label>
            <Input
              placeholder={tr('rolePermissions.nsFilter')}
              value={nsFilter}
              onChange={(e) => setNsFilter(e.target.value)}
            />
            {/* Bulk selection buttons — "Select matching" picks every ns the
                current filter is showing, "Clear selection" drops them all.
                Composable with the filter: type "boh", select, type "pos",
                select — ends up with both prefixes without new syntax. */}
            <div className="mt-1 flex items-center gap-2 text-[11px]">
              <button
                type="button"
                onClick={() =>
                  setSelectedNs((prev) =>
                    Array.from(new Set([...prev, ...filteredNamespaces]))
                  )
                }
                disabled={filteredNamespaces.length === 0}
                className="font-medium text-brand-600 hover:underline disabled:text-slate-300 disabled:no-underline dark:text-brand-300 dark:disabled:text-slate-600"
              >
                {tr('rolePermissions.selectMatching', { count: filteredNamespaces.length })}
              </button>
              <span className="text-slate-300 dark:text-slate-700">·</span>
              <button
                type="button"
                onClick={() => setSelectedNs([])}
                disabled={selectedNs.length === 0}
                className="font-medium text-slate-500 hover:text-rose-600 hover:underline disabled:text-slate-400 dark:disabled:text-slate-600 dark:text-slate-400 dark:hover:text-rose-300"
              >
                {tr('rolePermissions.clearSelection')}
              </button>
            </div>
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
                <span className="text-xs text-slate-500 dark:text-slate-400">{tr('rolePermissions.noMatch')}</span>
              )}
            </div>
          </div>
        </div>

        <div>
          <label className="mb-1 block text-[10px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
            {tr('rolePermissions.template')}
          </label>
          <div className="flex flex-wrap gap-1.5">
            {TEMPLATES.map((tplKey) => (
              <button
                key={tplKey}
                type="button"
                onClick={() => applyTemplate(tplKey)}
                className={`rounded-md border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                  template === tplKey
                    ? 'border-brand-400 bg-brand-50 text-brand-700 dark:border-brand-500/50 dark:bg-brand-500/15 dark:text-brand-200'
                    : 'border-slate-200 text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800'
                }`}
              >
                {tr(`rolePermissions.templates.${tplKey}`)}
              </button>
            ))}
          </div>
        </div>

        <PermissionMatrix
          matrix={matrix}
          onChange={(m) => {
            setTemplate(null);
            setMatrix(m);
          }}
          cell={(resource, a) => {
            // Rows where EVERY selected ns already has this (resource, action) will be skipped.
            const everywhereExists =
              selectedNs.length > 0 &&
              selectedNs.every((ns) => existing.has(`${clusterId}:${ns}:${resource}:${a.key}`));
            return everywhereExists
              ? { struck: true, title: tr('rolePermissions.alreadyEverywhere') }
              : {};
          }}
        />

        {preview.mode === 'edit' ? (
          <Alert severity={preview.adds === 0 && preview.dels === 0 ? 'info' : 'success'}>
            {preview.adds === 0 && preview.dels === 0
              ? tr('rolePermissions.noChanges')
              : tr('rolePermissions.editCounter', { adds: preview.adds, dels: preview.dels })}
          </Alert>
        ) : (
          <Alert severity={preview.total === 0 ? 'info' : 'success'}>
            {preview.total === 0
              ? tr('rolePermissions.nothingToAdd')
              : `${tr('rolePermissions.willCreate', { count: preview.total })}${
                  preview.skipped > 0 ? ` · ${tr('rolePermissions.skipped', { count: preview.skipped })}` : ''
                }.`}
          </Alert>
        )}
      </div>
    </Modal>
  );
};
