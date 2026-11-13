import React from 'react';
import { useTranslation } from 'react-i18next';
import { Checkbox } from './ui';

// ─── Catalog ────────────────────────────────────────────────────────────────
//
// The set of resource/action pairs that mean something on this backend. The
// backend's rbac.Catalog is the source of truth; keep these in sync (small
// list, hand-edited). Used by Role Permissions and API keys.

export type ActionFamily = 'read' | 'write' | 'destructive';
export type ActionDef = { key: string; family: ActionFamily };
export type Matrix = Record<string, Record<string, boolean>>;

// `edit` is destructive (full YAML write via server dry-run + apply). Scale /
// restart are "write" because they only change the obvious thing. logs/exec
// stay as read/destructive — exec can still mutate pod state via a shell.
export const RESOURCE_CATALOG: Array<{ resource: string; actions: ActionDef[] }> = [
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
  // list/get expose names, types and key names only; reveal returns values
  // and edit opens the full YAML (values included) — both audited, both in
  // the destructive (red) family, so only the Admin template has them.
  { resource: 'secrets', actions: [
    { key: 'list', family: 'read' },
    { key: 'get', family: 'read' },
    { key: 'reveal', family: 'destructive' },
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

export const FAMILY_CLASS: Record<ActionFamily, string> = {
  read:
    'bg-slate-100 text-slate-700 ring-1 ring-inset ring-slate-200 dark:bg-slate-800 dark:text-slate-200 dark:ring-slate-700',
  write:
    'bg-amber-50 text-amber-800 ring-1 ring-inset ring-amber-200 dark:bg-amber-500/15 dark:text-amber-200 dark:ring-amber-500/30',
  destructive:
    'bg-rose-50 text-rose-700 ring-1 ring-inset ring-rose-200 dark:bg-rose-500/15 dark:text-rose-200 dark:ring-rose-500/30',
};

export const emptyMatrix = (): Matrix =>
  Object.fromEntries(
    RESOURCE_CATALOG.map((r) => [r.resource, Object.fromEntries(r.actions.map((a) => [a.key, false]))])
  );

/** How one cell looks besides on / off: closed (with why), struck through, or marked partial. */
export type CellState = { disabled?: boolean; struck?: boolean; partial?: string; title?: string };

/**
 * Resource rows × action toggles (aria-pressed), colored by family. The row
 * checkbox flips every enabled action of the resource.
 */
export const PermissionMatrix: React.FC<{
  matrix: Matrix;
  onChange: (m: Matrix) => void;
  cell?: (resource: string, action: ActionDef) => CellState;
}> = ({ matrix, onChange, cell = (): CellState => ({}) }) => {
  const { t } = useTranslation();
  const set = (resource: string, keys: string[], on: boolean) =>
    onChange({ ...matrix, [resource]: { ...matrix[resource], ...Object.fromEntries(keys.map((k) => [k, on])) } });
  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-800">
      <table className="w-full text-sm">
        <thead className="bg-slate-50 text-left text-[10px] font-semibold text-slate-500 dark:bg-slate-900/70 dark:text-slate-400">
          <tr>
            <th className="px-3 py-2">{t('common.resource')}</th>
            <th className="px-3 py-2 text-right">{t('common.actions')}</th>
          </tr>
        </thead>
        <tbody>
          {RESOURCE_CATALOG.map(({ resource, actions }) => {
            const open = actions.filter((a) => !cell(resource, a).disabled);
            const allOn = open.length > 0 && open.every((a) => matrix[resource]?.[a.key]);
            const anyOn = actions.some((a) => matrix[resource]?.[a.key]);
            return (
              <tr key={resource} className="border-t border-slate-100 dark:border-slate-800">
                <td className="px-3 py-2">
                  <Checkbox
                    label={resource}
                    className="font-mono"
                    checked={allOn}
                    indeterminate={anyOn && !allOn}
                    disabled={open.length === 0}
                    onChange={(v) => set(resource, open.map((a) => a.key), v)}
                  />
                </td>
                <td className="px-3 py-2">
                  <div className="flex flex-wrap justify-end gap-1.5">
                    {actions.map((a) => {
                      const on = !!matrix[resource]?.[a.key];
                      const st = cell(resource, a);
                      return (
                        <button
                          key={a.key}
                          type="button"
                          aria-pressed={on}
                          aria-label={`${resource} ${a.key}${st.title ? ` — ${st.title}` : ''}`}
                          disabled={st.disabled}
                          onClick={() => set(resource, [a.key], !on)}
                          className={`inline-flex items-center gap-1 rounded px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide transition-all disabled:cursor-not-allowed disabled:opacity-40 ${
                            on
                              ? FAMILY_CLASS[a.family]
                              : 'bg-white text-slate-500 ring-1 ring-inset ring-slate-200 hover:bg-slate-50 dark:bg-slate-900 dark:text-slate-400 dark:ring-slate-700 dark:hover:bg-slate-800'
                          } ${st.struck ? 'opacity-50 line-through' : ''}`}
                          title={st.title ?? a.family}
                        >
                          {a.key}
                          {st.partial && (
                            <span className="rounded bg-amber-100 px-1 text-[9px] normal-case text-amber-800 dark:bg-amber-500/20 dark:text-amber-200">
                              {st.partial}
                            </span>
                          )}
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
  );
};
