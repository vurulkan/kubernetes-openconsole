import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Input, NativeSelect } from '../../components/ui';
import Combobox from '../../components/Combobox';
import { AuditEntryRow } from '../../components/AuditEntryRow';
import {
  exportAuditLogs,
  getAuditFacets,
  listAuditLogs,
  type AuditEntry,
  type AuditFacets,
  type AuditQuery,
} from '../../services/api';

/** The audit filters plus the page; kept by AdminPage so they survive a tab switch. */
export type AuditFilters = AuditQuery & { offset: number };

export const emptyAuditFilters: AuditFilters = {
  user: '',
  action: '',
  actionExact: false,
  verb: '',
  outcome: '',
  resourceType: '',
  cluster: '',
  source: '',
  apiKey: '',
  namespace: '',
  start: '',
  end: '',
  offset: 0,
};

const emptyFacets: AuditFacets = {
  actions: [],
  users: [],
  namespaces: [],
  verbs: [],
  resourceTypes: [],
  clusters: [],
  apiKeys: [],
};

const PAGE = 50;
// Typing in a filter waits this long before asking the server.
export const AUDIT_DEBOUNCE_MS = 300;

/**
 * Admin → Audit Logs. Loads only the audit list: one request per filter change
 * (debounced), and an answer for an older filter never replaces a newer one.
 */
export const AuditSection: React.FC<{
  filters: AuditFilters;
  onChange: (filters: AuditFilters) => void;
}> = ({ filters, onChange }) => {
  const { t: tr } = useTranslation();
  const [logs, setLogs] = useState<AuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [facets, setFacets] = useState<AuditFacets>(emptyFacets);
  const [error, setError] = useState<string | null>(null);

  // Suggestions for the filters, loaded each time the section opens.
  useEffect(() => {
    getAuditFacets()
      .then(setFacets)
      .catch(() => setFacets(emptyFacets));
  }, []);

  useEffect(() => {
    let live = true;
    const { offset, ...query } = filters;
    const timer = window.setTimeout(() => {
      listAuditLogs(PAGE, offset, query)
        .then((r) => {
          if (!live) return;
          setLogs(r.items ?? []);
          setTotal(r.total ?? 0);
          setError(null);
        })
        .catch((err) => live && setError((err as Error).message));
    }, AUDIT_DEBOUNCE_MS);
    return () => {
      live = false;
      window.clearTimeout(timer);
    };
  }, [filters]);

  // A filter change goes back to the first page.
  const set = (patch: Partial<AuditFilters>) => onChange({ ...filters, offset: 0, ...patch });
  const { offset } = filters;

  const handleExport = async () => {
    const { offset: _offset, ...query } = filters;
    try {
      await exportAuditLogs(query);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <>
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <Combobox
          label={tr('admin.audit.filterUser')}
          value={filters.user ?? ''}
          options={facets.users}
          onChange={(v) => set({ user: v })}
          className="w-44"
        />
        <Combobox
          label={tr('admin.audit.filterAction')}
          value={filters.action ?? ''}
          options={facets.actions}
          families
          placeholder={tr('admin.audit.actionPlaceholder')}
          onChange={(v, mode) => set({ action: v, actionExact: mode === 'exact' })}
          className="w-64"
        />
        <NativeSelect
          label={tr('admin.audit.filterOutcome')}
          value={filters.outcome ?? ''}
          onChange={(e) => set({ outcome: e.target.value as AuditQuery['outcome'] })}
        >
          <option value="">{tr('admin.audit.outcomeAny')}</option>
          <option value="success">success</option>
          <option value="denied">denied</option>
          <option value="failed">failed</option>
          <option value="rate_limited">rate_limited</option>
          <option value="locked">locked</option>
        </NativeSelect>
        <NativeSelect
          label={tr('admin.audit.filterVerb')}
          value={filters.verb ?? ''}
          onChange={(e) => set({ verb: e.target.value })}
        >
          <option value="">{tr('admin.audit.outcomeAny')}</option>
          {facets.verbs.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </NativeSelect>
        <NativeSelect
          label={tr('admin.audit.filterResourceType')}
          value={filters.resourceType ?? ''}
          onChange={(e) => set({ resourceType: e.target.value })}
        >
          <option value="">{tr('admin.audit.outcomeAny')}</option>
          {facets.resourceTypes.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </NativeSelect>
        <NativeSelect
          label={tr('admin.audit.cluster')}
          value={filters.cluster ?? ''}
          onChange={(e) => set({ cluster: e.target.value })}
        >
          <option value="">{tr('admin.audit.outcomeAny')}</option>
          {facets.clusters.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </NativeSelect>
        <NativeSelect
          label={tr('admin.audit.filterSource')}
          value={filters.source ?? ''}
          onChange={(e) => {
            const source = e.target.value as AuditQuery['source'];
            set(source === 'api_key' ? { source } : { source, apiKey: '' });
          }}
        >
          <option value="">{tr('admin.audit.outcomeAny')}</option>
          <option value="web">{tr('admin.audit.sourceWeb')}</option>
          <option value="api_key">{tr('admin.audit.sourceApiKey')}</option>
        </NativeSelect>
        {filters.source === 'api_key' && (
          <Combobox
            label={tr('admin.audit.filterApiKey')}
            value={filters.apiKey ?? ''}
            options={facets.apiKeys ?? []}
            onChange={(v) => set({ apiKey: v })}
            className="w-44"
          />
        )}
        <Combobox
          label={tr('admin.audit.filterNamespace')}
          value={filters.namespace ?? ''}
          options={facets.namespaces}
          onChange={(v) => set({ namespace: v })}
          className="w-44"
        />
        <Input
          label={tr('admin.audit.filterStart')}
          type="date"
          value={filters.start ?? ''}
          onChange={(e) => set({ start: e.target.value })}
        />
        <Input
          label={tr('admin.audit.filterEnd')}
          type="date"
          value={filters.end ?? ''}
          onChange={(e) => set({ end: e.target.value })}
        />
        <div className="flex items-end gap-3">
          <span className="text-xs text-slate-500 dark:text-slate-400">
            {tr('admin.audit.pageOf', { from: offset + 1, to: Math.min(offset + PAGE, total), total })}
          </span>
          <Button variant="outline" size="sm" onClick={handleExport}>
            {tr('admin.audit.exportCsv')}
          </Button>
        </div>
      </div>

      {error && (
        <Alert severity="error" className="mb-3">
          {error}
        </Alert>
      )}

      <div className="flex flex-col gap-2">
        {logs.map((entry) => (
          <AuditEntryRow key={entry.id} entry={entry} />
        ))}
      </div>

      <div className="mt-4 flex gap-2">
        <Button
          variant="outline"
          size="sm"
          disabled={offset === 0}
          onClick={() => onChange({ ...filters, offset: Math.max(0, offset - PAGE) })}
        >
          {tr('admin.audit.prev')}
        </Button>
        <Button
          variant="outline"
          size="sm"
          disabled={offset + PAGE >= total}
          onClick={() => onChange({ ...filters, offset: offset + PAGE })}
        >
          {tr('admin.audit.next')}
        </Button>
      </div>
    </>
  );
};
