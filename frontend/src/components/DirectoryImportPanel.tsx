import React, { useState } from 'react';
import { Check, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Input, MultiSelect, MultiSelectOption, Spinner } from './ui';
import {
  errorText,
  ImportAnswer,
  importAzureUsers,
  importLdapUsers,
  ImportResult,
  searchAzureUsers,
  searchLdapUsers,
} from '../services/api';

/** A person found in the directory; key is what the import call takes (LDAP: username, Azure AD: object id). */
export type DirectoryEntry = { key: string; label: string; detail?: string; exists?: boolean };

type Props = {
  help: string;
  search: (query: string) => Promise<DirectoryEntry[]>;
  importKeys: (keys: string[], groupIds: number[]) => Promise<ImportAnswer>;
  groups: Array<{ id: number; name: string }>;
  /** Called after an import with the new usernames (e.g. to reload and highlight them). */
  onImported: (created: string[]) => void | Promise<void>;
  /** Wraps a search error (Azure AD: "Graph unreachable … or enter the name by hand"). */
  renderSearchError?: (message: string) => React.ReactNode;
};

/**
 * Search a directory, collect people in a basket across searches, import them,
 * optionally straight into groups. LDAP (Admin → LDAP, New user → LDAP) and
 * Azure AD (New user → Azure AD with the directory search on).
 */
const DirectoryImportPanel: React.FC<Props> = ({ help, search, importKeys, groups, onImported, renderSearchError }) => {
  const { t } = useTranslation();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<DirectoryEntry[] | null>(null);
  const [basket, setBasket] = useState<DirectoryEntry[]>([]);
  const [groupIds, setGroupIds] = useState<number[]>([]);
  const [busy, setBusy] = useState<'' | 'search' | 'import'>('');
  const [error, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<Array<ImportResult & { label: string }>>([]);

  const picked = (key: string) => basket.some((e) => e.key === key);
  const toggle = (e: DirectoryEntry) =>
    setBasket((b) => (b.some((x) => x.key === e.key) ? b.filter((x) => x.key !== e.key) : [...b, e]));

  const runSearch = async () => {
    setBusy('search');
    setError(null);
    try {
      setResults(await search(query));
    } catch (err) {
      setResults(null);
      setError((err as Error).message);
    } finally {
      setBusy('');
    }
  };

  const runImport = async () => {
    if (basket.length === 0) return;
    setBusy('import');
    setError(null);
    try {
      const answer = await importKeys(basket.map((e) => e.key), groupIds);
      const byKey = new Map((answer.results ?? []).map((r) => [r.id ?? r.username, r]));
      setOutcome(basket.map((e) => ({ ...(byKey.get(e.key) ?? { username: e.label, status: 'failed' as const }), label: e.label })));
      // Created or already there: out of the basket and no longer pickable; a failure stays for another try.
      const done = new Set(basket.filter((e) => byKey.get(e.key)?.status !== 'failed' && byKey.has(e.key)).map((e) => e.key));
      setBasket((b) => b.filter((e) => !done.has(e.key)));
      setResults((r) => r?.map((e) => (done.has(e.key) ? { ...e, exists: true } : e)) ?? null);
      await onImported(answer.createdUsers ?? []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy('');
    }
  };

  const reasonText = (r: ImportResult) => (r.reason === 'exists' ? t('directoryImport.exists') : r.reason ? errorText(r.reason) : '');

  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-slate-500 dark:text-slate-400">{help}</p>
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          void runSearch();
        }}
      >
        <Input label={t('common.searchQuery')} value={query} onChange={(e) => setQuery(e.target.value)} className="w-60" autoFocus />
        <Button type="submit" variant="outline" disabled={busy !== ''}>
          {busy === 'search' ? (
            <span className="flex items-center gap-2">
              <Spinner size="sm" />
              {t('directoryImport.searching')}
            </span>
          ) : (
            t('directoryImport.search')
          )}
        </Button>
      </form>

      {error && (renderSearchError && busy === '' && results === null ? renderSearchError(error) : <Alert severity="error">{error}</Alert>)}

      {results && results.length === 0 && <p className="text-sm text-slate-500 dark:text-slate-400">{t('directoryImport.noResults')}</p>}
      {results && results.length > 0 && (
        <fieldset className="max-h-60 overflow-y-auto rounded-lg border border-slate-200 dark:border-slate-700" tabIndex={-1}>
          <legend className="sr-only">{t('directoryImport.results')}</legend>
          {results.map((e) => (
            <label
              key={e.key}
              className={`flex items-start gap-2 border-b border-slate-100 px-3 py-2 text-sm last:border-b-0 dark:border-slate-800 ${
                e.exists ? 'cursor-not-allowed opacity-60' : 'cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/60'
              }`}
            >
              <input
                type="checkbox"
                className="mt-0.5 h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500 dark:border-slate-600"
                checked={picked(e.key)}
                disabled={e.exists}
                onChange={() => toggle(e)}
              />
              <span className="flex min-w-0 flex-col">
                <span className="truncate font-medium text-slate-900 dark:text-slate-100">{e.label}</span>
                {(e.detail || e.exists) && (
                  <span className="truncate text-xs text-slate-500 dark:text-slate-400">
                    {e.exists ? t('directoryImport.exists') : e.detail}
                  </span>
                )}
              </span>
            </label>
          ))}
        </fieldset>
      )}

      <div className="flex flex-col gap-1.5">
        <span className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400" id="directory-basket">
          {t('directoryImport.selected', { count: basket.length })}
        </span>
        {basket.length === 0 ? (
          <p className="text-xs text-slate-500 dark:text-slate-400">{t('directoryImport.selectedEmpty')}</p>
        ) : (
          <ul className="flex flex-wrap gap-1.5" aria-labelledby="directory-basket">
            {basket.map((e) => (
              <li
                key={e.key}
                className="inline-flex items-center gap-1 rounded-md bg-brand-50 px-2 py-0.5 text-xs font-medium text-brand-700 ring-1 ring-inset ring-brand-200 dark:bg-brand-500/15 dark:text-brand-200 dark:ring-brand-500/30"
              >
                {e.label}
                <button
                  type="button"
                  onClick={() => toggle(e)}
                  aria-label={t('directoryImport.remove', { name: e.label })}
                  className="rounded p-0.5 hover:bg-brand-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/40 dark:hover:bg-brand-500/25"
                >
                  <X size={12} aria-hidden="true" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      <MultiSelect
        label={t('ldapImport.groups')}
        options={groups.map((g) => ({ id: g.id, label: g.name }))}
        value={groups.filter((g) => groupIds.includes(g.id)).map((g) => ({ id: g.id, label: g.name }))}
        onChange={(value: MultiSelectOption[]) => setGroupIds(value.map((v) => Number(v.id)))}
        noOptionsText={t('ldapImport.noGroups')}
        placeholder={t('ldapImport.groupsPlaceholder')}
      />

      {outcome.length > 0 && (
        <ul className="flex flex-col gap-1 text-xs" aria-live="polite">
          {outcome.map((r) => (
            <li key={r.label} className="flex items-start gap-1.5">
              {r.status === 'created' ? (
                <Check size={14} className="mt-px shrink-0 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
              ) : (
                <X size={14} className={`mt-px shrink-0 ${r.status === 'failed' ? 'text-rose-500' : 'text-amber-500'}`} aria-hidden="true" />
              )}
              <span className="text-slate-700 dark:text-slate-300">
                <span className="font-medium">{r.username}</span>: {t(`directoryImport.status.${r.status}`)}
                {reasonText(r) && ` (${reasonText(r)})`}
              </span>
            </li>
          ))}
        </ul>
      )}

      <div>
        <Button variant="primary" size="sm" onClick={() => void runImport()} disabled={basket.length === 0 || busy !== ''}>
          {busy === 'import' ? t('directoryImport.importing') : t('directoryImport.import', { count: basket.length })}
        </Button>
      </div>
    </div>
  );
};

export default DirectoryImportPanel;

type Groups = Array<{ id: number; name: string }>;
type Imported = (created: string[]) => void | Promise<void>;

/** LDAP: search by name, import by username. */
export const LdapImport: React.FC<{ groups: Groups; onImported: Imported }> = ({ groups, onImported }) => {
  const { t } = useTranslation();
  return (
    <DirectoryImportPanel
      help={t('ldapImport.help')}
      groups={groups}
      onImported={onImported}
      search={async (q) =>
        ((await searchLdapUsers(q)).items ?? []).map((u) => ({ key: u.username, label: u.username, detail: u.dn, exists: u.exists }))
      }
      importKeys={importLdapUsers}
    />
  );
};

/** Azure AD (directory search on): search Entra ID, import by object id; a Graph error offers the typed-name form. */
export const AzureImport: React.FC<{ groups: Groups; onImported: Imported; onManual: () => void }> = ({ groups, onImported, onManual }) => {
  const { t } = useTranslation();
  return (
    <DirectoryImportPanel
      help={t('azureImport.help')}
      groups={groups}
      onImported={onImported}
      search={async (q) =>
        ((await searchAzureUsers(q)).items ?? []).map((u) => ({
          key: u.id,
          label: u.username || u.userPrincipalName,
          detail: [u.displayName, u.mail && u.mail !== u.username ? u.mail : ''].filter(Boolean).join(' · '),
          exists: u.exists,
        }))
      }
      importKeys={importAzureUsers}
      renderSearchError={(message) => (
        <Alert severity="error">
          {t('azureImport.graphFailed', { reason: message })}{' '}
          <button type="button" onClick={onManual} className="font-medium underline underline-offset-2 hover:no-underline">
            {t('azureImport.manual')}
          </button>
        </Alert>
      )}
    />
  );
};
