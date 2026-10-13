import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Input, MultiSelect, MultiSelectOption, Spinner } from './ui';
import { importLdapUsers, searchLdapUsers } from '../services/api';

type Props = {
  groups: Array<{ id: number; name: string }>;
  /** Called after a successful import (e.g. to reload the user list). */
  onImported: () => void | Promise<void>;
};

/**
 * Search the directory, pick users and import them as LDAP accounts,
 * optionally straight into groups. Used in Admin → LDAP and in the
 * "Import from LDAP" dialog on Admin → Users.
 */
const LdapImportPanel: React.FC<Props> = ({ groups, onImported }) => {
  const { t } = useTranslation();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<Array<{ username: string; dn: string }>>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [groupIds, setGroupIds] = useState<number[]>([]);
  const [searching, setSearching] = useState(false);
  const [importing, setImporting] = useState(false);
  const [searched, setSearched] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  const search = async () => {
    setSearching(true);
    setError(null);
    setDone(null);
    try {
      const result = await searchLdapUsers(query);
      setResults(result.items ?? []);
      setSelected([]);
      setSearched(true);
    } catch (err) {
      setResults([]);
      setError((err as Error).message || t('ldapImport.searchFailed'));
    } finally {
      setSearching(false);
    }
  };

  const doImport = async () => {
    if (selected.length === 0) return;
    setImporting(true);
    setError(null);
    try {
      const result = await importLdapUsers(selected, groupIds);
      const skipped = result.skippedExisting?.length ?? 0;
      setDone(
        skipped > 0
          ? `${t('ldapImport.imported', { count: result.created })} ${t('ldapImport.skipped', { count: skipped })}`
          : t('ldapImport.imported', { count: result.created }),
      );
      setSelected([]);
      setResults([]);
      setQuery('');
      setSearched(false);
      await onImported();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setImporting(false);
    }
  };

  const option = (u: { username: string; dn: string }) => ({ id: u.username, label: `${u.username} (${u.dn})` });

  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-slate-500 dark:text-slate-400">{t('ldapImport.help')}</p>
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          void search();
        }}
      >
        <Input
          label={t('common.searchQuery')}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="w-60"
          autoFocus
        />
        <Button type="submit" variant="outline" size="sm" disabled={searching}>
          {searching ? (
            <span className="flex items-center gap-2">
              <Spinner size="sm" />
              {t('ldapImport.searching')}
            </span>
          ) : (
            t('ldapImport.search')
          )}
        </Button>
      </form>

      {searched && results.length === 0 && !error && (
        <p className="text-sm text-slate-500 dark:text-slate-400">{t('ldapImport.noResults')}</p>
      )}

      {results.length > 0 && (
        <>
          <MultiSelect
            label={t('common.ldapUsers')}
            options={results.map(option)}
            value={results.filter((u) => selected.includes(u.username)).map(option)}
            onChange={(value: MultiSelectOption[]) => setSelected(value.map((v) => String(v.id)))}
            noOptionsText={t('ldapImport.noResults')}
            placeholder={t('common.selectToImport')}
          />
          <MultiSelect
            label={t('ldapImport.groups')}
            options={groups.map((g) => ({ id: g.id, label: g.name }))}
            value={groups.filter((g) => groupIds.includes(g.id)).map((g) => ({ id: g.id, label: g.name }))}
            onChange={(value: MultiSelectOption[]) => setGroupIds(value.map((v) => Number(v.id)))}
            noOptionsText={t('ldapImport.noGroups')}
            placeholder={t('ldapImport.groupsPlaceholder')}
          />
        </>
      )}

      {error && <Alert severity="error">{error}</Alert>}
      {done && <Alert severity="success">{done}</Alert>}

      <div>
        <Button variant="primary" size="sm" onClick={() => void doImport()} disabled={selected.length === 0 || importing}>
          {t('ldapImport.importSelected', { count: selected.length })}
        </Button>
      </div>
    </div>
  );
};

export default LdapImportPanel;
