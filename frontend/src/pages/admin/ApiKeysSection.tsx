import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, Ban, Download } from 'lucide-react';
import Combobox from '../../components/Combobox';
import { confirm } from '../../components/ConfirmDialog';
import { Column, DataTable, IconButton } from '../../components/DataTable';
import { Alert, Badge, Button, Checkbox, NativeSelect } from '../../components/ui';
import { adminRevokeApiKey, exportApiKeysCsv, listAllApiKeys, type AdminApiKey, type User } from '../../services/api';
import { ExpiryBadge, dangerous } from '../apikeys/ApiKeyParts';

type Status = '' | AdminApiKey['status'];

/**
 * Admin → API keys: every user's keys (never a secret, only the prefix). Filter by owner, status, exec,
 * Admin API and "outside the expiry policy"; revoke with an optional comment for the audit log. An admin
 * cannot edit another user's key.
 */
export const ApiKeysSection: React.FC<{ users: User[] }> = ({ users }) => {
  const { t } = useTranslation();
  const [keys, setKeys] = useState<AdminApiKey[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [owner, setOwner] = useState('');
  const [status, setStatus] = useState<Status>('');
  const [exec, setExec] = useState(false);
  const [adminApi, setAdminApi] = useState(false);
  const [outside, setOutside] = useState(false);

  const load = useCallback(async () => {
    try {
      setKeys((await listAllApiKeys()).items);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);

  const rows = useMemo(
    () =>
      (keys ?? []).filter(
        (k) =>
          (!owner || k.owner === owner) &&
          (!status || k.status === status) &&
          (!exec || k.grants.includes('pods:exec')) &&
          (!adminApi || k.adminScope) &&
          (!outside || k.outsidePolicy),
      ),
    [keys, owner, status, exec, adminApi, outside],
  );

  const revoke = async (k: AdminApiKey) => {
    let comment = '';
    const ok = await confirm({
      title: t('adminApiKeys.revokeTitle', { name: k.name, owner: k.owner }),
      message: (
        <div className="space-y-3">
          <p>{t('adminApiKeys.revokeMessage')}</p>
          <label className="flex flex-col gap-1 text-xs font-medium text-slate-600 dark:text-slate-300">
            {t('adminApiKeys.comment')}
            <textarea
              rows={2}
              maxLength={500}
              onChange={(e) => (comment = e.target.value)}
              className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 focus:border-brand-500 focus:outline-none focus:ring-4 focus:ring-brand-500/15 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
            />
          </label>
        </div>
      ),
      confirmText: t('apiKeys.revoke'),
      variant: 'danger',
    });
    if (!ok) return;
    try {
      await adminRevokeApiKey(k.id, comment);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const columns: Column<AdminApiKey>[] = [
    {
      key: 'owner',
      header: t('adminApiKeys.owner'),
      sortValue: (k) => k.owner.toLowerCase(),
      cell: (k) => <span className="font-mono text-[13px] font-medium text-slate-900 dark:text-slate-100">{k.owner}</span>,
    },
    {
      key: 'name',
      header: t('apiKeys.name'),
      sortValue: (k) => k.name.toLowerCase(),
      cell: (k) => <span className="text-sm text-slate-800 dark:text-slate-100">{k.name}</span>,
    },
    {
      key: 'prefix',
      header: t('apiKeys.key'),
      cell: (k) => <code className="font-mono text-xs text-slate-700 dark:text-slate-300">{k.prefix}…</code>,
    },
    {
      key: 'scope',
      header: t('apiKeys.permissions'),
      cell: (k) => (
        <div className="flex flex-wrap items-center gap-1">
          <span className="text-xs text-slate-700 dark:text-slate-200">{t('apiKeys.grantCount', { count: k.grants.length })}</span>
          {dangerous(k.grants, k.adminScope).map((d) => (
            <Badge key={d} variant="error" className="!px-1.5 !py-0 font-mono text-[10px]">
              {d}
            </Badge>
          ))}
          <span className="text-xs text-slate-500 dark:text-slate-400">
            · {k.allNamespaces ? t('apiKeys.allNamespacesShort') : t('apiKeys.nsCount', { count: k.namespaces.length })}
          </span>
        </div>
      ),
    },
    {
      key: 'lastUsed',
      header: t('apiKeys.lastUsed'),
      sortValue: (k) => k.lastUsedAt ?? '',
      descFirst: true,
      cell: (k) =>
        k.lastUsedAt ? (
          <span className="text-xs text-slate-600 dark:text-slate-300">
            {new Date(k.lastUsedAt).toLocaleString()}
            {k.lastUsedIp && <span className="block font-mono text-[11px] text-slate-500 dark:text-slate-400">{k.lastUsedIp}</span>}
          </span>
        ) : (
          <span className="text-xs text-slate-500 dark:text-slate-400">—</span>
        ),
    },
    {
      key: 'expiry',
      header: t('apiKeys.expiry'),
      sortValue: (k) => k.revokedAt ?? k.expiresAt ?? '9999',
      cell: (k) => (
        <div className="flex flex-wrap items-center gap-1">
          <ExpiryBadge apiKey={k} />
          {k.outsidePolicy && (
            <span title={t('adminApiKeys.outsidePolicyHint')}>
              <Badge variant="warning" className="!px-1.5 !py-0 text-[10px]">
                <AlertTriangle size={10} aria-hidden="true" />
                {t('adminApiKeys.outsidePolicy')}
              </Badge>
            </span>
          )}
        </div>
      ),
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      width: '60px',
      cell: (k) =>
        k.status === 'active' ? (
          <IconButton label={t('adminApiKeys.revokeLabel', { name: k.name, owner: k.owner })} variant="danger" onClick={() => void revoke(k)}>
            <Ban size={14} />
          </IconButton>
        ) : null,
    },
  ];

  const owners = useMemo(() => [...new Set([...(keys ?? []).map((k) => k.owner), ...users.map((u) => u.username)])].sort(), [keys, users]);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end gap-3">
        <Combobox label={t('adminApiKeys.owner')} value={owner} options={owners} onChange={(v) => setOwner(v)} className="w-52" />
        <NativeSelect label={t('adminApiKeys.status')} value={status} onChange={(e) => setStatus(e.target.value as Status)} className="w-40">
          <option value="">{t('adminApiKeys.statusAll')}</option>
          <option value="active">{t('adminApiKeys.statusActive')}</option>
          <option value="expired">{t('apiKeys.expired')}</option>
          <option value="revoked">{t('apiKeys.revoked')}</option>
        </NativeSelect>
        <div className="flex flex-wrap items-center gap-4 pb-2">
          <Checkbox checked={exec} onChange={setExec} label={t('adminApiKeys.withExec')} />
          <Checkbox checked={adminApi} onChange={setAdminApi} label={t('apiKeys.adminApi')} />
          <Checkbox checked={outside} onChange={setOutside} label={t('adminApiKeys.outsidePolicy')} />
        </div>
        <Button variant="outline" size="sm" className="ml-auto" onClick={() => void exportApiKeysCsv().catch((e) => setError(String(e)))}>
          <Download size={14} />
          {t('admin.exportCsv')}
        </Button>
      </div>
      {error && <Alert severity="error">{error}</Alert>}
      <DataTable
        keyboardNav
        rows={rows}
        columns={columns}
        rowKey={(k) => k.id}
        sortStorageKey="adminApiKeysSort"
        emptyMessage={keys === null ? t('common.loading') : t('adminApiKeys.empty')}
      />
    </div>
  );
};

export default ApiKeysSection;
