import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, KeyRound, MoreHorizontal, Pencil, Plus, RefreshCw, Ban, Trash2 } from 'lucide-react';
import Layout from '../components/Layout';
import { DataTable, type Column } from '../components/DataTable';
import { MenuPopover, menuItemClass } from '../components/MenuPopover';
import { confirm } from '../components/ConfirmDialog';
import { Alert, Badge, Button, Modal, Spinner } from '../components/ui';
import {
  deleteApiKey,
  getApiKeyCeiling,
  listApiKeys,
  regenerateApiKey,
  revokeApiKey,
  type ApiKey,
  type ApiKeyCeiling,
  type User,
} from '../services/api';
import { ageShort } from '../utils/age';
import {
  ExpiryBadge,
  ExpiryPicker,
  SecretBox,
  classify,
  dangerous,
  expiryFromChoice,
  expiryState,
  type ExpiryChoice,
} from './apikeys/ApiKeyParts';

/** Every grant the ceiling holds somewhere, for naming a key "all my permissions". */
const ceilingGrants = (c: ApiKeyCeiling | null) => new Set(c?.namespaces.flatMap((n) => n.grants) ?? []);

const isLive = (k: ApiKey) => expiryState(k).kind === 'active' || expiryState(k).kind === 'never';

/** /account/api-keys: the caller's own keys for agents and scripts. */
const ApiKeysPage: React.FC<{ user: User }> = ({ user }) => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [keys, setKeys] = useState<ApiKey[] | null>(null);
  const [ceiling, setCeiling] = useState<ApiKeyCeiling | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [menu, setMenu] = useState<{ key: ApiKey; anchor: HTMLElement } | null>(null);
  const [regen, setRegen] = useState<ApiKey | null>(null);
  const [secret, setSecret] = useState<{ value: string; cluster?: string } | null>(null);

  const load = useCallback(async () => {
    try {
      const [list, c] = await Promise.all([listApiKeys(), getApiKeyCeiling()]);
      setKeys(list.items);
      setCeiling(c);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setKeys([]);
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);

  const available = useMemo(() => ceilingGrants(ceiling), [ceiling]);
  const clusterName = (k: ApiKey) =>
    k.clusters.includes(0) ? ceiling?.clusters[0]?.name : ceiling?.clusters.find((c) => c.id === k.clusters[0])?.name;

  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const revoke = async (k: ApiKey) => {
    const ok = await confirm({
      title: t('apiKeys.revokeTitle', { name: k.name }),
      message: t('apiKeys.revokeMessage'),
      confirmText: t('apiKeys.revoke'),
      variant: 'danger',
    });
    if (ok) await act(() => revokeApiKey(k.id));
  };
  const remove = async (k: ApiKey) => {
    const ok = await confirm({
      title: t('apiKeys.deleteTitle', { name: k.name }),
      message: isLive(k) ? t('apiKeys.deleteLiveMessage') : t('apiKeys.deleteMessage'),
      confirmText: t('actions.delete'),
      variant: 'danger',
    });
    if (ok) await act(() => deleteApiKey(k.id));
  };

  const columns: Column<ApiKey>[] = [
    {
      key: 'name',
      header: t('apiKeys.name'),
      sortValue: (k) => k.name.toLowerCase(),
      cell: (k) => <span className="font-medium text-slate-900 dark:text-slate-100">{k.name}</span>,
    },
    {
      key: 'note',
      header: t('apiKeys.note'),
      cell: (k) => <span className="line-clamp-1 text-xs text-slate-500 dark:text-slate-400">{k.note}</span>,
    },
    {
      key: 'prefix',
      header: t('apiKeys.key'),
      cell: (k) => <code className="font-mono text-xs text-slate-700 dark:text-slate-300">{k.prefix}…</code>,
    },
    {
      key: 'scope',
      header: t('apiKeys.permissions'),
      cell: (k) => {
        const invalid = k.invalidGrants ?? [];
        return (
          <div className="flex flex-wrap items-center gap-1">
            <span className="text-xs text-slate-700 dark:text-slate-200">{t(`apiKeys.templates.${classify(k.grants, available)}`)}</span>
            {dangerous(k.grants, k.adminScope).map((d) => (
              <Badge key={d} variant="error" className="!px-1.5 !py-0 font-mono text-[10px]">
                {d}
              </Badge>
            ))}
            <span className="text-xs text-slate-500 dark:text-slate-400">
              · {k.allNamespaces ? t('apiKeys.allNamespacesShort') : t('apiKeys.nsCount', { count: k.namespaces.length })}
            </span>
            {invalid.length > 0 && (
              <span title={t('apiKeys.invalidHint', { grants: invalid.join(', ') })}>
                <Badge variant="warning" className="!px-1.5 !py-0 text-[10px]">
                  <AlertTriangle size={10} aria-hidden="true" />
                  {t('apiKeys.invalidCount', { count: invalid.length })}
                </Badge>
              </span>
            )}
          </div>
        );
      },
    },
    {
      key: 'lastUsed',
      header: t('apiKeys.lastUsed'),
      sortValue: (k) => (k.lastUsedAt ? Date.parse(k.lastUsedAt) : 0),
      descFirst: true,
      cell: (k) =>
        k.lastUsedAt ? (
          <span className="text-xs text-slate-600 dark:text-slate-300" title={`${new Date(k.lastUsedAt).toLocaleString()} · ${k.lastUsedIp}`}>
            {t('apiKeys.ago', { age: ageShort(k.lastUsedAt) })}
          </span>
        ) : (
          <span className="text-xs text-slate-500 dark:text-slate-400">—</span>
        ),
    },
    {
      key: 'expiry',
      header: t('apiKeys.expiry'),
      sortValue: (k) => (k.revokedAt ? -2 : k.expiresAt ? Date.parse(k.expiresAt) : Number.MAX_SAFE_INTEGER),
      cell: (k) => <ExpiryBadge apiKey={k} />,
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      cell: (k) => (
        <button
          type="button"
          aria-label={t('apiKeys.actionsFor', { name: k.name })}
          aria-haspopup="menu"
          onClick={(e) => {
            e.stopPropagation();
            setMenu({ key: k, anchor: e.currentTarget });
          }}
          className="inline-flex h-7 w-7 cursor-pointer items-center justify-center rounded-md text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/40 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100"
        >
          <MoreHorizontal size={16} />
        </button>
      ),
    },
  ];

  return (
    <Layout user={user}>
      <div className="flex flex-col gap-4">
        <header className="flex flex-wrap items-start gap-x-4 gap-y-2">
          <div>
            <h1 className="flex items-center gap-2 text-lg font-semibold tracking-tight text-slate-900 dark:text-slate-50">
              <KeyRound size={20} className="text-brand-500" aria-hidden="true" />
              {t('apiKeys.title')}
            </h1>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{t('apiKeys.subtitle')}</p>
          </div>
          <Button className="ml-auto" size="sm" onClick={() => navigate('/account/api-keys/new')}>
            <Plus size={14} />
            {t('apiKeys.new')}
          </Button>
        </header>

        {error && <Alert severity="error">{error}</Alert>}
        {secret && <SecretBox secret={secret.value} cluster={secret.cluster} />}

        {keys === null ? (
          <div className="flex justify-center py-10">
            <Spinner />
          </div>
        ) : keys.length === 0 && !error ? (
          <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed border-slate-300 px-6 py-12 text-center dark:border-slate-700">
            <KeyRound size={28} className="text-slate-400" aria-hidden="true" />
            <p className="max-w-md text-sm text-slate-600 dark:text-slate-400">{t('apiKeys.empty')}</p>
            <Button size="sm" onClick={() => navigate('/account/api-keys/new')}>
              <Plus size={14} />
              {t('apiKeys.createFirst')}
            </Button>
          </div>
        ) : (
          <DataTable
            rows={keys}
            columns={columns}
            rowKey={(k) => k.id}
            keyboardNav
            sortStorageKey="apiKeys"
            onRowClick={(k) => {
              if (isLive(k)) navigate(`/account/api-keys/${k.id}`);
            }}
          />
        )}
      </div>

      {menu && (
        <MenuPopover anchor={menu.anchor} label={t('apiKeys.actionsFor', { name: menu.key.name })} onClose={() => setMenu(null)} className="w-48">
          {[
            ...(isLive(menu.key)
              ? [{ id: 'edit', icon: Pencil, label: t('actions.edit'), run: () => navigate(`/account/api-keys/${menu.key.id}`) }]
              : []),
            { id: 'regen', icon: RefreshCw, label: t('apiKeys.regenerate'), run: () => setRegen(menu.key) },
            ...(menu.key.revokedAt || !isLive(menu.key) ? [] : [{ id: 'revoke', icon: Ban, label: t('apiKeys.revoke'), run: () => void revoke(menu.key) }]),
            { id: 'delete', icon: Trash2, label: t('actions.delete'), run: () => void remove(menu.key) },
          ].map((item) => (
            <button
              key={item.id}
              type="button"
              role="menuitem"
              className={`${menuItemClass} ${item.id === 'revoke' || item.id === 'delete' ? '!text-rose-600 dark:!text-rose-300' : ''}`}
              onClick={() => {
                const anchor = menu.anchor;
                setMenu(null);
                anchor.focus();
                item.run();
              }}
            >
              <item.icon size={14} aria-hidden="true" />
              {item.label}
            </button>
          ))}
        </MenuPopover>
      )}

      {regen && (
        <RegenerateModal
          apiKey={regen}
          onClose={() => setRegen(null)}
          onDone={(value) => {
            setSecret({ value, cluster: clusterName(regen) });
            setRegen(null);
            void load();
          }}
        />
      )}
    </Layout>
  );
};

/** New secret + new expiry; the old secret stops working at once. */
const RegenerateModal: React.FC<{ apiKey: ApiKey; onClose: () => void; onDone: (secret: string) => void }> = ({ apiKey, onClose, onDone }) => {
  const { t } = useTranslation();
  const [choice, setChoice] = useState<ExpiryChoice>('30');
  const [date, setDate] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const expires = expiryFromChoice(choice, date);
  return (
    <Modal
      open
      size="md"
      title={t('apiKeys.regenerateTitle', { name: apiKey.name })}
      onClose={busy ? () => {} : onClose}
      footer={
        <>
          <Button variant="outline" size="sm" onClick={onClose} disabled={busy}>
            {t('actions.cancel')}
          </Button>
          <Button
            variant="danger"
            size="sm"
            disabled={busy || expires === undefined}
            onClick={async () => {
              setBusy(true);
              try {
                const r = await regenerateApiKey(apiKey.id, expires ?? null);
                onDone(r.secret);
              } catch (e) {
                setError(e instanceof Error ? e.message : String(e));
                setBusy(false);
              }
            }}
          >
            <RefreshCw size={14} />
            {t('apiKeys.regenerate')}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Alert severity="warning">{t('apiKeys.regenerateWarning')}</Alert>
        <ExpiryPicker
          choice={choice}
          date={date}
          onChange={(c, d) => {
            setChoice(c);
            setDate(d);
          }}
        />
        {error && <Alert severity="error">{error}</Alert>}
      </div>
    </Modal>
  );
};

export default ApiKeysPage;
