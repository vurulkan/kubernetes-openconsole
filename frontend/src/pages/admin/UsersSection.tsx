import React, { useState } from 'react';
import { ChevronDown, Cloud, Download, FolderTree, KeyRound, Pencil, Plus, Search as SearchIcon, ShieldOff, Trash2, UserRound } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { confirm } from '../../components/ConfirmDialog';
import { Alert, Badge, Button, Checkbox, Input, Modal, NativeSelect } from '../../components/ui';
import { Column, DataTable, IconButton } from '../../components/DataTable';
import { MenuPopover, menuItemClass } from '../../components/MenuPopover';
import { exportUsersCsv, resetUserPassword, resetUserTwoFactor, User } from '../../services/api';
import { ApiAccessBadge } from './ApiAccessParts';

const MIN_PASSWORD_LENGTH = 8;

type Props = {
  users: User[];
  groups: Array<{ id: number; name: string }>;
  userGroups: Record<number, Array<{ id: number; name: string }>>;
  filter: string;
  onFilter: (v: string) => void;
  /** Opens the create dialog for a local user or a pre-created Azure AD user. */
  onNew: (source: 'local' | 'azure') => void;
  /** Set when LDAP is enabled: opens the directory import dialog. */
  onImportLdap?: () => void;
  azureEnabled?: boolean;
  /** Azure AD directory search on: the Azure AD item searches Entra ID. */
  azureSearch?: boolean;
  /** Just created or imported: shown first and highlighted. */
  newUsernames?: string[];
  onEdit: (u: User) => void;
  onDelete: (u: User) => void;
  /** After an action that changes the list (2FA reset). */
  onReload?: () => void;
};

export const UsersSection: React.FC<Props> = ({
  users,
  userGroups,
  filter,
  onFilter,
  onNew,
  onImportLdap,
  azureEnabled,
  azureSearch,
  newUsernames = [],
  onEdit,
  onDelete,
  onReload,
}) => {
  const { t } = useTranslation();
  const [notice, setNotice] = useState<{ ok: boolean; text: string } | null>(null);
  const resetTwoFactor = async (u: User) => {
    const ok = await confirm({
      title: t('twoFactor.admin.resetTitle', { name: u.username }),
      message: t('twoFactor.admin.resetBody'),
      confirmText: t('twoFactor.admin.reset'),
      variant: 'danger',
    });
    if (!ok) return;
    try {
      await resetUserTwoFactor(u.id);
      setNotice({ ok: true, text: t('twoFactor.admin.resetDone', { name: u.username }) });
      onReload?.();
    } catch (err) {
      setNotice({ ok: false, text: (err as Error).message });
    }
  };
  const [resetTarget, setResetTarget] = useState<User | null>(null);
  // API access override filter: "*" = any, "" = by roles, else the mode.
  const [apiAccess, setApiAccess] = useState('*');
  const q = filter.trim().toLowerCase();
  const isNew = (u: User) => newUsernames.includes(u.username);
  const filtered = users.filter(
    (u) => (!q || u.username.toLowerCase().includes(q)) && (apiAccess === '*' || (u.apiAccessOverride ?? '') === apiAccess),
  );
  const rows = newUsernames.length > 0 ? [...filtered.filter(isNew), ...filtered.filter((u) => !isNew(u))] : filtered;

  const columns: Column<User>[] = [
    {
      key: 'username',
      header: t('admin.users.col.username'),
      cell: (u) => (
        <span className="inline-flex items-center gap-2">
          <span className="font-mono text-[13px] font-medium text-slate-900 dark:text-slate-100">{u.username}</span>
          {isNew(u) && <Badge variant="success">{t('admin.users.newBadge')}</Badge>}
        </span>
      ),
    },
    {
      key: 'source',
      header: t('admin.users.col.source'),
      align: 'center',
      cell: (u) => {
        const source = u.authSource ?? 'local';
        return (
          <Badge variant={source === 'local' ? 'default' : 'info'}>
            {t(`admin.users.source.${source}`)}
          </Badge>
        );
      },
    },
    {
      key: 'apiAccess',
      header: t('apiAccess.label'),
      align: 'center',
      cell: (u) => <ApiAccessBadge value={u.apiAccessOverride ?? ''} />,
    },
    {
      key: 'admin',
      header: t('admin.users.col.admin'),
      align: 'center',
      cell: (u) =>
        u.isAdmin ? (
          <Badge variant="info">{t('admin.users.adminBadge')}</Badge>
        ) : (
          <span className="text-xs text-slate-500 dark:text-slate-400">—</span>
        ),
    },
    {
      key: 'active',
      header: t('admin.users.col.status'),
      align: 'center',
      cell: (u) =>
        u.isActive ? (
          <Badge variant="success">{t('admin.users.active')}</Badge>
        ) : (
          <Badge variant="warning">{t('admin.users.disabled')}</Badge>
        ),
    },
    {
      key: 'twoFactor',
      header: t('twoFactor.admin.column'),
      align: 'center',
      cell: (u) =>
        u.twoFactorEnabled ? (
          <Badge variant="success">{t('twoFactor.statusOn')}</Badge>
        ) : u.authSource === 'azure' ? (
          <span className="text-xs text-slate-500 dark:text-slate-400">—</span>
        ) : (
          <span className="text-xs text-slate-500 dark:text-slate-400">{t('twoFactor.statusOff')}</span>
        ),
    },
    {
      key: 'groups',
      header: t('admin.users.col.groups'),
      cell: (u) => {
        const list = userGroups[u.id] ?? [];
        if (list.length === 0)
          return <span className="text-xs text-slate-500 dark:text-slate-400">—</span>;
        return (
          <div className="flex flex-wrap gap-1">
            {list.slice(0, 3).map((g) => (
              <span
                key={g.id}
                className="rounded-md bg-slate-100 px-1.5 py-0.5 text-[11px] font-medium text-slate-700 dark:bg-slate-800 dark:text-slate-200"
              >
                {g.name}
              </span>
            ))}
            {list.length > 3 && (
              <span className="rounded-md bg-slate-50 px-1.5 py-0.5 text-[11px] text-slate-500 dark:bg-slate-800/60 dark:text-slate-400">
                +{list.length - 3}
              </span>
            )}
          </div>
        );
      },
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      width: '160px',
      cell: (u) => (
        <div className="flex justify-end gap-1">
          <IconButton label={t('admin.users.editUser')} onClick={() => onEdit(u)}>
            <Pencil size={14} />
          </IconButton>
          {/* Directory users (LDAP / Azure AD) change their password there. */}
          {(u.authSource ?? 'local') === 'local' && (
            <IconButton label={t('admin.users.resetPassword')} onClick={() => setResetTarget(u)}>
              <KeyRound size={14} />
            </IconButton>
          )}
          {u.twoFactorEnabled && (
            <IconButton label={t('twoFactor.admin.reset')} onClick={() => void resetTwoFactor(u)}>
              <ShieldOff size={14} />
            </IconButton>
          )}
          <IconButton label={t('admin.users.deleteUser')} variant="danger" onClick={() => onDelete(u)}>
            <Trash2 size={14} />
          </IconButton>
        </div>
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative w-72">
          <SearchIcon
            size={14}
            className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400"
          />
          <Input
            placeholder={t('admin.users.search')}
            value={filter}
            onChange={(e) => onFilter(e.target.value)}
            className="pl-8"
          />
        </div>
        <NativeSelect aria-label={t('apiAccess.label')} value={apiAccess} onChange={(e) => setApiAccess(e.target.value)} className="w-48">
          <option value="*">{t('apiAccess.filterAny')}</option>
          <option value="">{t('apiAccess.roles')}</option>
          <option value="off">{t('apiAccess.off')}</option>
          <option value="safe_read">{t('apiAccess.safe_read')}</option>
          <option value="full">{t('apiAccess.fullUser')}</option>
        </NativeSelect>
        <div className="ml-auto flex items-center gap-2">
          <Button variant="outline" onClick={() => void exportUsersCsv().catch((err) => alertExport(err))}>
            <Download size={14} />
            {t('admin.exportCsv')}
          </Button>
          <NewUserMenu
            onLocal={() => onNew('local')}
            onLdap={onImportLdap}
            onAzure={azureEnabled ? () => onNew('azure') : undefined}
            azureSearch={azureSearch}
          />
        </div>
      </div>
      {notice && <Alert severity={notice.ok ? 'success' : 'error'}>{notice.text}</Alert>}
      <DataTable
        keyboardNav
        rowClassName={(u) => (isNew(u) ? 'bg-emerald-50/70 dark:bg-emerald-500/10' : '')}
        rows={rows}
        columns={columns}
        rowKey={(u) => u.id}
        emptyMessage={q || apiAccess !== '*' ? t('admin.users.emptyFilter') : t('admin.users.emptyAll')}
      />
      <ResetPasswordModal user={resetTarget} onClose={() => setResetTarget(null)} />
    </div>
  );
};

const ResetPasswordModal: React.FC<{ user: User | null; onClose: () => void }> = ({ user, onClose }) => {
  const { t } = useTranslation();
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [mustChange, setMustChange] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const close = () => {
    setPassword('');
    setConfirmPassword('');
    setMustChange(true);
    setError(null);
    setDone(false);
    onClose();
  };

  const submit = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!user) return;
    if (password.length < MIN_PASSWORD_LENGTH) {
      setError(t('admin.users.resetTooShort', { count: MIN_PASSWORD_LENGTH }));
      return;
    }
    if (password !== confirmPassword) {
      setError(t('admin.users.resetMismatch'));
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await resetUserPassword(user.id, password, mustChange);
      setDone(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={user !== null}
      onClose={close}
      title={t('admin.users.resetTitle', { name: user?.username ?? '' })}
      size="sm"
      footer={
        done ? (
          <Button variant="primary" size="sm" onClick={close}>
            {t('actions.close')}
          </Button>
        ) : (
          <>
            <Button variant="outline" size="sm" onClick={close}>
              {t('actions.cancel')}
            </Button>
            <Button variant="danger" size="sm" type="submit" form="reset-password-form" disabled={saving}>
              {t('admin.users.resetSubmit')}
            </Button>
          </>
        )
      }
    >
      {done ? (
        <Alert severity="success">{t('admin.users.resetDone', { name: user?.username ?? '' })}</Alert>
      ) : (
        <form id="reset-password-form" onSubmit={submit} className="flex flex-col gap-3">
          <p className="text-xs text-slate-500 dark:text-slate-400">{t('admin.users.resetHelp')}</p>
          <Input
            type="password"
            autoComplete="new-password"
            label={t('admin.users.resetNew')}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoFocus
          />
          <Input
            type="password"
            autoComplete="new-password"
            label={t('admin.users.resetConfirm')}
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
          />
          <Checkbox checked={mustChange} onChange={setMustChange} label={t('admin.users.resetMustChange')} />
          {error && <Alert severity="error">{error}</Alert>}
        </form>
      )}
    </Modal>
  );
};

export default UsersSection;

// Export failures are rare (session expired); show them in the app dialog.
function alertExport(err: unknown) {
  void confirm({
    title: 'CSV',
    message: err instanceof Error ? err.message : String(err),
    confirmText: 'OK',
  });
}

/**
 * "New user" button. With only local accounts available it opens the local
 * form; with LDAP and / or Azure AD on, any click opens the menu of sources
 * (so a directory installation doesn't make a local account by habit).
 */
const NewUserMenu: React.FC<{ onLocal: () => void; onLdap?: () => void; onAzure?: () => void; azureSearch?: boolean }> = ({
  onLocal,
  onLdap,
  onAzure,
  azureSearch,
}) => {
  const { t } = useTranslation();
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);

  if (!onLdap && !onAzure) {
    return (
      <Button variant="primary" onClick={onLocal}>
        <Plus size={14} />
        {t('admin.users.new')}
      </Button>
    );
  }

  const items = [
    { key: 'local', icon: UserRound, label: t('admin.newUserMenu.local'), hint: t('admin.newUserMenu.localHint'), run: onLocal },
    ...(onLdap
      ? [{ key: 'ldap', icon: FolderTree, label: t('admin.newUserMenu.ldap'), hint: t('admin.newUserMenu.ldapHint'), run: onLdap }]
      : []),
    ...(onAzure
      ? [{
          key: 'azure',
          icon: Cloud,
          label: t('admin.newUserMenu.azure'),
          hint: azureSearch ? t('admin.newUserMenu.azureSearchHint') : t('admin.newUserMenu.azureHint'),
          run: onAzure,
        }]
      : []),
  ];

  return (
    <>
      <Button
        variant="primary"
        aria-haspopup="menu"
        aria-expanded={anchor !== null}
        onClick={(e) => setAnchor(anchor ? null : e.currentTarget)}
        onKeyDown={(e) => {
          if (e.key !== 'ArrowDown') return;
          e.preventDefault();
          setAnchor(e.currentTarget);
        }}
      >
        <Plus size={14} />
        {t('admin.users.new')}
        <ChevronDown size={14} aria-hidden="true" />
      </Button>
      {anchor && (
        <MenuPopover anchor={anchor} label={t('admin.users.new')} onClose={() => setAnchor(null)} className="w-72">
          {items.map((item) => (
            <button
              key={item.key}
              type="button"
              role="menuitem"
              onClick={() => {
                setAnchor(null);
                item.run();
              }}
              className={`${menuItemClass} items-start gap-3 py-2`}
            >
              <item.icon size={16} className="mt-0.5 shrink-0 text-slate-500 dark:text-slate-400" aria-hidden="true" />
              <span className="flex flex-col">
                <span className="text-sm font-medium text-slate-900 dark:text-slate-100">{item.label}</span>
                <span className="text-xs text-slate-500 dark:text-slate-400">{item.hint}</span>
              </span>
            </button>
          ))}
        </MenuPopover>
      )}
    </>
  );
};
