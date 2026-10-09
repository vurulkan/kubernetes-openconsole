import React, { useState } from 'react';
import { Download, KeyRound, Pencil, Plus, Search as SearchIcon, Trash2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { confirm } from '../../components/ConfirmDialog';
import { Alert, Badge, Button, Checkbox, Input, Modal } from '../../components/ui';
import { Column, DataTable, IconButton } from '../../components/DataTable';
import { exportUsersCsv, resetUserPassword, User } from '../../services/api';

const MIN_PASSWORD_LENGTH = 8;

type Props = {
  users: User[];
  groups: Array<{ id: number; name: string }>;
  userGroups: Record<number, Array<{ id: number; name: string }>>;
  filter: string;
  onFilter: (v: string) => void;
  onNew: () => void;
  onEdit: (u: User) => void;
  onDelete: (u: User) => void;
};

export const UsersSection: React.FC<Props> = ({
  users,
  userGroups,
  filter,
  onFilter,
  onNew,
  onEdit,
  onDelete,
}) => {
  const { t } = useTranslation();
  const [resetTarget, setResetTarget] = useState<User | null>(null);
  const q = filter.trim().toLowerCase();
  const rows = q
    ? users.filter((u) => u.username.toLowerCase().includes(q))
    : users;

  const columns: Column<User>[] = [
    {
      key: 'username',
      header: t('admin.users.col.username'),
      cell: (u) => (
        <span className="font-mono text-[13px] font-medium text-slate-900 dark:text-slate-100">
          {u.username}
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
      key: 'admin',
      header: t('admin.users.col.admin'),
      align: 'center',
      cell: (u) =>
        u.isAdmin ? (
          <Badge variant="info">{t('admin.users.adminBadge')}</Badge>
        ) : (
          <span className="text-xs text-slate-400 dark:text-slate-500">—</span>
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
      key: 'groups',
      header: t('admin.users.col.groups'),
      cell: (u) => {
        const list = userGroups[u.id] ?? [];
        if (list.length === 0)
          return <span className="text-xs text-slate-400 dark:text-slate-500">—</span>;
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
      width: '130px',
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
          <IconButton label={t('admin.users.deleteUser')} variant="danger" onClick={() => onDelete(u)}>
            <Trash2 size={14} />
          </IconButton>
        </div>
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="relative w-72">
          <SearchIcon
            size={14}
            className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400"
          />
          <Input
            placeholder={t('admin.users.search')}
            value={filter}
            onChange={(e) => onFilter(e.target.value)}
            className="h-9 pl-8"
          />
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void exportUsersCsv().catch((err) => alertExport(err))}>
            <Download size={14} />
            {t('admin.exportCsv')}
          </Button>
          <Button variant="primary" size="sm" onClick={onNew}>
            <Plus size={14} />
            {t('admin.users.new')}
          </Button>
        </div>
      </div>
      <DataTable
        keyboardNav
        rows={rows}
        columns={columns}
        rowKey={(u) => u.id}
        emptyMessage={q ? t('admin.users.emptyFilter') : t('admin.users.emptyAll')}
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

