import React from 'react';
import { Pencil, Plus, Search as SearchIcon, Trash2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Badge, Button, Input } from '../../components/ui';
import { Column, DataTable, IconButton } from '../../components/DataTable';
import { User } from '../../services/api';

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
      width: '110px',
      cell: (u) => (
        <div className="flex justify-end gap-1">
          <IconButton label="Edit user" onClick={() => onEdit(u)}>
            <Pencil size={14} />
          </IconButton>
          <IconButton label="Delete user" variant="danger" onClick={() => onDelete(u)}>
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
        <Button variant="primary" size="sm" onClick={onNew}>
          <Plus size={14} />
          {t('admin.users.new')}
        </Button>
      </div>
      <DataTable
        rows={rows}
        columns={columns}
        rowKey={(u) => u.id}
        emptyMessage={q ? t('admin.users.emptyFilter') : t('admin.users.emptyAll')}
      />
    </div>
  );
};

export default UsersSection;
