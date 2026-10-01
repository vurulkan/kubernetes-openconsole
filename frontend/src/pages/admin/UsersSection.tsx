import React from 'react';
import { Pencil, Plus, Search as SearchIcon, Trash2 } from 'lucide-react';
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
  const q = filter.trim().toLowerCase();
  const rows = q
    ? users.filter((u) => u.username.toLowerCase().includes(q))
    : users;

  const columns: Column<User>[] = [
    {
      key: 'username',
      header: 'Username',
      cell: (u) => (
        <span className="font-mono text-[13px] font-medium text-slate-900 dark:text-slate-100">
          {u.username}
        </span>
      ),
    },
    {
      key: 'admin',
      header: 'Admin',
      align: 'center',
      cell: (u) =>
        u.isAdmin ? (
          <Badge variant="info">Admin</Badge>
        ) : (
          <span className="text-xs text-slate-400 dark:text-slate-500">—</span>
        ),
    },
    {
      key: 'active',
      header: 'Status',
      align: 'center',
      cell: (u) =>
        u.isActive ? (
          <Badge variant="success">Active</Badge>
        ) : (
          <Badge variant="warning">Disabled</Badge>
        ),
    },
    {
      key: 'groups',
      header: 'Groups',
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
            placeholder="Search users…"
            value={filter}
            onChange={(e) => onFilter(e.target.value)}
            className="h-9 pl-8"
          />
        </div>
        <Button variant="primary" size="sm" onClick={onNew}>
          <Plus size={14} />
          New user
        </Button>
      </div>
      <DataTable
        rows={rows}
        columns={columns}
        rowKey={(u) => u.id}
        emptyMessage={q ? 'No users match this search.' : 'No users yet.'}
      />
    </div>
  );
};

export default UsersSection;
