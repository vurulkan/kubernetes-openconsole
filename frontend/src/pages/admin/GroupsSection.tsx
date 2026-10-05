import React from 'react';
import { Pencil, Plus, Search as SearchIcon, Trash2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Badge, Button, Input } from '../../components/ui';
import { Column, DataTable, IconButton } from '../../components/DataTable';
import { User } from '../../services/api';

type Group = { id: number; name: string };
type Role = { id: number; name: string; description: string };

type Props = {
  groups: Group[];
  roles: Role[];
  groupRoles: Record<number, Array<{ id: number; name: string }>>;
  users: User[];
  userGroups: Record<number, Array<{ id: number; name: string }>>;
  filter: string;
  onFilter: (v: string) => void;
  onNew: () => void;
  onEdit: (g: Group) => void;
  onDelete: (g: Group) => void;
};

export const GroupsSection: React.FC<Props> = ({
  groups,
  groupRoles,
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
  const rows = q ? groups.filter((g) => g.name.toLowerCase().includes(q)) : groups;

  // Pre-compute member count per group once.
  const memberCount = React.useMemo(() => {
    const m = new Map<number, number>();
    users.forEach((u) => {
      (userGroups[u.id] ?? []).forEach((g) => m.set(g.id, (m.get(g.id) ?? 0) + 1));
    });
    return m;
  }, [users, userGroups]);

  const columns: Column<Group>[] = [
    {
      key: 'name',
      header: t('admin.groups.col.name'),
      cell: (g) => (
        <span className="font-medium text-slate-900 dark:text-slate-100">{g.name}</span>
      ),
    },
    {
      key: 'members',
      header: t('admin.groups.col.members'),
      align: 'center',
      cell: (g) => (
        <Badge variant="default">{memberCount.get(g.id) ?? 0}</Badge>
      ),
    },
    {
      key: 'roles',
      header: t('admin.groups.col.roles'),
      cell: (g) => {
        const list = groupRoles[g.id] ?? [];
        if (list.length === 0)
          return <span className="text-xs text-slate-400 dark:text-slate-500">—</span>;
        return (
          <div className="flex flex-wrap gap-1">
            {list.slice(0, 3).map((r) => (
              <span
                key={r.id}
                className="rounded-md bg-brand-50 px-1.5 py-0.5 text-[11px] font-medium text-brand-700 dark:bg-brand-500/15 dark:text-brand-200"
              >
                {r.name}
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
      cell: (g) => (
        <div className="flex justify-end gap-1">
          <IconButton label="Edit group" onClick={() => onEdit(g)}>
            <Pencil size={14} />
          </IconButton>
          <IconButton label="Delete group" variant="danger" onClick={() => onDelete(g)}>
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
            placeholder={t('admin.groups.search')}
            value={filter}
            onChange={(e) => onFilter(e.target.value)}
            className="h-9 pl-8"
          />
        </div>
        <Button variant="primary" size="sm" onClick={onNew}>
          <Plus size={14} />
          {t('admin.groups.new')}
        </Button>
      </div>
      <DataTable
        rows={rows}
        columns={columns}
        rowKey={(g) => g.id}
        emptyMessage={q ? t('admin.groups.emptyFilter') : t('admin.groups.emptyAll')}
      />
    </div>
  );
};

export default GroupsSection;
