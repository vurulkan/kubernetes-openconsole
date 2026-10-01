import React from 'react';
import { Pencil, Plus, Search as SearchIcon, Trash2 } from 'lucide-react';
import { Badge, Button, Input } from '../../components/ui';
import { Column, DataTable, IconButton } from '../../components/DataTable';

type Role = { id: number; name: string; description: string };

type Props = {
  roles: Role[];
  groupRoles: Record<number, Array<{ id: number; name: string }>>;
  filter: string;
  onFilter: (v: string) => void;
  onNew: () => void;
  onEdit: (r: Role) => void;
  onDelete: (r: Role) => void;
};

export const RolesSection: React.FC<Props> = ({
  roles,
  groupRoles,
  filter,
  onFilter,
  onNew,
  onEdit,
  onDelete,
}) => {
  const q = filter.trim().toLowerCase();
  const rows = q
    ? roles.filter(
        (r) =>
          r.name.toLowerCase().includes(q) ||
          (r.description ?? '').toLowerCase().includes(q)
      )
    : roles;

  // Groups using each role count.
  const groupsByRole = React.useMemo(() => {
    const m = new Map<number, number>();
    Object.values(groupRoles).forEach((list) => {
      list.forEach((r) => m.set(r.id, (m.get(r.id) ?? 0) + 1));
    });
    return m;
  }, [groupRoles]);

  const columns: Column<Role>[] = [
    {
      key: 'name',
      header: 'Name',
      cell: (r) => (
        <span className="font-medium text-slate-900 dark:text-slate-100">{r.name}</span>
      ),
    },
    {
      key: 'description',
      header: 'Description',
      cell: (r) =>
        r.description ? (
          <span className="text-sm text-slate-600 dark:text-slate-300">{r.description}</span>
        ) : (
          <span className="text-xs text-slate-400 dark:text-slate-500">—</span>
        ),
    },
    {
      key: 'groups',
      header: 'Used by',
      align: 'center',
      cell: (r) => (
        <Badge variant="default">
          {groupsByRole.get(r.id) ?? 0} group{(groupsByRole.get(r.id) ?? 0) === 1 ? '' : 's'}
        </Badge>
      ),
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      width: '110px',
      cell: (r) => (
        <div className="flex justify-end gap-1">
          <IconButton label="Edit role" onClick={() => onEdit(r)}>
            <Pencil size={14} />
          </IconButton>
          <IconButton label="Delete role" variant="danger" onClick={() => onDelete(r)}>
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
            placeholder="Search roles…"
            value={filter}
            onChange={(e) => onFilter(e.target.value)}
            className="h-9 pl-8"
          />
        </div>
        <Button variant="primary" size="sm" onClick={onNew}>
          <Plus size={14} />
          New role
        </Button>
      </div>
      <DataTable
        rows={rows}
        columns={columns}
        rowKey={(r) => r.id}
        emptyMessage={q ? 'No roles match this search.' : 'No roles yet.'}
      />
    </div>
  );
};

export default RolesSection;
