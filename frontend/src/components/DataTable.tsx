import React, { useMemo, useState } from 'react';
import { ChevronDown, ChevronLeft, ChevronRight, ChevronUp, ChevronsUpDown } from 'lucide-react';

export type Column<T> = {
  key: string;
  header: React.ReactNode;
  cell: (row: T) => React.ReactNode;
  width?: string;
  className?: string;
  align?: 'left' | 'right' | 'center';
  /** Opt a column into sort. Return any Comparable (string | number | Date-ish). */
  sortValue?: (row: T) => string | number | undefined | null;
};

type Props<T> = {
  rows: T[];
  columns: Column<T>[];
  rowKey: (row: T) => string | number;
  onRowClick?: (row: T) => void;
  pageSize?: number;
  emptyMessage?: string;
  /**
   * localStorage key for persisting the sort state between visits. If omitted,
   * sorting resets to "no sort" on each mount.
   */
  sortStorageKey?: string;
};

type SortState = { key: string; dir: 'asc' | 'desc' } | null;

const alignClass = (a?: 'left' | 'right' | 'center') => {
  if (a === 'right') return 'text-right';
  if (a === 'center') return 'text-center';
  return 'text-left';
};

/**
 * Minimal admin-style table. Client-side pagination (default 25 per page),
 * no sorting UI yet — add later with a Column.sortable flag. Rows are
 * clickable when onRowClick is provided; action cells inside the row stop
 * propagation on their own.
 */
export function DataTable<T>({
  rows,
  columns,
  rowKey,
  onRowClick,
  pageSize = 25,
  emptyMessage = 'No data.',
  sortStorageKey,
}: Props<T>) {
  const [page, setPage] = useState(0);

  // Sort state persisted per-table via sortStorageKey so a user who likes
  // "Age desc" on the Pods list keeps it on refresh.
  const [sort, setSort] = useState<SortState>(() => {
    if (!sortStorageKey) return null;
    try {
      const raw = localStorage.getItem('dt:' + sortStorageKey);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed.key === 'string' && (parsed.dir === 'asc' || parsed.dir === 'desc')) {
        return parsed;
      }
    } catch (err) {
      /* ignore */
    }
    return null;
  });
  React.useEffect(() => {
    if (!sortStorageKey) return;
    try {
      if (sort) {
        localStorage.setItem('dt:' + sortStorageKey, JSON.stringify(sort));
      } else {
        localStorage.removeItem('dt:' + sortStorageKey);
      }
    } catch (err) {
      /* ignore */
    }
  }, [sort, sortStorageKey]);

  const sortedRows = useMemo(() => {
    if (!sort) return rows;
    const col = columns.find((c) => c.key === sort.key);
    if (!col?.sortValue) return rows;
    const dir = sort.dir === 'asc' ? 1 : -1;
    const compare = (a: T, b: T) => {
      const va = col.sortValue!(a);
      const vb = col.sortValue!(b);
      if (va == null && vb == null) return 0;
      if (va == null) return 1 * dir; // nulls last on asc, first on desc
      if (vb == null) return -1 * dir;
      if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * dir;
      return String(va).localeCompare(String(vb)) * dir;
    };
    return [...rows].sort(compare);
  }, [rows, sort, columns]);

  const total = sortedRows.length;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const start = page * pageSize;
  const end = Math.min(start + pageSize, total);
  const slice = useMemo(() => sortedRows.slice(start, end), [sortedRows, start, end]);

  // Reset to page 0 when sort changes so the user actually sees the new top.
  React.useEffect(() => {
    setPage(0);
  }, [sort?.key, sort?.dir]);

  const toggleSort = (colKey: string) => {
    setSort((cur) => {
      if (!cur || cur.key !== colKey) return { key: colKey, dir: 'asc' };
      if (cur.dir === 'asc') return { key: colKey, dir: 'desc' };
      return null; // third click clears
    });
  };

  // Keep the cursor on-page when the underlying list shrinks (e.g. a delete).
  if (page > 0 && start >= total) {
    setTimeout(() => setPage(Math.max(0, pageCount - 1)), 0);
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="overflow-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900/60">
        <table className="w-full text-sm">
          <thead className="bg-slate-50/70 dark:bg-slate-800/40">
            <tr>
              {columns.map((c) => {
                const sortable = Boolean(c.sortValue);
                const sortIcon = (() => {
                  if (!sortable) return null;
                  if (sort?.key !== c.key)
                    return (
                      <ChevronsUpDown
                        size={11}
                        className="text-slate-300 group-hover:text-slate-500 dark:text-slate-600 dark:group-hover:text-slate-300"
                      />
                    );
                  return sort.dir === 'asc' ? (
                    <ChevronUp size={11} className="text-brand-600 dark:text-brand-300" />
                  ) : (
                    <ChevronDown size={11} className="text-brand-600 dark:text-brand-300" />
                  );
                })();
                return (
                  <th
                    key={c.key}
                    className={`px-4 py-3 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 ${alignClass(c.align)}`}
                    style={c.width ? { width: c.width } : undefined}
                  >
                    {sortable ? (
                      <button
                        type="button"
                        onClick={() => toggleSort(c.key)}
                        className={`group inline-flex items-center gap-1 ${
                          c.align === 'right'
                            ? 'float-right'
                            : c.align === 'center'
                            ? 'mx-auto'
                            : ''
                        } hover:text-slate-700 dark:hover:text-slate-200 focus:outline-none`}
                      >
                        {c.header}
                        {sortIcon}
                      </button>
                    ) : (
                      c.header
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
            {slice.length === 0 && (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-4 py-10 text-center text-sm text-slate-400 dark:text-slate-500"
                >
                  {emptyMessage}
                </td>
              </tr>
            )}
            {slice.map((row) => {
              const key = rowKey(row);
              return (
                <tr
                  key={key}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  className={`transition-colors ${
                    onRowClick
                      ? 'cursor-pointer hover:bg-brand-50/40 dark:hover:bg-brand-500/10'
                      : ''
                  }`}
                >
                  {columns.map((c) => (
                    <td
                      key={c.key}
                      className={`px-4 py-2.5 align-middle ${alignClass(c.align)} ${c.className ?? ''}`}
                    >
                      {c.cell(row)}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {total > pageSize && (
        <div className="flex items-center justify-between gap-3 text-xs text-slate-500 dark:text-slate-400">
          <span>
            {start + 1}–{end} of {total}
          </span>
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="rounded-md border border-slate-200 bg-white p-1 text-slate-500 transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:bg-slate-800"
            >
              <ChevronLeft size={14} />
            </button>
            <span className="px-2 text-slate-500 dark:text-slate-400">
              {page + 1} / {pageCount}
            </span>
            <button
              type="button"
              onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
              disabled={page >= pageCount - 1}
              className="rounded-md border border-slate-200 bg-white p-1 text-slate-500 transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:bg-slate-800"
            >
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default DataTable;

/** IconButton primitive for row actions (edit, delete, etc.). */
export const IconButton: React.FC<{
  onClick: () => void;
  label: string;
  children: React.ReactNode;
  variant?: 'default' | 'danger';
}> = ({ onClick, label, children, variant = 'default' }) => (
  <button
    type="button"
    onClick={(e) => {
      e.stopPropagation();
      onClick();
    }}
    title={label}
    aria-label={label}
    className={`inline-flex h-7 w-7 items-center justify-center rounded-md border transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/40 ${
      variant === 'danger'
        ? 'border-transparent text-slate-500 hover:border-rose-200 hover:bg-rose-50 hover:text-rose-600 dark:text-slate-400 dark:hover:border-rose-500/30 dark:hover:bg-rose-500/10 dark:hover:text-rose-300'
        : 'border-transparent text-slate-500 hover:border-slate-200 hover:bg-slate-100 hover:text-slate-800 dark:text-slate-400 dark:hover:border-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-100'
    }`}
  >
    {children}
  </button>
);
