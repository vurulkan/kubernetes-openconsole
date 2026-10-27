import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { Column, DataTable, IconButton } from './DataTable';
import { expectNoA11yViolations } from '../test/a11y';

type Row = { id: number; name: string };
const rows: Row[] = [
  { id: 1, name: 'alpha' },
  { id: 2, name: 'beta' },
  { id: 3, name: 'gamma' },
];

function table(props: { onRowClick?: (r: Row) => void; onDelete?: (r: Row) => void; onEdit?: (r: Row) => void }) {
  const columns: Column<Row>[] = [
    { key: 'name', header: 'Name', cell: (r) => r.name },
    {
      key: 'actions',
      header: 'Actions',
      cell: (r) => (
        <>
          <IconButton label={`Edit ${r.name}`} onClick={() => props.onEdit?.(r)}>e</IconButton>
          <IconButton label={`Delete ${r.name}`} variant="danger" onClick={() => props.onDelete?.(r)}>d</IconButton>
        </>
      ),
    },
  ];
  return render(
    <div>
      <input aria-label="filter" />
      <DataTable rows={rows} columns={columns} rowKey={(r) => r.id} onRowClick={props.onRowClick} keyboardNav />
    </div>,
  );
}

const key = (k: string, target: Element | Document = document) => fireEvent.keyDown(target, { key: k });

describe('DataTable keyboard navigation', () => {
  it('j / k move the cursor, Enter opens the row', () => {
    const onRowClick = vi.fn();
    table({ onRowClick });
    key('j');
    key('j');
    key('k');
    key('j');
    const selected = screen.getAllByRole('row').filter((r) => r.getAttribute('aria-selected') === 'true');
    expect(selected).toHaveLength(1);
    expect(selected[0]).toHaveTextContent('beta');
    key('Enter');
    expect(onRowClick).toHaveBeenCalledWith(rows[1]);
  });

  it('Enter without onRowClick runs the first action; d runs the danger action', () => {
    const onEdit = vi.fn();
    const onDelete = vi.fn();
    table({ onEdit, onDelete });
    key('j');
    key('Enter');
    expect(onEdit).toHaveBeenCalledWith(rows[0]);
    key('d');
    expect(onDelete).toHaveBeenCalledWith(rows[0]);
  });

  it('ignores keys while typing and binds Enter / d only with a selected row', () => {
    const onDelete = vi.fn();
    const onRowClick = vi.fn();
    table({ onDelete, onRowClick });
    const input = screen.getByLabelText('filter');
    key('j', input);
    key('d');
    key('Enter');
    expect(onDelete).not.toHaveBeenCalled();
    expect(onRowClick).not.toHaveBeenCalled();
    key('j');
    key('Escape');
    key('d');
    expect(onDelete).not.toHaveBeenCalled();
  });

  it('has no accessibility violations', async () => {
    const { container } = table({});
    await expectNoA11yViolations(container);
  });
});

describe('DataTable sorting', () => {
  type U = { id: number; pct: number | null };
  const data: U[] = [
    { id: 1, pct: 0.2 },
    { id: 2, pct: null },
    { id: 3, pct: 0.95 },
  ];
  const cols: Column<U>[] = [
    { key: 'id', header: 'Id', cell: (r) => `row-${r.id}` },
    { key: 'pct', header: 'Use', cell: (r) => String(r.pct), sortValue: (r) => r.pct, descFirst: true },
  ];
  const order = () => screen.getAllByText(/^row-/).map((el) => el.textContent);

  it('a descFirst column sorts highest first, and empty values stay last both ways', () => {
    render(<DataTable rows={data} columns={cols} rowKey={(r) => r.id} />);
    fireEvent.click(screen.getByRole('button', { name: /Use/ }));
    expect(order()).toEqual(['row-3', 'row-1', 'row-2']);
    fireEvent.click(screen.getByRole('button', { name: /Use/ }));
    expect(order()).toEqual(['row-1', 'row-3', 'row-2']);
  });
});

describe('DataTable column picker', () => {
  type P = { id: number; name: string; ns: string; ip: string };
  const data: P[] = [{ id: 1, name: 'web', ns: 'prod', ip: '10.0.0.1' }];
  const cols: Column<P>[] = [
    { key: 'name', header: 'Name', cell: (r) => r.name },
    { key: 'ns', header: 'Namespace', cell: (r) => r.ns },
    { key: 'ip', header: 'IP', cell: (r) => r.ip },
    { key: 'actions', header: '', cell: () => null },
  ];
  const headers = () => screen.getAllByRole('columnheader').map((h) => h.textContent);
  const mount = () => render(<DataTable rows={data} columns={cols} rowKey={(r) => r.id} columnsStorageKey="t:pods" />);

  it('hides a column, keeps it after a remount, and resets; Name cannot be hidden', async () => {
    localStorage.clear();
    const { unmount } = mount();
    const button = screen.getByRole('button', { name: 'Columns' });
    fireEvent.click(button);
    const items = screen.getAllByRole('menuitemcheckbox');
    expect(items.map((i) => i.textContent)).toEqual(['Name', 'Namespace', 'IP']);
    expect(items[0]).toBeDisabled();
    expect(items[1]).toHaveFocus();
    await expectNoA11yViolations(document.body);

    fireEvent.click(items[1]);
    expect(headers()).toEqual(['Name', 'IP', 'Actions']);
    expect(screen.queryByText('prod')).toBeNull();
    expect(localStorage.getItem('dt:cols:t:pods')).toBe('["ns"]');

    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('menu')).toBeNull();
    expect(button).toHaveFocus();

    unmount();
    mount();
    expect(headers()).toEqual(['Name', 'IP', 'Actions']);
    fireEvent.click(screen.getByRole('button', { name: 'Columns' }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Reset to default' }));
    expect(headers()).toEqual(['Name', 'Namespace', 'IP', 'Actions']);
    expect(localStorage.getItem('dt:cols:t:pods')).toBeNull();
  });

  it('arrow keys move through the enabled items', () => {
    localStorage.clear();
    mount();
    fireEvent.click(screen.getByRole('button', { name: 'Columns' }));
    const [, ns, ip] = screen.getAllByRole('menuitemcheckbox');
    const reset = screen.getByRole('menuitem');
    fireEvent.keyDown(ns, { key: 'ArrowDown' });
    expect(ip).toHaveFocus();
    fireEvent.keyDown(ip, { key: 'ArrowDown' });
    expect(reset).toHaveFocus();
    fireEvent.keyDown(reset, { key: 'ArrowDown' });
    expect(ns).toHaveFocus(); // Name is disabled, so the wrap skips it
  });

  it('is off without columnsStorageKey', () => {
    render(<DataTable rows={data} columns={cols} rowKey={(r) => r.id} />);
    expect(screen.queryByRole('button', { name: 'Columns' })).toBeNull();
  });
});
