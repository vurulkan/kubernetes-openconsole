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
