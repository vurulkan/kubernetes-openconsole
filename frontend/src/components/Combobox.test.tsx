import React, { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, within } from '@testing-library/react';
import Combobox, { ComboMode } from './Combobox';
import { expectNoA11yViolations } from '../test/a11y';

const actions = ['pod.exec.start', 'pod.exec.end', 'pod.exec.denied', 'secret.reveal.success', 'login.failed'];

function Harness({ onPick }: { onPick: (v: string, m: ComboMode) => void }) {
  const [value, setValue] = useState('');
  return (
    <Combobox
      label="Action"
      value={value}
      options={actions}
      families
      onChange={(v, m) => {
        setValue(v);
        onPick(v, m);
      }}
    />
  );
}

describe('Combobox', () => {
  it('filters as you type and offers the family row', async () => {
    const onPick = vi.fn();
    render(<Harness onPick={onPick} />);
    const input = screen.getByRole('combobox', { name: 'Action' });
    fireEvent.change(input, { target: { value: 'exec' } });
    expect(onPick).toHaveBeenLastCalledWith('exec', 'contains');
    const options = within(screen.getByRole('listbox')).getAllByRole('option').map((o) => o.textContent);
    expect(options[0]).toContain('pod.exec.*');
    expect(options).toHaveLength(4); // family + 3 members
    await expectNoA11yViolations(document.body);
  });

  it('picks with the keyboard: family, then an exact action', () => {
    const onPick = vi.fn();
    render(<Harness onPick={onPick} />);
    const input = screen.getByRole('combobox');
    fireEvent.change(input, { target: { value: 'pod' } });
    fireEvent.keyDown(input, { key: 'ArrowDown' });
    expect(input).toHaveAttribute('aria-activedescendant');
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(onPick).toHaveBeenLastCalledWith('pod.exec.*', 'family');
    expect(screen.getByRole('combobox')).toHaveAttribute('aria-expanded', 'false');

    fireEvent.change(input, { target: { value: 'login' } });
    fireEvent.keyDown(input, { key: 'ArrowDown' });
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(onPick).toHaveBeenLastCalledWith('login.failed', 'exact');
  });

  it('Escape closes the list and the clear button empties the filter', () => {
    const onPick = vi.fn();
    render(<Harness onPick={onPick} />);
    const input = screen.getByRole('combobox');
    fireEvent.change(input, { target: { value: 'secret' } });
    expect(input).toHaveAttribute('aria-expanded', 'true');
    fireEvent.keyDown(input, { key: 'Escape' });
    expect(input).toHaveAttribute('aria-expanded', 'false');
    fireEvent.click(screen.getByRole('button', { name: 'Clear Action' }));
    expect(onPick).toHaveBeenLastCalledWith('', 'contains');
  });
});
