import React, { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { DateField } from './DateField';
import { expectNoA11yViolations } from '../test/a11y';

const Harness: React.FC<{ onValue: (v: string) => void; min?: string; max?: string }> = ({ onValue, min, max }) => {
  const [v, setV] = useState('');
  return (
    <DateField
      aria-label="Until"
      value={v}
      min={min}
      max={max}
      onChange={(x) => {
        setV(x);
        onValue(x);
      }}
    />
  );
};

afterEach(() => vi.unstubAllGlobals());

describe('DateField', () => {
  it('sends only whole days, flags a day past the limit, and the calendar keeps to the limit', async () => {
    const got: string[] = [];
    render(<Harness onValue={(v) => got.push(v)} min="2026-11-25" max="2026-12-24" />);
    const field = screen.getByLabelText('Until');
    fireEvent.change(field, { target: { value: '2026-12' } });
    expect(got[got.length - 1]).toBe(''); // half typed: nothing to filter or send yet
    expect(field).toHaveValue('2026-12');
    expect(screen.getByText('Enter a date as YYYY-MM-DD.')).toBeInTheDocument();
    fireEvent.change(field, { target: { value: '2026-12-31' } });
    expect(got[got.length - 1]).toBe('2026-12-31');
    expect(screen.getByText('Pick 2026-12-24 or earlier.')).toBeInTheDocument();
    fireEvent.change(field, { target: { value: '2026-12-10' } });
    expect(screen.queryByText(/or earlier/)).toBeNull();

    const open = screen.getByRole('button', { name: 'Open the calendar: Until' });
    fireEvent.click(open);
    const dialog = screen.getByRole('dialog', { name: 'Calendar: Until' });
    const grid = within(dialog).getByRole('grid');
    // December 2026: 1–24 can be picked, 25–31 can't; six week rows every month (fixedWeeks).
    const day = (n: number) =>
      within(grid)
        .getAllByRole('button')
        .find((b) => b.closest('td')?.getAttribute('data-day') === `2026-12-${String(n).padStart(2, '0')}`) as HTMLButtonElement;
    expect(day(24)).toBeEnabled();
    expect(day(25)).toBeDisabled();
    expect(grid.querySelectorAll('tbody tr')).toHaveLength(6); // December 2026 needs 5
    await expectNoA11yViolations(document.body);
    fireEvent.click(day(20));
    expect(got[got.length - 1]).toBe('2026-12-20');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.activeElement).toBe(open);

    fireEvent.click(open);
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.activeElement).toBe(open);
  });

  it('uses the browser date field with min / max on a touch screen', () => {
    vi.stubGlobal('matchMedia', (q: string) => ({ matches: q === '(pointer: coarse)', addEventListener() {}, removeEventListener() {} }));
    const got: string[] = [];
    render(<Harness onValue={(v) => got.push(v)} min="2026-11-25" max="2026-12-24" />);
    const field = screen.getByLabelText('Until');
    expect(field).toHaveAttribute('type', 'date');
    expect(field).toHaveAttribute('max', '2026-12-24');
    expect(screen.queryByRole('button')).toBeNull();
    fireEvent.change(field, { target: { value: '2026-12-31' } });
    expect(got[got.length - 1]).toBe('2026-12-31');
    expect(screen.getByText('Pick 2026-12-24 or earlier.')).toBeInTheDocument();
  });
});
