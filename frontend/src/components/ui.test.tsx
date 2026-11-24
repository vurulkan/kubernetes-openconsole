import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Input, NativeSelect } from './ui';

// Tailwind 3 settles w-full vs w-40 by CSS order (w-full wins), so a caller's size
// only applies when the default steps aside.
describe('field size', () => {
  it('defaults to full width and h-9', () => {
    render(<Input aria-label="a" />);
    expect(screen.getByLabelText('a').className).toMatch(/(^|\s)w-full(\s|$)/);
    expect(screen.getByLabelText('a').className).toMatch(/(^|\s)h-9(\s|$)/);
  });

  it("keeps the caller's width and height", () => {
    render(
      <>
        <Input aria-label="b" className="h-8 w-40 pl-8" />
        <NativeSelect aria-label="c" className="w-48">
          <option>x</option>
        </NativeSelect>
        <Input aria-label="d" className="sm:w-72" />
      </>,
    );
    const b = screen.getByLabelText('b').className;
    expect(b).not.toMatch(/w-full|h-9/);
    expect(b).toMatch(/w-40/);
    const c = screen.getByLabelText('c').className;
    expect(c).not.toMatch(/w-full/);
    expect(c).toMatch(/(^|\s)h-9(\s|$)/);
    // A breakpoint width still starts from full width.
    expect(screen.getByLabelText('d').className).toMatch(/(^|\s)w-full(\s|$)/);
  });
});
