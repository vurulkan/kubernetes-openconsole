import React, { useState } from 'react';
import { afterEach, describe, expect, it } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { Modal } from './ui';
import Drawer from './Drawer';
import { ConfirmProvider, confirm } from './ConfirmDialog';

afterEach(cleanup);

const tab = (shift = false) => fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Tab', shiftKey: shift });

const WithModal: React.FC<{ kind: 'modal' | 'drawer' }> = ({ kind }) => {
  const [open, setOpen] = useState(false);
  const body = (
    <>
      <input aria-label="Name" />
      <button type="button">Save</button>
    </>
  );
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Open
      </button>
      {kind === 'modal' ? (
        <Modal open={open} onClose={() => setOpen(false)} title="Edit" size="sm">
          {body}
        </Modal>
      ) : (
        <Drawer open={open} onClose={() => setOpen(false)} title="Edit">
          {body}
        </Drawer>
      )}
    </>
  );
};

describe.each(['modal', 'drawer'] as const)('%s focus', (kind) => {
  it('moves focus in, keeps Tab inside, and returns it to the opener', () => {
    render(<WithModal kind={kind} />);
    const opener = screen.getByRole('button', { name: 'Open' });
    opener.focus();
    fireEvent.click(opener);
    const dialog = screen.getByRole('dialog', { name: 'Edit' });
    // The first field, not the close button in the header.
    expect(document.activeElement).toBe(screen.getByRole('textbox', { name: 'Name' }));

    // Shift+Tab from the first control wraps to the last one, Tab from the last wraps back.
    const close = screen.getByRole('button', { name: 'Close' });
    close.focus();
    tab(true);
    const items = Array.from(dialog.querySelectorAll<HTMLElement>('button, input, [tabindex="0"]'));
    expect(document.activeElement).toBe(items[items.length - 1]);
    tab();
    expect(document.activeElement).toBe(items[0]);
    expect(dialog.contains(document.activeElement)).toBe(true);

    fireEvent.keyDown(document.activeElement!, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.activeElement).toBe(opener);
  });
});

describe('confirm dialog', () => {
  it('over a modal: Esc closes the confirm only', async () => {
    const Host: React.FC = () => {
      const [open, setOpen] = useState(true);
      return (
        <Modal open={open} onClose={() => setOpen(false)} title="YAML" size="sm">
          <button type="button" onClick={() => void confirm({ title: 'Apply?', message: 'Sure?' })}>
            Apply
          </button>
        </Modal>
      );
    };
    render(
      <ConfirmProvider>
        <Host />
      </ConfirmProvider>,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
    expect(screen.getByRole('dialog', { name: 'Apply?' })).toBeInTheDocument();
    fireEvent.keyDown(document.activeElement!, { key: 'Escape' });
    await act(async () => {});
    expect(screen.queryByRole('dialog', { name: 'Apply?' })).toBeNull();
    expect(screen.getByRole('dialog', { name: 'YAML' })).toBeInTheDocument();
  });

  it('starts on the safe choice and an Esc closes only the confirm, not the drawer under it', async () => {
    render(
      <ConfirmProvider>
        <WithModal kind="drawer" />
      </ConfirmProvider>,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Open' }));
    const save = screen.getByRole('button', { name: 'Save' });
    save.focus();
    let answer: Promise<boolean> = Promise.resolve(true);
    act(() => {
      answer = confirm({ title: 'Delete?', message: 'Really?', variant: 'danger' });
    });
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Cancel' }));

    fireEvent.keyDown(document.activeElement!, { key: 'Escape' });
    await expect(answer).resolves.toBe(false);
    expect(screen.queryByRole('dialog', { name: 'Delete?' })).toBeNull();
    expect(screen.getByRole('dialog', { name: 'Edit' })).toBeInTheDocument();
    expect(document.activeElement).toBe(save);
  });
});
