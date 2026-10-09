import React from 'react';
import { describe, expect, it } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import i18n from '../i18n';
import { confirm, ConfirmProvider } from './ConfirmDialog';
import { expectNoA11yViolations } from '../test/a11y';

describe('confirm()', () => {
  it('resolves true on confirm and false on cancel, with translated defaults', async () => {
    await act(() => i18n.changeLanguage('tr'));
    render(<ConfirmProvider><div /></ConfirmProvider>);

    let answer: Promise<boolean>;
    act(() => {
      answer = confirm({ title: 'Silinsin mi?', message: 'Emin misiniz?' });
    });
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    await expectNoA11yViolations(document.body);
    fireEvent.click(screen.getByRole('button', { name: 'İptal' }));
    await expect(answer!).resolves.toBe(false);

    act(() => {
      answer = confirm({ title: 'Silinsin mi?', message: 'Emin misiniz?' });
    });
    fireEvent.click(await screen.findByRole('button', { name: 'Onayla' }));
    await expect(answer!).resolves.toBe(true);
    await act(() => i18n.changeLanguage('en'));
  });
});
