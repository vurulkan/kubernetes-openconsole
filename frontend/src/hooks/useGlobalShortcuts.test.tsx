import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { EVENTS_PANEL_EVENT_NAME, useGlobalShortcuts } from './useGlobalShortcuts';

const Host: React.FC = () => {
  useGlobalShortcuts({ isAdmin: false, setTheme: () => {} });
  return (
    <>
      {/* Monaco takes text through a plain focusable div (EditContext). */}
      <div className="monaco-editor">
        <div tabIndex={0} data-testid="editor" />
      </div>
      <div className="xterm">
        <div tabIndex={0} data-testid="terminal" />
      </div>
      <button type="button" data-testid="page">page</button>
    </>
  );
};

afterEach(() => vi.restoreAllMocks());

describe('global shortcuts', () => {
  it('leave keys typed in the YAML editor or a terminal alone', () => {
    const { getByTestId } = render(
      <MemoryRouter>
        <Host />
      </MemoryRouter>,
    );
    const toggled = vi.fn();
    window.addEventListener(EVENTS_PANEL_EVENT_NAME, toggled);
    for (const id of ['editor', 'terminal']) {
      fireEvent.keyDown(getByTestId(id), { key: 'e', code: 'KeyE' });
    }
    expect(toggled).not.toHaveBeenCalled();
    fireEvent.keyDown(getByTestId('page'), { key: 'e', code: 'KeyE' });
    expect(toggled).toHaveBeenCalledTimes(1);
    window.removeEventListener(EVENTS_PANEL_EVENT_NAME, toggled);
  });
});
