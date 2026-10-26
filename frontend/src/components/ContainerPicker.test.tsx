import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { ContainerPicker } from './ContainerPicker';
import { expectNoA11yViolations } from '../test/a11y';

const pod = {
  metadata: { labels: { app: 'digital-planet-integration-bk' } },
  spec: { containers: [{ name: 'filebeat' }, { name: 'digital-planet-integration' }, { name: 'pvc-cleaner' }] },
  status: {
    containerStatuses: [
      { name: 'filebeat', state: { running: {} } },
      { name: 'digital-planet-integration', state: { running: {} } },
      { name: 'pvc-cleaner', state: { terminated: {} } },
    ],
  },
};

describe('ContainerPicker', () => {
  it('puts the main container first and focused; a stopped one cannot be picked', async () => {
    const anchor = document.createElement('button');
    anchor.textContent = 'Shell';
    document.body.appendChild(anchor);
    const onPick = vi.fn();
    const onClose = vi.fn();
    render(<ContainerPicker pod={pod} anchor={anchor} onPick={onPick} onClose={onClose} />);

    const items = screen.getAllByRole('menuitem');
    expect(items.map((b) => b.textContent)).toEqual(['digital-planet-integrationmain', 'filebeat', 'pvc-cleanernot running']);
    expect(items[0]).toHaveFocus();
    expect(items[2]).toBeDisabled();

    fireEvent.keyDown(items[0], { key: 'ArrowDown' });
    expect(items[1]).toHaveFocus();
    fireEvent.keyDown(items[1], { key: 'ArrowDown' }); // skips the stopped one
    expect(items[0]).toHaveFocus();

    fireEvent.click(items[0]);
    expect(onPick).toHaveBeenCalledWith('digital-planet-integration');

    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalled();
    expect(anchor).toHaveFocus();

    await expectNoA11yViolations(document.body);
  });
});
