import React from 'react';
import { describe, expect, it } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { ContainerSquares } from './PodStatusBadge';
import { containerStates } from '../utils/podStatus';
import { expectNoA11yViolations } from '../test/a11y';

describe('ContainerSquares', () => {
  it('labels each square and shows the tip on hover', async () => {
    const pod = {
      spec: { containers: [{ name: 'app' }], initContainers: [{ name: 'logs', restartPolicy: 'Always' }] },
      status: {
        containerStatuses: [{ name: 'app', restartCount: 3, state: { waiting: { reason: 'CrashLoopBackOff' } } }],
        initContainerStatuses: [{ name: 'logs', ready: true, state: { running: { startedAt: '2026-10-26T08:00:00Z' } } }],
      },
    };
    const { container } = render(<ContainerSquares containers={containerStates(pod)} />);
    const [app, logs] = screen.getAllByRole('img');
    expect(app).toHaveAccessibleName('app, waiting: CrashLoopBackOff, 3 restarts');
    expect(logs.getAttribute('aria-label')).toMatch(/^logs · sidecar, running, ready, Started at .+ ago\), 0 restarts$/);
    fireEvent.mouseEnter(app);
    expect(document.body).toHaveTextContent('waiting: CrashLoopBackOff');
    await expectNoA11yViolations(container);
  });
});
