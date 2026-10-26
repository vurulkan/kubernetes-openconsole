import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { expectNoA11yViolations } from '../test/a11y';

type Opts = {
  path: string;
  params: Record<string, string>;
  live: boolean;
  onLine: (f: { t: 'line'; text: string }) => void;
  onStatus: (s: { state: string; reason?: string }) => void;
};
const streams: Opts[] = [];
vi.mock('../utils/logStream', () => ({
  openLogStream: (o: Opts) => {
    streams.push(o);
    return () => undefined;
  },
}));

import { LogViewer, MAX_LINES } from './LogViewer';

const pod = {
  metadata: { annotations: { 'kubectl.kubernetes.io/default-container': 'app' } },
  spec: { initContainers: [{ name: 'migrate' }], containers: [{ name: 'sidecar' }, { name: 'app' }] },
};

const wait = (ms = 50) => act(() => new Promise((r) => setTimeout(r, ms)));

describe('LogViewer', () => {
  it('opens on the default container, switches instance and container, finds lines', async () => {
    render(<LogViewer namespace="team-a" target={{ kind: 'pods', name: 'api-1' }} pod={pod} onClose={() => undefined} />);
    await wait(0);
    expect(streams).toHaveLength(1);
    expect(streams[0].path).toBe('/ws/namespaces/team-a/pods/api-1/logs');
    expect(streams[0].params).toEqual({ tail: '100', container: 'app' });
    expect(streams[0].live).toBe(true);

    act(() => {
      streams[0].onStatus({ state: 'following' });
      for (const text of ['boot', 'ERROR one', 'ok', 'error two']) streams[0].onLine({ t: 'line', text });
    });
    await wait();
    expect(screen.getByText('Following')).toBeInTheDocument();
    expect(screen.getByText('boot')).toBeInTheDocument();

    fireEvent.change(screen.getByRole('searchbox', { name: 'Find in log' }), { target: { value: 'error' } });
    expect(screen.getByText('1/2')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Next match' }));
    expect(screen.getByText('2/2')).toBeInTheDocument();

    const select = screen.getByRole('combobox', { name: 'Container' });
    expect([...(select as HTMLSelectElement).options].map((o) => o.text)).toEqual(['migrate (init)', 'sidecar', 'app']);
    // Quick flips open only the last choice.
    fireEvent.click(screen.getByRole('button', { name: 'Before last restart' }));
    fireEvent.click(screen.getByRole('button', { name: 'Live' }));
    fireEvent.click(screen.getByRole('button', { name: 'Before last restart' }));
    await wait(300);
    expect(streams).toHaveLength(2);
    expect(streams[1].params).toEqual({ tail: '100', container: 'app', previous: 'true' });
    expect(streams[1].live).toBe(false);
    fireEvent.change(select, { target: { value: 'migrate' } });
    await wait(300);
    expect(streams[2].params.container).toBe('migrate');
    // A new stream starts from an empty view.
    expect(screen.queryByText('boot')).not.toBeInTheDocument();

    await expectNoA11yViolations(document.body);
  });

  it('keeps only the last lines and says how many were dropped', async () => {
    streams.length = 0;
    render(<LogViewer namespace="team-a" target={{ kind: 'deployments', name: 'web' }} onClose={() => undefined} />);
    await wait(0);
    expect(streams[0].params).toEqual({ tail: '100' });
    act(() => {
      for (let i = 0; i < MAX_LINES + 600; i++) streams[0].onLine({ t: 'line', text: `line ${i}` });
    });
    await wait();
    // Trimmed in chunks of 500, so the buffer holds 10,000 to 10,499 lines.
    expect(screen.getByText(/older lines dropped/)).toHaveTextContent('500 older lines dropped');
  });
});
