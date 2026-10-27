import React from 'react';
import { describe, expect, it } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { ResourceListView } from './ResourceListView';

const pod = (name: string, states: Array<'ok' | 'crash'>) => ({
  metadata: { name },
  spec: { containers: states.map((_, i) => ({ name: `c${i}` })) },
  status: {
    phase: 'Running',
    containerStatuses: states.map((s, i) =>
      s === 'ok'
        ? { name: `c${i}`, ready: true, state: { running: {} } }
        : { name: `c${i}`, state: { waiting: { reason: 'CrashLoopBackOff' } } },
    ),
  },
});

describe('Pods Containers column sort', () => {
  it('sorts by container count, then problem containers, then keeps the name order', () => {
    localStorage.clear();
    const noop = () => {};
    render(
      <ResourceListView
        activeTab="pods"
        items={[pod('a', ['ok']), pod('b', ['ok', 'ok']), pod('c', ['ok', 'crash']), pod('d', ['ok', 'ok', 'ok']), pod('e', ['ok', 'ok'])]}
        selectedNamespace="ns"
        searchQuery=""
        loading={false}
        canExecPods={false}
        canRestartDeployments={false}
        canScaleDeployments={false}
        canScaleStatefulSets={false}
        openYamlModal={noop}
        openEventsModal={noop}
        openLogModal={noop}
        onOpen={noop}
        metrics={null}
        failingByOwner={new Map()}
        openConfigMapDataModal={noop}
        openSecretModal={noop}
        canEditSecrets={false}
        openDeploymentLogs={noop}
        openJobLogs={noop}
        onExec={noop}
        onRestart={noop}
        onScale={noop}
        onScaleStatefulSet={noop}
      />,
    );
    const order = () => screen.getAllByRole('row').slice(1).map((r) => r.querySelector('td')?.textContent);
    fireEvent.click(screen.getByRole('button', { name: /Containers/ }));
    expect(order()).toEqual(['d', 'c', 'b', 'e', 'a']);
    fireEvent.click(screen.getByRole('button', { name: /Containers/ }));
    expect(order()).toEqual(['a', 'b', 'e', 'c', 'd']);
  });
});
