import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { act, render, screen } from '@testing-library/react';

vi.mock('./MonacoYaml', () => ({
  YamlEditor: ({ value }: { value: string }) => <pre data-testid="yaml">{value}</pre>,
  YamlDiff: () => null,
}));
import YamlEditModal, { type YamlEditTarget } from './YamlEditModal';

const target = (name: string, fetchYaml: YamlEditTarget['fetchYaml']): YamlEditTarget => ({
  resource: 'deployments',
  resourceLabel: 'Deployment',
  namespace: 'shop',
  name,
  fetchYaml,
  canEdit: false,
});

describe('YamlEditModal', () => {
  it('shows the YAML of the resource opened last, even when the previous one answers later', async () => {
    let releaseA: (v: { yaml: string }) => void = () => {};
    const a = target('a', () => new Promise((resolve) => (releaseA = resolve)));
    const b = target('b', async () => ({ yaml: 'name: b' }));
    const { rerender } = render(<YamlEditModal target={a} onClose={() => {}} theme="light" />);
    rerender(<YamlEditModal target={b} onClose={() => {}} theme="light" />);
    expect(await screen.findByText('name: b')).toBeInTheDocument();
    await act(async () => {
      releaseA({ yaml: 'name: a' });
    });
    expect(screen.getByTestId('yaml')).toHaveTextContent('name: b');
  });
});
