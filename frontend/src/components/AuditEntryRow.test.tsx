import React from 'react';
import { describe, expect, it } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import '../i18n';
import { AuditEntryRow } from './AuditEntryRow';
import { expectNoA11yViolations } from '../test/a11y';
import type { AuditEntry } from '../services/api';

const restart: AuditEntry = {
  id: 1,
  timestamp: '2026-10-15T14:55:22Z',
  timestampFormatted: '2026-10-15 14:55:22',
  user: 'mustafa@corp.com',
  action: 'deployment.restart',
  verb: 'restart',
  outcome: 'success',
  namespace: 'boh-cy',
  resourceType: 'deployment',
  resourceName: 'boh',
  cluster: 'Zenia-NonProd',
  details: { restarted_at: '2026-10-15T14:55:22Z' },
  sourceIp: '10.1.2.3',
  requestId: 'r1',
};

describe('AuditEntryRow', () => {
  it('shows action, outcome, target and expandable details', async () => {
    const { container } = render(<AuditEntryRow entry={restart} />);
    expect(screen.getByText('deployment.restart')).toBeInTheDocument();
    expect(screen.getByText('success')).toBeInTheDocument();
    expect(screen.getByText('boh-cy/boh')).toBeInTheDocument();
    expect(screen.getByText('Zenia-NonProd')).toBeInTheDocument();
    fireEvent.click(screen.getByText('Details'));
    expect(screen.getByText('restarted_at')).toBeInTheDocument();
    expect(screen.getByText('10.1.2.3')).toBeInTheDocument();
    await expectNoA11yViolations(container);
  });

  it('has no details toggle when there is nothing to show', () => {
    render(<AuditEntryRow entry={{ ...restart, details: undefined, sourceIp: undefined, requestId: undefined }} />);
    expect(screen.queryByText('Details')).toBeNull();
  });
});
