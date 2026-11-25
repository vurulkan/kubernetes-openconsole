import { describe, expect, it } from 'vitest';
import { takeFilters, typingNamespace } from './paletteQuery';

describe('takeFilters', () => {
  it.each([
    ['web', { rest: 'web' }],
    ['svc web', { kind: 'services', rest: 'web' }],
    ['svc:web', { kind: 'services', rest: 'web' }],
    ['service web', { kind: 'services', rest: 'web' }],
    ['pods web', { kind: 'pods', rest: 'web' }],
    ['ns:prod svc web', { kind: 'services', ns: 'prod', rest: 'web' }],
    ['svc ns:Prod web', { kind: 'services', ns: 'prod', rest: 'web' }],
    // a word that only starts like a kind, a kind alone, ns: still being typed: all text
    ['svc-gateway', { rest: 'svc-gateway' }],
    ['svc', { rest: 'svc' }],
    ['ns:pro', { rest: 'ns:pro' }],
    ['10.42.0.7', { rest: '10.42.0.7' }],
    // one kind only: the second kind word is the name
    ['po deploy', { kind: 'pods', rest: 'deploy' }],
    ['ns web', { kind: 'namespaces', rest: 'web' }],
  ])('%s', (input, want) => {
    expect(takeFilters(input, true)).toEqual(want);
  });

  it('nodes only for admins', () => {
    expect(takeFilters('no node-a', true)).toEqual({ kind: 'nodes', rest: 'node-a' });
    expect(takeFilters('no node-a', false)).toEqual({ rest: 'no node-a' });
  });

  it('typingNamespace', () => {
    expect(typingNamespace('ns:pro')).toEqual({ ns: 'pro', text: '' });
    expect(typingNamespace(' web ')).toEqual({ text: 'web' });
  });
});
