import { describe, expect, it } from 'vitest';
import { constellationLink } from '../src/shared/OpenInConstellation';

/** AUTH-T-10.1: the link D3 Constellation opens a person or group from. */
describe('constellationLink', () => {
  it('names this host and D3 Auth, so the app opens the same connection', () => {
    expect(constellationLink('person/01a0-abc', 'auth.d3cloud.io')).toBe('d3constellation://auth.d3cloud.io/d3auth/person/01a0-abc');
    expect(constellationLink('group/g 1', 'auth.d3cloud.io')).toBe('d3constellation://auth.d3cloud.io/d3auth/group/g%201');
  });
});
