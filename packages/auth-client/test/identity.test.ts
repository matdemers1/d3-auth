import { describe, expect, it } from 'vitest';
import { identityKey, isSameIdentity } from '../src/identity.js';
import * as sdk from '../src/index.js';

// REQ-093: identity is (iss, sub), and the SDK offers no way to do it by email.

describe('identity', () => {
  it('keys on both halves, because a sub means nothing without its issuer', () => {
    expect(identityKey({ iss: 'https://a.test', sub: '1' })).not.toBe(identityKey({ iss: 'https://b.test', sub: '1' }));
    expect(isSameIdentity('https://a.test#1', { iss: 'https://a.test', sub: '1' })).toBe(true);
    expect(isSameIdentity('https://a.test#1', { iss: 'https://b.test', sub: '1' })).toBe(false);
  });

  it('exports nothing that looks up a person by email', () => {
    const byEmail = Object.keys(sdk).filter((name) => /email/i.test(name));
    expect(byEmail).toEqual([]);
  });
});
