import { describe, expect, it, vi } from 'vitest';
import type { SecretHasher } from '../../src/security/hash.js';
import { createPasswordVerifier } from '../../src/security/password.js';
import { checkPassword, loadBlocklist, MIN_LENGTH } from '../../src/security/policy.js';

describe('password policy (REQ-025)', () => {
  it('accepts a long passphrase', () => {
    expect(checkPassword('otter parade lantern')).toEqual({ ok: true, problems: [] });
  });

  it.each(['short', 'elevenchars', 'a'.repeat(MIN_LENGTH - 1)])('rejects %s as too short', (password) => {
    expect(checkPassword(password).problems.join()).toMatch(/at least 12 characters/);
  });

  it('rejects long passwords that are still guessable first', () => {
    for (const password of ['passwordpassword', 'Password123456!', 'qwertyqwerty', 'letmeinletmein', 'correcthorsebatterystaple']) {
      expect(checkPassword(password).ok, password).toBe(false);
    }
  });

  it('rejects a password built from the account itself', () => {
    const context = { email: 'alex@example.com', username: 'alexd', displayName: 'Alex Demers' };
    expect(checkPassword('alex@example.com!!', context).ok).toBe(false);
    expect(checkPassword('my alexd is here', context).ok).toBe(false);
    expect(checkPassword('otter parade lantern', context).ok).toBe(true);
  });

  it('caps the length so a huge body is not free work', () => {
    expect(checkPassword('a'.repeat(300)).problems.join()).toMatch(/at most 256/);
  });

  it('ships a blocklist that actually contains long entries', () => {
    const list = loadBlocklist();
    expect(list.size).toBeGreaterThan(100);
    expect([...list].filter((entry) => entry.length >= 12).length).toBeGreaterThan(20);
    expect(list.has('passwordpassword')).toBe(true);
  });

  it('says what is wrong without suggesting composition rules', () => {
    const { problems } = checkPassword('short');
    expect(problems.join()).not.toMatch(/symbol|uppercase|digit|special/i);
  });
});

describe('password verification (REQ-026, REQ-086)', () => {
  const hasher = (): SecretHasher & { calls: string[] } => {
    const calls: string[] = [];
    return {
      calls,
      hash: (value: string) => {
        calls.push(`hash:${value.slice(0, 4)}`);
        return Promise.resolve(`hashed:${value}`);
      },
      verify: (hash: string, value: string) => {
        calls.push('verify');
        return Promise.resolve(hash === `hashed:${value}`);
      },
    };
  };

  it('accepts the right password and rejects the wrong one', async () => {
    const verifier = await createPasswordVerifier(hasher());
    expect(await verifier.verify('hashed:otter parade lantern', 'otter parade lantern')).toBe(true);
    expect(await verifier.verify('hashed:otter parade lantern', 'something else')).toBe(false);
  });

  it('still performs a verification when the account has no password', async () => {
    const spy = hasher();
    const verifier = await createPasswordVerifier(spy);
    spy.calls.length = 0;

    expect(await verifier.verify(undefined, 'anything at all')).toBe(false);
    expect(await verifier.verify(null, 'anything at all')).toBe(false);
    expect(spy.calls).toEqual(['verify', 'verify']);
  });

  it('never answers true for an unknown account, even if the decoy somehow matched', async () => {
    const always: SecretHasher = { hash: () => Promise.resolve('decoy'), verify: () => Promise.resolve(true) };
    const verifier = await createPasswordVerifier(always);
    expect(await verifier.verify(undefined, 'guess')).toBe(false);
    expect(await verifier.verify('decoy', 'guess')).toBe(true);
  });

  it('computes the decoy once, at construction', async () => {
    const spy = hasher();
    const verifier = await createPasswordVerifier(spy);
    expect(spy.calls.filter((c) => c.startsWith('hash:'))).toHaveLength(1);
    await verifier.verify(undefined, 'a');
    await verifier.verify(undefined, 'b');
    expect(spy.calls.filter((c) => c.startsWith('hash:'))).toHaveLength(1);
  });

  it('does the same work for a known and an unknown account', async () => {
    // Uniform *timing* is measured under load in the Phase 5 adversarial suite (T-5.1); a
    // wall-clock comparison on a shared CI runner measures the runner, not the code. What is
    // deterministic, and what the decoy exists for, is that both paths perform one verification
    // against a hash of the same shape.
    const seen: { hash: string; password: string }[] = [];
    const recording: SecretHasher = {
      hash: () => Promise.resolve('$argon2id$decoy'),
      verify: (hash, password) => {
        seen.push({ hash, password });
        return Promise.resolve(false);
      },
    };
    const verifier = await createPasswordVerifier(recording);

    await verifier.verify('$argon2id$real', 'guess');
    await verifier.verify(undefined, 'guess');

    expect(seen).toHaveLength(2);
    expect(seen[0]?.password).toBe(seen[1]?.password);
    expect(seen[1]?.hash).toBe('$argon2id$decoy');
    expect(seen[1]?.hash).not.toBe('');
  });
});

describe('argon2 parameters (REQ-024)', () => {
  it('uses OWASP minimums', async () => {
    const argon2 = (await import('argon2')).default;
    const { ARGON2_PARAMS } = await import('../../src/security/hash.js');
    expect(ARGON2_PARAMS).toEqual({ type: argon2.argon2id, memoryCost: 19_456, timeCost: 2, parallelism: 1 });
    expect(ARGON2_PARAMS.memoryCost).toBeGreaterThanOrEqual(19 * 1024);
  });

  it('produces an argon2id hash with those parameters', async () => {
    vi.setConfig({ testTimeout: 20_000 });
    const { createSecretHasher } = await import('../../src/security/hash.js');
    const hasher = createSecretHasher(Buffer.alloc(32, 7));
    const hash = await hasher.hash('otter parade lantern');
    expect(hash).toMatch(/^\$argon2id\$v=19\$m=19456,p=1,t=2\$/);
    expect(await hasher.verify(hash, 'otter parade lantern')).toBe(true);
    expect(await hasher.verify(hash, 'otter parade lanterns')).toBe(false);
  });
});
