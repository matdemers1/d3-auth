import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { createThrottle } from '../../src/security/throttle.js';
import { testDb, unique } from './helpers.js';

const db = testDb();
const throttle = createThrottle(db);

beforeEach(async () => {
  await db.throttleCounter.deleteMany();
});

afterAll(async () => {
  await db.$disconnect();
});

const keys = () => ({ account: `person-${unique()}@example.com`, ip: `203.0.113.${Math.ceil(Math.random() * 250)}` });

describe('throttle storage (REQ-027, REQ-028)', () => {
  it('allows the first four failures and blocks the fifth attempt', async () => {
    const k = keys();
    const now = new Date('2026-09-16T10:00:00Z');
    for (let i = 0; i < 4; i++) {
      expect((await throttle.check(k, now)).allowed).toBe(true);
      await throttle.recordFailure(k, now);
    }
    expect((await throttle.check(k, now)).allowed).toBe(true);

    await throttle.recordFailure(k, now);
    const blocked = await throttle.check(k, now);
    expect(blocked).toMatchObject({ allowed: false, scope: 'account' });
    expect(blocked.retryAfterSeconds).toBe(2);
  });

  it('lets the attempt through once the delay has passed, then doubles again', async () => {
    const k = keys();
    const start = new Date('2026-09-16T10:00:00Z');
    for (let i = 0; i < 5; i++) await throttle.recordFailure(k, start);

    const later = new Date(start.getTime() + 3_000);
    expect((await throttle.check(k, later)).allowed).toBe(true);

    await throttle.recordFailure(k, later);
    expect((await throttle.check(k, later)).retryAfterSeconds).toBe(4);
  });

  it('is case- and whitespace-insensitive about the email', async () => {
    const k = { account: 'Alex@Example.com', ip: '203.0.113.9' };
    const now = new Date();
    for (let i = 0; i < 5; i++) await throttle.recordFailure(k, now);
    expect((await throttle.check({ account: '  alex@example.com ', ip: '203.0.113.9' }, now)).allowed).toBe(false);
  });

  it('clears on success so it is a delay, not a lockout', async () => {
    const k = keys();
    const now = new Date();
    for (let i = 0; i < 6; i++) await throttle.recordFailure(k, now);
    expect((await throttle.check(k, now)).allowed).toBe(false);

    await throttle.clear(k);
    expect((await throttle.check(k, now)).allowed).toBe(true);
    expect(await db.throttleCounter.count({ where: { key: k.account } })).toBe(0);
  });

  it('blocks a different account from the same address only after 20 failures', async () => {
    const ip = `198.51.100.${Math.ceil(Math.random() * 250)}`;
    const now = new Date();
    for (let i = 0; i < 20; i++) await throttle.recordFailure({ account: `guest-${unique()}@example.com`, ip }, now);

    const innocent = { account: `innocent-${unique()}@example.com`, ip };
    expect((await throttle.check(innocent, now)).allowed).toBe(true);

    await throttle.recordFailure({ account: `guest-${unique()}@example.com`, ip }, now);
    const decision = await throttle.check(innocent, now);
    expect(decision).toMatchObject({ allowed: false, scope: 'ip' });
  });

  it('works without an IP at all', async () => {
    const k = { account: `no-ip-${unique()}@example.com` };
    const now = new Date();
    for (let i = 0; i < 5; i++) await throttle.recordFailure(k, now);
    expect((await throttle.check(k, now)).allowed).toBe(false);
  });

  it('reports the longer of the two waits', async () => {
    const ip = `198.51.100.${Math.ceil(Math.random() * 250)}`;
    const now = new Date();
    const k = { account: `both-${unique()}@example.com`, ip };
    for (let i = 0; i < 25; i++) await throttle.recordFailure(k, now);
    const decision = await throttle.check(k, now);
    expect(decision.allowed).toBe(false);
    expect(decision.retryAfterSeconds).toBeGreaterThanOrEqual(32);
  });

  it('prunes counters past the retention window', async () => {
    const k = keys();
    const old = new Date('2026-01-01T00:00:00Z');
    await throttle.recordFailure(k, old);
    expect(await throttle.prune(new Date('2026-06-01T00:00:00Z'))).toBeGreaterThanOrEqual(1);
    expect(await db.throttleCounter.count({ where: { key: k.account } })).toBe(0);
  });
});
