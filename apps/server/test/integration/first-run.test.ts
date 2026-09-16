import { randomBytes } from 'node:crypto';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { createAuditWriter } from '../../src/audit/writer.js';
import { createLogger } from '../../src/log.js';
import { createAdapterFactory } from '../../src/oidc/adapter.js';
import { createSecretHasher } from '../../src/security/hash.js';
import { createFirstRunSetup, type FirstRunSetup } from '../../src/setup/first-run.js';
import { testDb } from './helpers.js';

// REQ-141: a fresh instance can be claimed from the browser once, and never again.

const db = testDb();
const hasher = createSecretHasher(randomBytes(32));

let logLines: string[];
let setup: FirstRunSetup;

const OWNER = {
  email: 'owner@example.com',
  username: 'owner',
  displayName: 'The Owner',
  password: 'otter parade lantern',
};

const codeFromLog = (): string => {
  const line = logLines.find((entry) => entry.includes('setupCode')) ?? '{}';
  return (JSON.parse(line) as { setupCode?: string }).setupCode ?? '';
};

beforeEach(async () => {
  // A genuinely empty instance.
  await db.passwordCredential.deleteMany();
  await db.session.deleteMany();
  await db.grant.deleteMany();
  await db.user.deleteMany();
  await db.oidcPayload.deleteMany();

  logLines = [];
  const logger = createLogger({ level: 'debug', destination: { write: (line: string) => { logLines.push(line); } } });
  setup = createFirstRunSetup(db, createAdapterFactory(db), hasher, createAuditWriter(db, logger), logger);
  await setup.prepare();
});

afterAll(async () => {
  await db.$disconnect();
});

describe('first-run setup', () => {
  it('is available only while there are no accounts', async () => {
    expect(await setup.available()).toBe(true);
    await db.user.create({ data: { email: 'someone@example.com', username: 'someone', displayName: 'Someone', status: 'active' } });
    expect(await setup.available()).toBe(false);
  });

  it('prints a readable setup code that the log scrubber leaves alone', () => {
    const code = codeFromLog();
    expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4})+$/);
    expect(code).not.toContain('[redacted]');
    expect(logLines.join()).toMatch(/no accounts yet/);
  });

  it('creates the owner, once', async () => {
    const result = await setup.claim({ ...OWNER, code: codeFromLog(), ip: '203.0.113.5', userAgent: 'test' });
    expect(result).toMatchObject({ ok: true });

    const user = await db.user.findUniqueOrThrow({ where: { email: OWNER.email } });
    expect(user).toMatchObject({ kind: 'owner', status: 'active', emailVerified: true, username: 'owner' });
    const credential = await db.passwordCredential.findFirstOrThrow({ where: { userId: user.id } });
    expect(await hasher.verify(credential.argon2idHash, OWNER.password)).toBe(true);

    const audited = await db.auditEvent.findFirst({ where: { event: 'owner.claimed' }, orderBy: { id: 'desc' } });
    expect(audited).toMatchObject({ actorUserId: user.id, targetType: 'user' });
    expect(JSON.stringify(audited?.detail)).not.toContain(OWNER.password);

    // Second time: refused, whatever code is offered.
    expect(await setup.claim({ ...OWNER, email: 'other@example.com', username: 'other', code: codeFromLog() })).toMatchObject({
      ok: false,
      error: 'already_claimed',
    });
    expect(await setup.available()).toBe(false);
  });

  it('refuses the wrong code, and forgives how the right one is typed', async () => {
    expect(await setup.claim({ ...OWNER, code: 'NOTTHERIGHTCODEATALL' })).toMatchObject({ ok: false, error: 'bad_code' });
    expect(await db.user.count()).toBe(0);

    // Dashes stripped, lower case, spaces, and the look-alikes people type instead.
    const typed = codeFromLog().replaceAll('-', ' ').toLowerCase().replace(/1/g, 'l').replace(/0/g, 'o');
    expect(await setup.claim({ ...OWNER, code: typed })).toMatchObject({ ok: true });
  });

  it('applies the password policy and the username rules', async () => {
    const code = codeFromLog();
    const weak = await setup.claim({ ...OWNER, code, password: 'passwordpassword' });
    expect(weak).toMatchObject({ ok: false, error: 'invalid' });
    expect(!weak.ok && weak.problems?.join()).toMatch(/attackers try first/);

    const badName = await setup.claim({ ...OWNER, code, username: 'no spaces allowed' });
    expect(badName).toMatchObject({ ok: false, error: 'invalid' });

    const badEmail = await setup.claim({ ...OWNER, code, email: 'not-an-email' });
    expect(badEmail).toMatchObject({ ok: false, error: 'invalid' });

    expect(await db.user.count()).toBe(0);
  });

  it('lets only one of two simultaneous claims win', async () => {
    const code = codeFromLog();
    const results = await Promise.all([
      setup.claim({ ...OWNER, code }),
      setup.claim({ ...OWNER, code, email: 'second@example.com', username: 'second' }),
    ]);
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(await db.user.count()).toBe(1);
  });

  it('forgets the code once it has been used', async () => {
    const code = codeFromLog();
    await setup.claim({ ...OWNER, code });
    await db.user.deleteMany();
    // Even with the instance emptied again, the old code is gone: a new one must be minted.
    expect(await setup.claim({ ...OWNER, code })).toMatchObject({ ok: false, error: 'bad_code' });
  });
});
