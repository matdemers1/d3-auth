import { randomBytes } from 'node:crypto';
import { Secret, TOTP } from 'otpauth';
import { afterAll, describe, expect, it } from 'vitest';
import { createAuditWriter } from '../../src/audit/writer.js';
import { createLogger } from '../../src/log.js';
import { createSecretHasher } from '../../src/security/hash.js';
import { createKekCrypto } from '../../src/security/kek.js';
import { createTotp, DIGITS, PERIOD_SECONDS } from '../../src/security/totp.js';
import { OwnerPasswordError, setOwnerPassword } from '../../src/setup/owner-password.js';
import { testDb, unique } from './helpers.js';

// A forgotten owner password, from the host (REQ-145, ADR-010). The new password has to work, the
// old one has to stop, and the second step has to still be there: a shell on the host replaces a
// password, it does not get past the factor.

const db = testDb();
const hasher = createSecretHasher(randomBytes(32));
const totp = createTotp(db, createKekCrypto(randomBytes(32)), 'D3 Auth');
const deps = { db, hasher, audit: createAuditWriter(db, createLogger({ level: 'silent' })) };

const strong = (): string => `new-${randomBytes(12).toString('base64url')}`;

async function owner(kind: 'owner' | 'admin' = 'owner') {
  const email = `${kind}-pw-${unique()}@example.com`;
  const user = await db.user.create({ data: { email, username: `${kind}pw${unique()}`, displayName: 'Owner', kind, status: 'active', emailVerified: true } });
  await db.passwordCredential.create({ data: { userId: user.id, argon2idHash: await hasher.hash('the-one-that-was-overwritten') } });
  const enrolment = await totp.begin({ userId: user.id, accountName: email, label: 'Phone' });
  const code = new TOTP({ secret: Secret.fromBase32(enrolment.manualKey), digits: DIGITS, period: PERIOD_SECONDS }).generate();
  expect(await totp.confirm({ userId: user.id, credentialId: enrolment.credentialId, code })).toBe(true);
  return { user, email };
}

afterAll(async () => {
  await db.$disconnect();
});

describe('set-password for the owner', () => {
  it('replaces the password, keeps the factor, ends sessions, clears the throttle and audits', async () => {
    const { user, email } = await owner();
    const uid = `sess-${unique()}`;
    await db.oidcPayload.create({ data: { id: uid, kind: 'Session', uid, payload: {} } });
    await db.session.create({ data: { userId: user.id, oidcSessionUid: uid, expiresAt: new Date(Date.now() + 3_600_000) } });
    await db.throttleCounter.create({ data: { scope: 'account', key: email, failures: 9, blockedUntil: new Date(Date.now() + 600_000) } });

    const password = strong();
    const result = await setOwnerPassword(deps, { email: email.toUpperCase(), password });
    expect(result).toEqual({ email, sessionsEnded: 1, factors: 1 });

    const credentials = await db.passwordCredential.findMany({ where: { userId: user.id } });
    expect(credentials).toHaveLength(1);
    expect(await hasher.verify(credentials[0]?.argon2idHash ?? '', password)).toBe(true);
    expect(await hasher.verify(credentials[0]?.argon2idHash ?? '', 'the-one-that-was-overwritten')).toBe(false);

    expect(await db.totpCredential.count({ where: { userId: user.id, confirmedAt: { not: null } } })).toBe(1);
    expect(await db.session.count({ where: { userId: user.id, revokedAt: null } })).toBe(0);
    expect(await db.oidcPayload.count({ where: { kind: 'Session', uid } })).toBe(0);
    expect(await db.throttleCounter.count({ where: { scope: 'account', key: email } })).toBe(0);

    const audited = await db.auditEvent.findMany({ where: { event: 'password.set_from_host', targetId: user.id } });
    expect(audited).toHaveLength(1);
    expect(audited[0]?.detail).toMatchObject({ email, by: 'host', sessionsEnded: 1, factors: 1 });
    expect(JSON.stringify(audited[0]?.detail)).not.toContain(password);
  });

  it('refuses anybody who is not the owner, and an unknown address', async () => {
    const { user, email } = await owner('admin');
    await expect(setOwnerPassword(deps, { email, password: strong() })).rejects.toThrow(/not the owner/);
    await expect(setOwnerPassword(deps, { email: `nobody-${unique()}@example.com`, password: strong() })).rejects.toThrow(OwnerPasswordError);
    expect(await db.auditEvent.count({ where: { event: 'password.set_from_host', targetId: user.id } })).toBe(0);
  });

  it('holds the new password to the same policy as a password change, and changes nothing when it fails', async () => {
    const { user, email } = await owner();
    const before = await db.passwordCredential.findFirstOrThrow({ where: { userId: user.id } });
    await expect(setOwnerPassword(deps, { email, password: 'short' })).rejects.toThrow(/at least 12/);
    await expect(setOwnerPassword(deps, { email, password: 'password1234' })).rejects.toThrow(OwnerPasswordError);
    const after = await db.passwordCredential.findFirstOrThrow({ where: { userId: user.id } });
    expect(after.argon2idHash).toBe(before.argon2idHash);
  });
});
