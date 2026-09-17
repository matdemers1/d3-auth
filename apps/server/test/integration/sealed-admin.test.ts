import { randomBytes } from 'node:crypto';
import { Secret, TOTP } from 'otpauth';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { SEALED_ADMIN_KEY, SealedAdminError, sealAdmin } from '../../src/admin/sealed-admin.js';
import { createAuditWriter } from '../../src/audit/writer.js';
import { createLogger } from '../../src/log.js';
import { createSecretHasher } from '../../src/security/hash.js';
import { createKekCrypto } from '../../src/security/kek.js';
import { createTotp, PERIOD_SECONDS } from '../../src/security/totp.js';
import { testDb, unique } from './helpers.js';

// The sealed second admin (T-6.5, REQ-123). What is printed must work on its own — a password and
// an authenticator seed, nothing else — and rotating must make the last envelope worthless.

const db = testDb();
const hasher = createSecretHasher(randomBytes(32));
const totp = createTotp(db, createKekCrypto(randomBytes(32)), 'D3 Auth');
const deps = { db, hasher, totp, audit: createAuditWriter(db, createLogger({ level: 'silent' })) };

const codeAt = (manualKey: string, at: Date): string =>
  new TOTP({ secret: Secret.fromBase32(manualKey), digits: 6, period: PERIOD_SECONDS }).generate({ timestamp: at.getTime() });

beforeEach(async () => {
  await db.setting.deleteMany({ where: { key: SEALED_ADMIN_KEY } });
});

afterAll(async () => {
  await db.setting.deleteMany({ where: { key: SEALED_ADMIN_KEY } });
  await db.$disconnect();
});

describe('sealing an admin', () => {
  it('creates an active admin whose printed password and authenticator both work', async () => {
    const email = `sealed-${unique()}@example.com`;
    const sealed = await sealAdmin(deps, { email, displayName: 'Sealed admin', rotate: false });

    const user = await db.user.findUniqueOrThrow({ where: { email }, include: { passwordCredentials: true } });
    expect(user).toMatchObject({ kind: 'admin', status: 'active' });
    expect(await hasher.verify(user.passwordCredentials[0]?.argon2idHash ?? '', sealed.password)).toBe(true);

    // A code from the printed seed, in the next step (the one used to confirm is spent).
    const later = new Date(Date.now() + 2 * PERIOD_SECONDS * 1000);
    expect(await totp.verify({ userId: user.id, code: codeAt(sealed.manualKey, later), at: later })).toBe(true);

    const setting = await db.setting.findUniqueOrThrow({ where: { key: SEALED_ADMIN_KEY } });
    expect(setting.value).toMatchObject({ userId: user.id });
    const audited = await db.auditEvent.findFirstOrThrow({ where: { event: 'admin.sealed', targetId: user.id } });
    // The audit row says it happened; it never carries what was printed.
    expect(JSON.stringify(audited.detail)).not.toContain(sealed.password);
    expect(JSON.stringify(audited.detail)).not.toContain(sealed.manualKey);
  });

  it('refuses an address that already has an account, and a second sealed admin', async () => {
    const taken = `taken-${unique()}@example.com`;
    await db.user.create({ data: { email: taken, username: `taken${unique()}`, displayName: 'Taken', status: 'active' } });
    await expect(sealAdmin(deps, { email: taken, displayName: 'Sealed admin', rotate: false })).rejects.toThrow(SealedAdminError);

    await sealAdmin(deps, { email: `first-${unique()}@example.com`, displayName: 'Sealed admin', rotate: false });
    await expect(sealAdmin(deps, { email: `second-${unique()}@example.com`, displayName: 'Sealed admin', rotate: false })).rejects.toThrow(/already exists/);
  });

  it('rotating makes the old envelope worthless and signs the account out', async () => {
    const email = `rotate-${unique()}@example.com`;
    const first = await sealAdmin(deps, { email, displayName: 'Sealed admin', rotate: false });
    const user = await db.user.findUniqueOrThrow({ where: { email } });
    await db.session.create({ data: { userId: user.id, expiresAt: new Date(Date.now() + 3_600_000) } });

    const second = await sealAdmin(deps, { email, displayName: 'Sealed admin', rotate: true });
    const credential = await db.passwordCredential.findFirstOrThrow({ where: { userId: user.id } });
    expect(await hasher.verify(credential.argon2idHash, first.password)).toBe(false);
    expect(await hasher.verify(credential.argon2idHash, second.password)).toBe(true);

    const later = new Date(Date.now() + 2 * PERIOD_SECONDS * 1000);
    expect(await totp.verify({ userId: user.id, code: codeAt(first.manualKey, later), at: later })).toBe(false);
    expect(await db.session.count({ where: { userId: user.id, revokedAt: null } })).toBe(0);
  });

  it('will not rotate an account that is not the sealed admin', async () => {
    const other = `other-${unique()}@example.com`;
    await db.user.create({ data: { email: other, username: `other${unique()}`, displayName: 'Other', kind: 'admin', status: 'active' } });
    await expect(sealAdmin(deps, { email: other, displayName: 'x', rotate: true })).rejects.toThrow(/not the sealed admin/);
  });
});
