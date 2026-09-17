import { randomBytes } from 'node:crypto';
import { Secret, TOTP } from 'otpauth';
import { AUDIT_EVENTS } from '../audit/events.js';
import type { AuditWriter } from '../audit/writer.js';
import type { Db } from '../db.js';
import { revokeAllTokens } from '../oidc/revoke-tokens.js';
import type { SecretHasher } from '../security/hash.js';
import { DIGITS, PERIOD_SECONDS, type Totp } from '../security/totp.js';

// The sealed second admin (T-6.5, REQ-123, R-06).
//
// If the owner loses every factor at once, break-glass needs a shell on the host. The sealed admin
// is the other way back in: an admin account whose password and authenticator seed are printed
// once, put in an envelope, and not touched. Opening the envelope is meant to be loud — the alert
// rules email the moment this account signs in — and after any use, the credentials are rotated and
// sealed again, so an envelope that has been opened is never still valid.

export const SEALED_ADMIN_KEY = 'sealed_admin';

export interface SealedCredentials {
  email: string;
  password: string;
  /** Typed into an authenticator app by hand, or rendered as a QR code from `uri`. */
  manualKey: string;
  uri: string;
}

export class SealedAdminError extends Error {}

/** A password nobody will ever type from memory: 32 random bytes, grouped so it can be copied off paper. */
const printablePassword = (): string =>
  randomBytes(24)
    .toString('base64url')
    .match(/.{1,8}/g)
    ?.join('-') ?? randomBytes(24).toString('base64url');

export async function sealAdmin(
  deps: { db: Db; hasher: SecretHasher; totp: Totp; audit: AuditWriter },
  input: { email: string; displayName: string; rotate: boolean },
): Promise<SealedCredentials> {
  const { db, hasher, totp, audit } = deps;
  const email = input.email.trim().toLowerCase();
  const existing = await db.user.findUnique({ where: { email } });
  const record = await db.setting.findUnique({ where: { key: SEALED_ADMIN_KEY } });
  const sealedId = (record?.value as { userId?: string } | null)?.userId;

  if (input.rotate) {
    if (!existing || existing.id !== sealedId) throw new SealedAdminError(`${email} is not the sealed admin; nothing to rotate.`);
  } else {
    if (existing) throw new SealedAdminError(`${email} already has an account. The sealed admin must be an account used for nothing else.`);
    if (sealedId) throw new SealedAdminError('A sealed admin already exists. Rotate it with --rotate rather than making a second.');
  }

  const password = printablePassword();
  const user = existing
    ? await db.user.update({ where: { id: existing.id }, data: { status: 'active', kind: 'admin' } })
    : await db.user.create({
        data: { email, username: `sealed-${randomBytes(3).toString('hex')}`, displayName: input.displayName, kind: 'admin', status: 'active', emailVerified: true },
      });

  // Everything that could still let the last envelope in goes: password, factors, devices, and
  // sessions — the provider's own rows too, since this runs from a shell with no provider to ask.
  const sessions = await db.session.findMany({ where: { userId: user.id, revokedAt: null, oidcSessionUid: { not: null } }, select: { oidcSessionUid: true } });
  await db.$transaction([
    db.passwordCredential.deleteMany({ where: { userId: user.id } }),
    db.totpCredential.deleteMany({ where: { userId: user.id } }),
    db.webauthnCredential.deleteMany({ where: { userId: user.id } }),
    db.trustedDevice.updateMany({ where: { userId: user.id, revokedAt: null }, data: { revokedAt: new Date() } }),
    db.oidcPayload.deleteMany({ where: { kind: 'Session', uid: { in: sessions.map((row) => row.oidcSessionUid ?? '') } } }),
    db.session.updateMany({ where: { userId: user.id, revokedAt: null }, data: { revokedAt: new Date() } }),
  ]);
  await revokeAllTokens(db, user.id);
  await db.passwordCredential.create({ data: { userId: user.id, argon2idHash: await hasher.hash(password) } });

  // An admin must hold a factor (REQ-035), so the authenticator is enrolled and confirmed here, with
  // a code computed from the seed about to be printed.
  const enrolment = await totp.begin({ userId: user.id, accountName: email, label: 'Sealed envelope' });
  const code = new TOTP({ secret: Secret.fromBase32(enrolment.manualKey), digits: DIGITS, period: PERIOD_SECONDS }).generate();
  if (!(await totp.confirm({ userId: user.id, credentialId: enrolment.credentialId, code }))) {
    throw new SealedAdminError('The authenticator could not be confirmed; nothing has been printed.');
  }

  await db.setting.upsert({
    where: { key: SEALED_ADMIN_KEY },
    create: { key: SEALED_ADMIN_KEY, value: { userId: user.id, sealedAt: new Date().toISOString() } },
    update: { value: { userId: user.id, sealedAt: new Date().toISOString() } },
  });
  await audit.write({ event: AUDIT_EVENTS.adminSealed, targetType: 'user', targetId: user.id, detail: { rotated: input.rotate } });

  return { email, password, manualKey: enrolment.manualKey, uri: enrolment.uri };
}
