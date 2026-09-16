import { Secret, TOTP } from 'otpauth';
import type { Db } from '../db.js';
import type { KekCrypto } from './kek.js';

// TOTP (REQ-033). Six digits, thirty seconds, one step either side of now — and each code works
// exactly once.
//
// Single use is the part that is easy to leave out and expensive to miss: without it, a code
// read over someone's shoulder, or captured on a phishing page, stays valid for the rest of its
// window. Every successful verification records the step it used, and anything at or below that
// step is refused afterwards.

export const DIGITS = 6;
export const PERIOD_SECONDS = 30;
/** One step either side, so a slightly wrong clock still works. */
export const WINDOW = 1;

const sealContext = (id: string): string => `totp_credential:${id}`;

const stepFor = (at: Date): number => Math.floor(at.getTime() / 1000 / PERIOD_SECONDS);

export interface TotpEnrolment {
  credentialId: string;
  /** For the QR code. Contains the secret, so it is shown once and never logged. */
  uri: string;
  /** For typing into an app by hand. */
  manualKey: string;
}

export interface Totp {
  begin(input: { userId: string; accountName: string; label?: string }): Promise<TotpEnrolment>;
  /** Confirms an enrolment; only a confirmed credential counts as a factor. */
  confirm(input: { userId: string; credentialId: string; code: string; at?: Date }): Promise<boolean>;
  /** Verifies at sign-in against every confirmed credential the user has. */
  verify(input: { userId: string; code: string; at?: Date }): Promise<boolean>;
  list(userId: string): Promise<{ id: string; label: string; confirmedAt: Date | null }[]>;
  remove(input: { userId: string; credentialId: string }): Promise<boolean>;
}

export function createTotp(db: Db, kek: KekCrypto, issuerName: string): Totp {
  const build = (secret: string, accountName: string): TOTP =>
    new TOTP({
      issuer: issuerName,
      label: accountName,
      algorithm: 'SHA1',
      digits: DIGITS,
      period: PERIOD_SECONDS,
      secret: Secret.fromBase32(secret),
    });

  const secretOf = (row: { id: string; secretEncrypted: Uint8Array }): string =>
    kek.decrypt(row.secretEncrypted, sealContext(row.id)).toString('utf8');

  return {
    async begin({ userId, accountName, label }) {
      const secret = new Secret({ size: 20 }).base32;
      // The row exists before the secret is sealed to it, because the context binds to its id.
      const created = await db.totpCredential.create({
        data: { userId, label: label ?? 'Authenticator app', secretEncrypted: new Uint8Array(0) },
      });
      await db.totpCredential.update({
        where: { id: created.id },
        data: { secretEncrypted: kek.encrypt(Buffer.from(secret, 'utf8'), sealContext(created.id)) },
      });
      return { credentialId: created.id, uri: build(secret, accountName).toString(), manualKey: secret };
    },

    async confirm({ userId, credentialId, code, at = new Date() }) {
      const row = await db.totpCredential.findFirst({ where: { id: credentialId, userId } });
      if (!row || row.confirmedAt) return false;

      // The timestamp is passed explicitly: otherwise otpauth validates against the real clock,
      // which makes the caller's notion of "now" a lie.
      const delta = build(secretOf(row), 'confirm').validate({
        token: code.replace(/\s/g, ''),
        window: WINDOW,
        timestamp: at.getTime(),
      });
      if (delta === null) return false;

      await db.totpCredential.update({
        where: { id: row.id },
        data: { confirmedAt: at, lastUsedStep: BigInt(stepFor(at) + delta) },
      });
      return true;
    },

    async verify({ userId, code, at = new Date() }) {
      const rows = await db.totpCredential.findMany({ where: { userId, confirmedAt: { not: null } } });
      const token = code.replace(/\s/g, '');

      for (const row of rows) {
        const delta = build(secretOf(row), 'verify').validate({ token, window: WINDOW, timestamp: at.getTime() });
        if (delta === null) continue;

        const used = stepFor(at) + delta;
        // Replay: this code, or an older one, has already been accepted.
        if (row.lastUsedStep !== null && BigInt(used) <= row.lastUsedStep) return false;

        await db.totpCredential.update({ where: { id: row.id }, data: { lastUsedStep: BigInt(used) } });
        return true;
      }
      return false;
    },

    list(userId) {
      return db.totpCredential.findMany({
        where: { userId },
        orderBy: { id: 'asc' },
        select: { id: true, label: true, confirmedAt: true },
      });
    },

    async remove({ userId, credentialId }) {
      const { count } = await db.totpCredential.deleteMany({ where: { id: credentialId, userId } });
      return count > 0;
    },
  };
}
