import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Db } from '../db.js';

// Trusted devices (REQ-036). After a second factor has been answered, the person may say "don't
// ask on this browser again" and get a cookie that skips the factor step for thirty days.
//
// Three rules keep this honest. The cookie is a bearer token, so only its SHA-256 is stored and
// the value never appears in a log. It is bound to one account: presenting somebody else's cookie
// proves nothing about you. And it is never issued to an account that cannot sign in (REQ-041),
// because a suspension has to take effect everywhere at once, not just where a factor is asked.

export const TRUSTED_DEVICE_DAYS = 30;
const TOKEN_BYTES = 32;

const hashOf = (token: string): string => createHash('sha256').update(token).digest('hex');

/** Constant-time compare, so a near-miss hash takes as long as a wrong one. */
const sameHash = (a: string, b: string): boolean => {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  return left.length === right.length && timingSafeEqual(left, right);
};

export interface TrustedDeviceSummary {
  id: string;
  userAgent: string | null;
  createdAt: Date;
  expiresAt: Date;
  /** True for the browser making this request, so the console can say "this device". */
  current: boolean;
}

export interface TrustedDevices {
  /** Returns the cookie value to set, or undefined when the account may not be trusted. */
  issue(input: { userId: string; userAgent?: string | undefined; now?: Date }): Promise<{ token: string; expiresAt: Date } | undefined>;
  /** Does this cookie still vouch for this account? */
  verify(input: { userId: string; token: string | undefined; now?: Date }): Promise<boolean>;
  list(input: { userId: string; token?: string | undefined }): Promise<TrustedDeviceSummary[]>;
  revoke(input: { userId: string; id: string }): Promise<boolean>;
  /** Used by admin reset (REQ-039) and "sign out everywhere". */
  revokeAll(userId: string): Promise<number>;
}

export function createTrustedDevices(db: Db): TrustedDevices {
  return {
    async issue({ userId, userAgent, now = new Date() }) {
      const user = await db.user.findUnique({ where: { id: userId }, select: { status: true } });
      if (user?.status !== 'active') return undefined;

      const token = randomBytes(TOKEN_BYTES).toString('base64url');
      const expiresAt = new Date(now.getTime() + TRUSTED_DEVICE_DAYS * 24 * 60 * 60 * 1000);
      await db.trustedDevice.create({
        data: { userId, tokenHash: hashOf(token), userAgent: userAgent ?? null, expiresAt },
      });
      return { token, expiresAt };
    },

    async verify({ userId, token, now = new Date() }) {
      if (!token) return false;
      const rows = await db.trustedDevice.findMany({
        where: { userId, revokedAt: null, expiresAt: { gt: now } },
        select: { tokenHash: true },
      });
      const candidate = hashOf(token);
      return rows.some((row) => sameHash(row.tokenHash, candidate));
    },

    async list({ userId, token }) {
      const rows = await db.trustedDevice.findMany({
        where: { userId, revokedAt: null, expiresAt: { gt: new Date() } },
        orderBy: { createdAt: 'desc' },
        select: { id: true, tokenHash: true, userAgent: true, createdAt: true, expiresAt: true },
      });
      const candidate = token ? hashOf(token) : undefined;
      return rows.map(({ tokenHash, ...row }) => ({
        ...row,
        current: candidate !== undefined && sameHash(tokenHash, candidate),
      }));
    },

    async revoke({ userId, id }) {
      const { count } = await db.trustedDevice.updateMany({
        where: { id, userId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      return count > 0;
    },

    async revokeAll(userId) {
      const { count } = await db.trustedDevice.updateMany({
        where: { userId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      return count;
    },
  };
}
