import type { Db } from '../db.js';
import type { ThrottleScope } from '../generated/prisma/enums.js';

// Sign-in throttling (REQ-027, REQ-028). Two independent counters, both checked *before* any
// Argon2id work, so guessing costs the attacker time and costs us nothing.
//
// Per account: 4 free attempts, then a doubling delay capped at 10 minutes.
// Per IP (CF-Connecting-IP): 20 free, then the same doubling — deliberately loose, because a
// household shares one address (R-07).
//
// This is a soft delay, never a lockout: the counter only ever postpones the next attempt, and a
// successful sign-in clears it. Nobody can lock a person out by guessing at their email.

export interface ThrottlePolicy {
  freeAttempts: number;
  baseDelaySeconds: number;
  maxDelaySeconds: number;
}

export const ACCOUNT_POLICY: ThrottlePolicy = { freeAttempts: 4, baseDelaySeconds: 2, maxDelaySeconds: 600 };
export const IP_POLICY: ThrottlePolicy = { freeAttempts: 20, baseDelaySeconds: 2, maxDelaySeconds: 600 };

/** Counters older than this are noise; a prune job removes them (Data Model: Retention). */
export const RETENTION_DAYS = 90;

export const policyFor = (scope: ThrottleScope): ThrottlePolicy => (scope === 'account' ? ACCOUNT_POLICY : IP_POLICY);

/** Seconds to wait after `failures` consecutive failures. Pure, so the maths is unit-tested. */
export function delayAfter(failures: number, policy: ThrottlePolicy): number {
  const over = failures - policy.freeAttempts;
  if (over <= 0) return 0;
  const doubled = policy.baseDelaySeconds * 2 ** (over - 1);
  return Math.min(doubled, policy.maxDelaySeconds);
}

export interface ThrottleDecision {
  allowed: boolean;
  /** Seconds to put in `Retry-After`; 0 when allowed. */
  retryAfterSeconds: number;
  /** The scope that blocked the attempt, for the audit event. */
  scope?: ThrottleScope;
}

const ALLOWED: ThrottleDecision = { allowed: true, retryAfterSeconds: 0 };

export interface Throttle {
  check(keys: ThrottleKeys, now?: Date): Promise<ThrottleDecision>;
  recordFailure(keys: ThrottleKeys, now?: Date): Promise<void>;
  clear(keys: ThrottleKeys): Promise<void>;
  prune(before: Date): Promise<number>;
}

export interface ThrottleKeys {
  /** Lower-cased email as typed, so an unknown address is throttled the same way. */
  account: string;
  ip?: string | undefined;
}

const secondsUntil = (until: Date, now: Date): number => Math.max(1, Math.ceil((until.getTime() - now.getTime()) / 1000));

export function createThrottle(db: Db): Throttle {
  const pairs = (keys: ThrottleKeys): { scope: ThrottleScope; key: string }[] => [
    { scope: 'account' as const, key: keys.account.trim().toLowerCase() },
    ...(keys.ip ? [{ scope: 'ip' as const, key: keys.ip }] : []),
  ];

  return {
    async check(keys, now = new Date()) {
      const rows = await db.throttleCounter.findMany({
        where: { OR: pairs(keys).map(({ scope, key }) => ({ scope, key })) },
      });
      const blocking = rows
        .filter((row) => row.blockedUntil && row.blockedUntil > now)
        .sort((a, b) => (b.blockedUntil?.getTime() ?? 0) - (a.blockedUntil?.getTime() ?? 0))[0];
      if (!blocking?.blockedUntil) return ALLOWED;
      return { allowed: false, retryAfterSeconds: secondsUntil(blocking.blockedUntil, now), scope: blocking.scope };
    },

    async recordFailure(keys, now = new Date()) {
      for (const { scope, key } of pairs(keys)) {
        const existing = await db.throttleCounter.findUnique({ where: { scope_key: { scope, key } } });
        const failures = (existing?.failures ?? 0) + 1;
        const delay = delayAfter(failures, policyFor(scope));
        const blockedUntil = delay > 0 ? new Date(now.getTime() + delay * 1000) : null;
        await db.throttleCounter.upsert({
          where: { scope_key: { scope, key } },
          create: { scope, key, failures, firstFailureAt: now, lastFailureAt: now, blockedUntil },
          update: { failures, lastFailureAt: now, blockedUntil },
        });
      }
    },

    async clear(keys) {
      await db.throttleCounter.deleteMany({ where: { OR: pairs(keys).map(({ scope, key }) => ({ scope, key })) } });
    },

    async prune(before) {
      const { count } = await db.throttleCounter.deleteMany({ where: { lastFailureAt: { lt: before } } });
      return count;
    },
  };
}
