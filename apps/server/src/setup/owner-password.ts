import { AUDIT_EVENTS } from '../audit/events.js';
import type { AuditWriter } from '../audit/writer.js';
import type { Db } from '../db.js';
import { revokeAllTokens } from '../oidc/revoke-tokens.js';
import { verifiedFactorCount } from '../security/factors.js';
import type { SecretHasher } from '../security/hash.js';
import { checkPassword } from '../security/policy.js';

// A forgotten owner password, from the host (REQ-145, ADR-010).
//
// Break-glass (`recover`) is for the owner who lost their factors and still knows the password.
// This is the other half: the owner who knows their factors and lost the password. Nobody can reset
// the owner from the console (`owner_protected`), so before this the only way back was a
// hand-written UPDATE — no policy check, no audit row, nobody told.
//
// It replaces the password and leaves every factor where it is. That is the line that keeps a
// shell on the host from being the owner's account on its own: set-password still meets the second
// step, and recover still needs the password. Running both is loud twice over.

export class OwnerPasswordError extends Error {}

export interface OwnerPasswordResult {
  email: string;
  sessionsEnded: number;
  /** Zero means the next sign-in is password-only: the CLI says so. */
  factors: number;
}

export async function setOwnerPassword(
  deps: { db: Db; hasher: SecretHasher; audit: AuditWriter },
  input: { email: string; password: string },
): Promise<OwnerPasswordResult> {
  const { db, hasher, audit } = deps;
  const email = input.email.trim().toLowerCase();
  const user = await db.user.findUnique({ where: { email } });
  if (!user) throw new OwnerPasswordError(`No account for ${email}.`);
  if (user.kind !== 'owner') {
    throw new OwnerPasswordError(`${email} is not the owner. Reset anybody else from the console: People → them → Reset.`);
  }
  if (user.status !== 'active') throw new OwnerPasswordError(`${email} is ${user.status}, not active; finish first-run setup instead.`);

  const policy = checkPassword(input.password, { email: user.email, username: user.username, displayName: user.displayName });
  if (!policy.ok) throw new OwnerPasswordError(policy.problems.join(' '));

  const argon2idHash = await hasher.hash(input.password);

  // Every session belonged to the old password — the provider's rows too, since this runs from a
  // shell with no provider to ask. The throttle goes as well: a lockout earned by typing the
  // password that no longer exists would only stand between the owner and the new one.
  const sessions = await db.session.findMany({ where: { userId: user.id, revokedAt: null }, select: { oidcSessionUid: true } });
  const uids = sessions.flatMap((row) => (row.oidcSessionUid ? [row.oidcSessionUid] : []));
  await db.$transaction([
    db.passwordCredential.deleteMany({ where: { userId: user.id } }),
    db.passwordCredential.create({ data: { userId: user.id, argon2idHash } }),
    db.oidcPayload.deleteMany({ where: { kind: 'Session', uid: { in: uids } } }),
    db.session.updateMany({ where: { userId: user.id, revokedAt: null }, data: { revokedAt: new Date() } }),
    db.throttleCounter.deleteMany({ where: { scope: 'account', key: email } }),
  ]);
  await revokeAllTokens(db, user.id);

  const factors = await verifiedFactorCount(db, user.id);
  await audit.write({
    event: AUDIT_EVENTS.passwordSetFromHost,
    targetType: 'user',
    targetId: user.id,
    detail: { email, by: 'host', sessionsEnded: sessions.length, factors },
  });
  return { email, sessionsEnded: sessions.length, factors };
}
