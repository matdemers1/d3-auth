import type { Db } from '../db.js';
import type { UserKind } from '../generated/prisma/enums.js';

// The rule that decides who must be able to prove it is them with something other than a
// password (REQ-035, REQ-042).
//
// It lives in one place because it is enforced from two directions that must agree: an account
// cannot be *made* an admin without a factor, and an admin cannot *remove* their way down to
// none. If those two ever disagreed, the system would have an admin who cannot be asked to prove
// anything — which is the state this rule exists to prevent.

/** Owners and admins must hold at least one verified factor. Guests may, and often will not. */
export const mustHoldFactor = (kind: UserKind): boolean => kind === 'owner' || kind === 'admin';

/** Passkeys plus *confirmed* authenticator apps: an unconfirmed enrolment proves nothing. */
export async function verifiedFactorCount(db: Db, userId: string): Promise<number> {
  const [passkeys, codes] = await Promise.all([
    db.webauthnCredential.count({ where: { userId } }),
    db.totpCredential.count({ where: { userId, confirmedAt: { not: null } } }),
  ]);
  return passkeys + codes;
}
