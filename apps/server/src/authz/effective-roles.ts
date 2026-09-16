import type { Db } from '../db.js';

// Who may sign in to what, and as what (REQ-049, REQ-050, REQ-051).
//
// Access is a grant: one person, one app, a set of that app's roles. There is no implicit
// access — an account with no grant for the client cannot sign in to it at all, whatever else is
// true about the account. That is the invariant the rest of the system is built on, and the one
// worth being boring about: no caching, no clever fallbacks, one query at the moment of decision.
//
// Group grants join the union in P4 (REQ-050). The shape below already answers "and where did
// this role come from", so adding them does not change any caller.

export interface EffectiveAccess {
  /** False means access_denied, before any interstitial (REQ-051). */
  hasGrant: boolean;
  /** Role keys, highest first by the app's manifest order. */
  roles: string[];
  /** Null until their first completed sign-in to this app — the continue-as cue (REQ-059). */
  firstSignInAt: Date | null;
}

export const NO_ACCESS: EffectiveAccess = { hasGrant: false, roles: [], firstSignInAt: null };

/**
 * What this person may do in this app, right now.
 *
 * A disabled app answers "no access" rather than "no roles": disabling is meant to stop sign-in,
 * and a caller that only looked at `roles` would otherwise let somebody in with none.
 */
export async function effectiveAccess(db: Db, input: { userId: string; clientId: string }): Promise<EffectiveAccess> {
  const grant = await db.grant.findFirst({
    where: { userId: input.userId, app: { clientId: input.clientId, enabled: true } },
    select: { firstSignInAt: true, roles: { select: { role: { select: { key: true, sortOrder: true } } } } },
  });
  if (!grant) return NO_ACCESS;

  const roles = grant.roles
    .map((row) => row.role)
    .sort((a, b) => b.sortOrder - a.sortOrder)
    .map((role) => role.key);
  // A grant with no roles is still a grant: the app decides what an unroled person may see.
  return { hasGrant: true, roles, firstSignInAt: grant.firstSignInAt };
}
