import { isConsoleClient } from '../console/console-client.js';
import type { Db } from '../db.js';

// Who may sign in to what, and as what (REQ-049, REQ-050, REQ-051).
//
// Access is a grant: one person, one app, a set of that app's roles. Access can also come from a
// group the person belongs to, and the two add up — the union, never the intersection, and never
// "the group wins". Somebody given `admin` directly and `member` through a group has both.
//
// There is no implicit access. An account with neither a direct grant nor a group grant cannot
// sign in to the app at all, whatever else is true about the account. That is the invariant the
// rest of the system is built on, and the one worth being boring about: one decision, at the
// moment it is needed, from the database.

export interface EffectiveAccess {
  /** False means access_denied, before any interstitial (REQ-051). */
  hasGrant: boolean;
  /** Role keys, highest first by the app's manifest order, with duplicates collapsed. */
  roles: string[];
  /** Where the access came from. The console shows it; a token never does (REQ-053). */
  from: { direct: boolean; groups: string[] };
  /** Null until their first completed sign-in to this app — the continue-as cue (REQ-059). */
  firstSignInAt: Date | null;
}

export const NO_ACCESS: EffectiveAccess = { hasGrant: false, roles: [], from: { direct: false, groups: [] }, firstSignInAt: null };

/**
 * The one exception, and it is not an app: the console's own client (ADR-005). Every account may
 * sign in to its own account page, with no roles and no interstitial. It is decided by client id
 * alone, which no registered app can take, and the account must still be able to sign in at all —
 * `findAccount` refuses anybody invited or suspended before this is ever asked.
 */
const CONSOLE_ACCESS: EffectiveAccess = { hasGrant: true, roles: [], from: { direct: false, groups: [] }, firstSignInAt: new Date(0) };

type RoleRow = { role: { key: string; sortOrder: number } };

/** Highest first by the app's own manifest order, so a caller never has to sort again. */
const orderedKeys = (rows: RoleRow[]): string[] => {
  const byKey = new Map<string, number>();
  for (const { role } of rows) byKey.set(role.key, Math.max(byKey.get(role.key) ?? -Infinity, role.sortOrder));
  return [...byKey.entries()].sort((a, b) => b[1] - a[1]).map(([key]) => key);
};

/**
 * What this person may do in this app, right now.
 *
 * A disabled app answers "no access" rather than "no roles": disabling is meant to stop sign-in,
 * and a caller that only looked at `roles` would otherwise let somebody in with none.
 */
export async function effectiveAccess(db: Db, input: { userId: string; clientId: string }): Promise<EffectiveAccess> {
  if (isConsoleClient(input.clientId)) return CONSOLE_ACCESS;
  const [direct, viaGroups, visit] = await Promise.all([
    db.grant.findFirst({
      where: { userId: input.userId, app: { clientId: input.clientId, enabled: true } },
      select: { roles: { select: { role: { select: { key: true, sortOrder: true } } } } },
    }),
    db.groupGrant.findMany({
      where: {
        app: { clientId: input.clientId, enabled: true },
        group: { members: { some: { userId: input.userId } } },
      },
      select: { group: { select: { name: true } }, roles: { select: { role: { select: { key: true, sortOrder: true } } } } },
    }),
    db.appVisit.findFirst({
      where: { userId: input.userId, app: { clientId: input.clientId } },
      select: { firstSignInAt: true },
    }),
  ]);

  if (!direct && viaGroups.length === 0) return NO_ACCESS;

  // A grant with no roles is still a grant: the app decides what an unroled person may see.
  const rows = [...(direct?.roles ?? []), ...viaGroups.flatMap((grant) => grant.roles)];
  return {
    hasGrant: true,
    roles: orderedKeys(rows),
    from: { direct: direct !== null, groups: viaGroups.map((grant) => grant.group.name) },
    firstSignInAt: visit?.firstSignInAt ?? null,
  };
}
