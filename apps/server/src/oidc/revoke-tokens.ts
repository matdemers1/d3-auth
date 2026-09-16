import { effectiveAccess } from '../authz/effective-roles.js';
import type { Db } from '../db.js';

// Taking tokens back (REQ-051, REQ-056).
//
// Deny-by-default is enforced when somebody *asks* for access. A token already handed out does
// not ask again: an access token is good until it expires, and a refresh token for thirty days.
// So when access is taken away, the tokens that carried it are taken away too — every artefact of
// every provider grant between that person and that app: codes, access tokens, refresh tokens.
//
// The back-channel logout tells the app to end its own session. This is the other half: even an
// app that ignores that message cannot use what it was holding.

type Family = { grantIds: string[] };

/** The provider grants between one person and one app (or every app, when none is named). */
async function familiesOf(db: Db, userId: string, clientId?: string): Promise<Family> {
  const rows = await db.oidcPayload.findMany({
    where: {
      kind: 'Grant',
      payload: { path: ['accountId'], equals: userId },
      ...(clientId ? { AND: [{ payload: { path: ['clientId'], equals: clientId } }] } : {}),
    },
    select: { id: true },
  });
  return { grantIds: rows.map((row) => row.id) };
}

async function destroy(db: Db, { grantIds }: Family): Promise<number> {
  if (grantIds.length === 0) return 0;
  const tokens = await db.oidcPayload.deleteMany({ where: { grantId: { in: grantIds } } });
  await db.oidcPayload.deleteMany({ where: { kind: 'Grant', id: { in: grantIds } } });
  return tokens.count;
}

/** Revokes everything issued to this person for this app. Returns how many tokens went. */
export async function revokeTokens(db: Db, userId: string, clientId: string): Promise<number> {
  return destroy(db, await familiesOf(db, userId, clientId));
}

/** Revokes everything issued to this person for any app — a reset, a lost phone. */
export async function revokeAllTokens(db: Db, userId: string): Promise<number> {
  return destroy(db, await familiesOf(db, userId));
}

/**
 * Revokes only if the change actually left them without access. A group losing an app does not
 * matter to somebody who also holds a direct grant for it; revoking their tokens anyway would sign
 * out people nothing happened to.
 */
export async function revokeTokensIfNoAccess(db: Db, userId: string, clientId: string): Promise<number> {
  const access = await effectiveAccess(db, { userId, clientId });
  return access.hasGrant ? 0 : revokeTokens(db, userId, clientId);
}
