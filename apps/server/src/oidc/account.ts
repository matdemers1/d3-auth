import type { FindAccount } from 'oidc-provider';
import { effectiveAccess } from '../authz/effective-roles.js';
import type { Db } from '../db.js';
import { ROLES_CLAIM, ROLES_SCOPE } from './protocol.js';

// Maps `sub` to a user. Only active users are accounts; invited and suspended users are not,
// so their sessions and refresh tokens stop working without extra checks.
//
// The `roles` claim is scoped to the client asking for it (REQ-052). It is computed here, at the
// moment a token or a userinfo response is built, from the grant that exists then — not from
// anything carried along in the session — so roles taken away are gone from the next renewal,
// and one app's roles can never appear in another app's token.
export function createFindAccount(db: Db): FindAccount {
  return async (ctx, sub) => {
    const user = await db.user.findUnique({ where: { id: sub } });
    if (user?.status !== 'active') return undefined;

    // Whoever is asking: the client in the authorization request, or the one presenting the
    // token at userinfo.
    const clientId = ctx.oidc.client?.clientId;

    return {
      accountId: user.id,
      async claims(_use, scope) {
        const base = {
          sub: user.id,
          email: user.email,
          email_verified: user.emailVerified,
          preferred_username: user.username,
          name: user.displayName,
        };
        if (!clientId || !scope.split(' ').includes(ROLES_SCOPE)) return base;

        const access = await effectiveAccess(db, { userId: user.id, clientId });
        return { ...base, [ROLES_CLAIM]: access.roles };
      },
    };
  };
}
