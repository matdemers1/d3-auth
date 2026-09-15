import type { FindAccount } from 'oidc-provider';
import type { Db } from '../db.js';

// Maps `sub` to a user. Only active users are accounts; invited and suspended users are not,
// so their sessions and refresh tokens stop working without extra checks.
export function createFindAccount(db: Db): FindAccount {
  return async (_ctx, sub) => {
    const user = await db.user.findUnique({ where: { id: sub } });
    if (user?.status !== 'active') return undefined;
    return {
      accountId: user.id,
      claims: () => ({
        sub: user.id,
        email: user.email,
        email_verified: user.emailVerified,
        preferred_username: user.username,
        name: user.displayName,
      }),
    };
  };
}
