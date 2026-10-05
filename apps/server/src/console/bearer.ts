import type { Request } from 'express';
import { createLocalJWKSet, jwtVerify, type JWK } from 'jose';
import type { AdapterFactory } from 'oidc-provider';
import { CONSTELLATION_CLIENT_ID } from '../admin/presets/constellation.js';
import { effectiveAccess } from '../authz/effective-roles.js';
import type { Db } from '../db.js';
import type { UserModel as User } from '../generated/prisma/models.js';
import { SIGNING_ALGS } from '../oidc/keys.js';

// D3 Constellation on D3 Auth's own APIs (AUTH-T-9.5, AUTH-ADR-008).
//
// The app holds no cookie. It presents the access token its grant mints for D3 Auth's own
// audience, and that is checked here completely: signed by one of this provider's keys, issued by
// this issuer, audienced at it, unexpired, minted for Constellation's client — and then against
// the database, so a token is only as good as what still stands behind it: an active person, their
// access to Constellation, and the grant itself (signing out or revoking ends it at once rather
// than when the token expires).

export interface BearerUser {
  user: User;
  /** The provider's grant the token came from: what native step-up is recorded against. */
  grantId: string;
}

/** The Bearer token in a request, if it carries one. */
export function bearerOf(req: Request): string | null {
  const header = req.get('authorization') ?? '';
  const [scheme, value] = header.split(' ', 2);
  return scheme?.toLowerCase() === 'bearer' && value !== undefined && value.length > 0 ? value : null;
}

export interface BearerVerifier {
  verify(token: string): Promise<BearerUser | undefined>;
}

export function createBearerVerifier(input: { db: Db; adapterFactory: AdapterFactory; issuer: string; publicKeys: readonly JWK[] }): BearerVerifier {
  const { db } = input;
  const self = input.issuer.replace(/\/+$/, '');
  const keys = createLocalJWKSet({ keys: [...input.publicKeys] });
  const grants = input.adapterFactory('Grant');

  return {
    async verify(token) {
      let payload: Record<string, unknown>;
      try {
        ({ payload } = await jwtVerify(token, keys, {
          issuer: input.issuer,
          audience: self,
          algorithms: [...SIGNING_ALGS],
          typ: 'at+jwt',
          requiredClaims: ['exp', 'sub', 'client_id'],
        }));
      } catch {
        return undefined;
      }
      const grantId = payload['gid'];
      if (payload['client_id'] !== CONSTELLATION_CLIENT_ID || typeof grantId !== 'string' || typeof payload['sub'] !== 'string') return undefined;
      // Revoked or signed out: the grant is gone, and so is every token it minted.
      if (!(await grants.find(grantId))) return undefined;
      const user = await db.user.findUnique({ where: { id: payload['sub'] } });
      if (user?.status !== 'active') return undefined;
      if (!(await effectiveAccess(db, { userId: user.id, clientId: CONSTELLATION_CLIENT_ID })).hasGrant) return undefined;
      return { user, grantId };
    },
  };
}
