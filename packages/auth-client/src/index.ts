// D3 Auth relying-party SDK for TypeScript.
//
// Ten rules make up the consumer contract (docs/consumer-contract.md); this package exists so a
// consuming app gets the four easiest to get wrong for free: a pinned algorithm list, identity by
// (iss, sub), roles refreshed on every renewal, and a back-channel logout handler that is
// idempotent by jti.

export { createAuthClient, SsoUnavailable, type AuthClient, type AuthClientOptions, type Session, type SignInStart, type SsoMode } from './client.js';
export { identityKey, isSameIdentity, type Identity } from './identity.js';
export {
  ALLOWED_ALGORITHMS,
  createBackchannelHandler,
  inMemorySeen,
  jwksFor,
  LOGOUT_EVENT,
  LogoutTokenError,
  verifyLogoutToken,
  type BackchannelHandlerOptions,
  type LogoutTokenOptions,
  type VerifiedLogout,
} from './logout-token.js';
