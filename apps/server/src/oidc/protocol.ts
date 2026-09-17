// The protocol choices every app has to match, in one place (REQ-142).
//
// The provider configuration, the client metadata and the connection sheet all read these, so the
// sheet an owner copies from cannot say ES256 while the provider signs with something else. Change
// a value here and every one of them changes with it — which is the point, and also why a change
// here is a change for every app already connected.

/** How ID tokens are signed. Apps that default to RS256 (Immich does) fail every sign-in. */
export const ID_TOKEN_SIGNING_ALG = 'ES256';

/** The algorithms the provider will sign with at all. Never `none`, never symmetric. */
export const SIGNING_ALGS = ['ES256', 'RS256'] as const;

/** How each kind of app proves itself at the token endpoint. */
export const TOKEN_ENDPOINT_AUTH_METHOD = {
  confidential_web: 'client_secret_basic',
  public_native: 'none',
} as const;

/** PKCE is required on every client, and `plain` does not exist here (REQ-003). */
export const PKCE_METHOD = 'S256';

/** Ours: asking for it is what puts the roles claim in a token (REQ-052). */
export const ROLES_SCOPE = 'd3:roles';

/** The claim the roles arrive in: an array of this app's role keys, and only this app's. */
export const ROLES_CLAIM = 'roles';

/** What an app asks for to know who somebody is. */
export const IDENTITY_SCOPES = ['openid', 'profile', 'email'] as const;

/** Asked for by an app that keeps people signed in with refresh tokens. */
export const OFFLINE_SCOPE = 'offline_access';

/** Every scope the provider understands. */
export const SUPPORTED_SCOPES = ['openid', OFFLINE_SCOPE, 'profile', 'email', ROLES_SCOPE] as const;

/** Discovery lives at the issuer root, so the issuer is the only address an app needs. */
export const DISCOVERY_PATH = '/.well-known/openid-configuration';
