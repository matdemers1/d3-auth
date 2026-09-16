import * as oidc from 'openid-client';
import { type Identity } from './identity.js';
import { ALLOWED_ALGORITHMS } from './logout-token.js';

// The relying-party half of a sign-in (REQ-088, REQ-094, REQ-095, REQ-096, REQ-097).
//
// This wraps `openid-client` rather than reimplementing OAuth, and adds the four things a
// consumer of *this* provider needs: a pinned algorithm list, identity by `(iss, sub)`, roles
// refreshed from userinfo on every token renewal, and an `ssoMode` so an app can decide what to
// do when the provider is unreachable.

export type SsoMode = 'off' | 'optional' | 'required';

export interface AuthClientOptions {
  /** The provider, e.g. https://auth.d3cloud.io. */
  issuer: string;
  clientId: string;
  /** Omit for a native or single-page app; those prove themselves with PKCE alone. */
  clientSecret?: string;
  redirectUri: string;
  /** `d3:roles` is what makes the roles claim appear at all. */
  scope?: string;
  ssoMode?: SsoMode;
  /** Swap in for tests. */
  fetch?: typeof fetch;
}

export interface SignInStart {
  /** Send the person here. */
  url: string;
  /** Keep these three for the callback; they are what make the round trip safe. */
  verifier: string;
  state: string;
  nonce: string;
}

export interface Session {
  identity: Identity;
  accessToken: string;
  refreshToken?: string;
  /** When the access token stops working, as epoch seconds. */
  expiresAt?: number;
  /** The session the provider knows this by, for back-channel logout. */
  sid?: string;
  idToken: string;
}

export class SsoUnavailable extends Error {
  constructor(readonly detail: string) {
    super(`the sign-in provider is not available: ${detail}`);
    this.name = 'SsoUnavailable';
  }
}

const rolesOf = (claims: Record<string, unknown> | undefined): string[] => {
  const roles = claims?.roles;
  return Array.isArray(roles) ? roles.filter((role): role is string => typeof role === 'string') : [];
};

export interface AuthClient {
  readonly ssoMode: SsoMode;
  /** Can people sign in right now? Used to decide whether to offer the button (REQ-102). */
  healthy(): Promise<boolean>;
  beginSignIn(extra?: Record<string, string>): Promise<SignInStart>;
  completeSignIn(callbackUrl: string | URL, start: Pick<SignInStart, 'verifier' | 'state' | 'nonce'>): Promise<Session>;
  /** Renews the access token *and* the roles, because roles change between renewals (REQ-097). */
  refresh(refreshToken: string): Promise<Session>;
  /** The roles this person has in this app right now. */
  rolesNow(accessToken: string, sub: string): Promise<string[]>;
  endSessionUrl(input: { idToken: string; returnTo?: string }): Promise<string>;
}

export async function createAuthClient(options: AuthClientOptions): Promise<AuthClient> {
  const issuer = options.issuer.replace(/\/$/, '');
  const scope = options.scope ?? 'openid profile email d3:roles offline_access';
  const ssoMode = options.ssoMode ?? 'optional';
  const doFetch = options.fetch ?? fetch;

  const auth = options.clientSecret ? oidc.ClientSecretBasic(options.clientSecret) : oidc.None();
  const config = await oidc
    .discovery(new URL(issuer), options.clientId, undefined, auth, {
      [oidc.customFetch]: (url, init) => doFetch(url, init as RequestInit),
    })
    .catch((err: unknown) => {
      throw new SsoUnavailable(err instanceof Error ? err.message : 'discovery failed');
    });
  config[oidc.customFetch] = (url, init) => doFetch(url, init as RequestInit);

  /**
   * The pinned algorithm list (REQ-094, REQ-095). `openid-client` checks the signature against
   * the provider's JWKS; this makes sure the algorithm it accepted is one we are willing to
   * trust — never `none`, and never a symmetric one, where the key that verifies is the key that
   * signs.
   */
  const checkAlgorithm = (idToken: string): void => {
    const header = JSON.parse(Buffer.from(idToken.split('.')[0] ?? '', 'base64url').toString('utf8')) as { alg?: unknown };
    const alg = typeof header.alg === 'string' ? header.alg : '';
    if (!(ALLOWED_ALGORITHMS as readonly string[]).includes(alg)) {
      throw new Error(`refusing an ID token signed with "${alg || 'none'}"`);
    }
  };

  const sessionFrom = async (tokens: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers): Promise<Session> => {
    const idToken = tokens.id_token ?? '';
    if (!idToken) throw new Error('the provider returned no ID token');
    checkAlgorithm(idToken);

    const claims = tokens.claims() as unknown as Record<string, unknown> | undefined;
    const sub = typeof claims?.sub === 'string' ? claims.sub : '';
    const iss = typeof claims?.iss === 'string' ? claims.iss : issuer;
    if (!sub) throw new Error('the ID token has no subject');

    // Roles come from userinfo when the token did not carry them, so a caller always gets the
    // current answer rather than whatever the last sign-in happened to include.
    let roles = rolesOf(claims);
    if (roles.length === 0 && tokens.access_token) {
      roles = rolesOf(await oidc.fetchUserInfo(config, tokens.access_token, sub));
    }

    return {
      identity: { iss, sub, claims: claims ?? {}, roles },
      accessToken: tokens.access_token,
      ...(tokens.refresh_token ? { refreshToken: tokens.refresh_token } : {}),
      ...(tokens.expiresIn() ? { expiresAt: Math.floor(Date.now() / 1000) + (tokens.expiresIn() ?? 0) } : {}),
      ...(typeof claims?.sid === 'string' ? { sid: claims.sid } : {}),
      idToken,
    };
  };

  return {
    ssoMode,

    async healthy() {
      try {
        const response = await doFetch(`${issuer}/readyz`, { redirect: 'manual' });
        return response.ok;
      } catch {
        return false;
      }
    },

    async beginSignIn(extra = {}) {
      const verifier = oidc.randomPKCECodeVerifier();
      const state = oidc.randomState();
      const nonce = oidc.randomNonce();
      const url = oidc.buildAuthorizationUrl(config, {
        redirect_uri: options.redirectUri,
        scope,
        code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
        code_challenge_method: 'S256',
        state,
        nonce,
        ...extra,
      });
      return { url: url.toString(), verifier, state, nonce };
    },

    async completeSignIn(callbackUrl, start) {
      const tokens = await oidc.authorizationCodeGrant(config, new URL(callbackUrl), {
        pkceCodeVerifier: start.verifier,
        expectedState: start.state,
        expectedNonce: start.nonce,
      });
      return sessionFrom(tokens);
    },

    async refresh(refreshToken) {
      const tokens = await oidc.refreshTokenGrant(config, refreshToken);
      return sessionFrom(tokens);
    },

    async rolesNow(accessToken, sub) {
      return rolesOf(await oidc.fetchUserInfo(config, accessToken, sub));
    },

    endSessionUrl({ idToken, returnTo }) {
      const url = oidc.buildEndSessionUrl(config, {
        id_token_hint: idToken,
        ...(returnTo ? { post_logout_redirect_uri: returnTo } : {}),
      });
      return Promise.resolve(url.toString());
    },
  };
}
