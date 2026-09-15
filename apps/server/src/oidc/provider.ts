import Provider, { type ClientMetadata, type Configuration } from 'oidc-provider';
import type { Db } from '../db.js';
import type { SecretHasher } from '../security/hash.js';
import { createFindAccount } from './account.js';
import { createAdapterFactory } from './adapter.js';
import { installHashedClientSecrets } from './clients.js';
import type { PrivateJwk } from './keys.js';

// Provider configuration per ADR-001 and T-0.7. Every value here narrows the library's
// defaults; none of them bypass its validation (redirect matching, PKCE, alg checks).

export const ACCESS_TOKEN_TTL = 10 * 60;
export const REFRESH_TOKEN_ABSOLUTE_TTL = 30 * 24 * 60 * 60;

/** Endpoints live under /oidc; discovery stays at the issuer root so the issuer is https://auth.d3cloud.io. */
export const ROUTES = {
  authorization: '/oidc/auth',
  token: '/oidc/token',
  userinfo: '/oidc/me',
  jwks: '/oidc/jwks',
  introspection: '/oidc/token/introspection',
  revocation: '/oidc/token/revocation',
  end_session: '/oidc/session/end',
} as const;

export const COOKIE_NAMES = {
  session: '__Host-d3auth_session',
  interaction: '__Host-d3auth_interaction',
  // The provider pins the resume cookie's Path to the resume URL, which __Host- forbids.
  resume: '__Secure-d3auth_resume',
} as const;

export interface ProviderOptions {
  issuer: string;
  db: Db;
  keys: PrivateJwk[];
  clients: ClientMetadata[];
  clientSecretHashes: ReadonlyMap<string, string>;
  hasher: SecretHasher;
  cookieKeys: string[];
  interactionPath: (uid: string) => string;
}

const escapeHtml = (value: unknown): string =>
  String(value).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

export function createProvider(options: ProviderOptions): Provider {
  const configuration: Configuration = {
    adapter: createAdapterFactory(options.db),
    clients: options.clients,
    findAccount: createFindAccount(options.db),
    jwks: { keys: options.keys },
    routes: ROUTES,

    responseTypes: ['code'],
    scopes: ['openid', 'offline_access', 'profile', 'email'],
    claims: {
      openid: ['sub'],
      email: ['email', 'email_verified'],
      profile: ['name', 'preferred_username'],
    },
    clientAuthMethods: ['client_secret_basic', 'none'],
    clientDefaults: {
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      id_token_signed_response_alg: 'ES256',
      token_endpoint_auth_method: 'client_secret_basic',
    },
    enabledJWA: {
      idTokenSigningAlgValues: ['ES256', 'RS256'],
      userinfoSigningAlgValues: ['ES256', 'RS256'],
      introspectionSigningAlgValues: ['ES256', 'RS256'],
      authorizationSigningAlgValues: ['ES256', 'RS256'],
      requestObjectSigningAlgValues: ['ES256', 'RS256'],
      clientAuthSigningAlgValues: ['ES256', 'RS256'],
      dPoPSigningAlgValues: ['ES256'],
    },

    // PKCE S256 on every client, confidential ones included (REQ-003). v9 has no `plain`.
    pkce: { required: () => true },
    allowOmittingSingleRegisteredRedirectUri: false,
    clockTolerance: 60,

    ttl: {
      AccessToken: ACCESS_TOKEN_TTL,
      AuthorizationCode: 60,
      IdToken: 60 * 60,
      Interaction: 60 * 60,
      Session: REFRESH_TOKEN_ABSOLUTE_TTL,
      Grant: REFRESH_TOKEN_ABSOLUTE_TTL,
      // Absolute lifetime: a rotated token inherits what is left of its predecessor.
      RefreshToken: (ctx) => ctx.oidc.entities.RotatedRefreshToken?.remainingTTL ?? REFRESH_TOKEN_ABSOLUTE_TTL,
    },
    // Rotate on every use; reuse of a rotated token revokes the grant (REQ-009).
    rotateRefreshToken: true,
    issueRefreshToken: (_ctx, client) => client.grantTypeAllowed('refresh_token'),

    cookies: {
      keys: options.cookieKeys,
      names: COOKIE_NAMES,
      long: { httpOnly: true, sameSite: 'lax', path: '/' },
      short: { httpOnly: true, sameSite: 'lax', path: '/' },
    },

    interactions: { url: (_ctx, interaction) => options.interactionPath(interaction.uid) },

    features: {
      devInteractions: { enabled: false },
      introspection: {
        enabled: true,
        allowedPolicy: (_ctx, client) => client.clientAuthMethod !== 'none',
      },
      revocation: { enabled: true },
      userinfo: { enabled: true },
      rpInitiatedLogout: { enabled: true },
      registration: { enabled: false },
      claimsParameter: { enabled: false },
      clientCredentials: { enabled: false },
      deviceFlow: { enabled: false },
      encryption: { enabled: false },
      jwtResponseModes: { enabled: false },
      requestObjects: { enabled: false },
      // Available later as flags, off until a consumer needs them (ADR-001).
      pushedAuthorizationRequests: { enabled: false },
      dPoP: { enabled: false },
      resourceIndicators: { enabled: false },
    },

    renderError: (ctx, out) => {
      ctx.type = 'html';
      const detail = Object.entries(out)
        .map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd>`)
        .join('');
      ctx.body = `<!doctype html><meta charset="utf-8"><title>Sign-in error</title><h1>Something went wrong</h1><dl>${detail}</dl>`;
    },
  };

  const provider = new Provider(options.issuer, configuration);
  provider.proxy = true;
  installHashedClientSecrets(provider, options.clientSecretHashes, options.hasher);
  return provider;
}
