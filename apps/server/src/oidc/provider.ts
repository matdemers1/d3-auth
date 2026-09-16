import Provider, { type AdapterFactory, type Configuration } from 'oidc-provider';
import type { Db } from '../db.js';
import type { SecretHasher } from '../security/hash.js';
import { createFindAccount } from './account.js';
import { effectiveAccess } from '../authz/effective-roles.js';
import { createAdapterFactory } from './adapter.js';
import { createClientAdapter, installHashedClientSecrets } from './clients.js';
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

/**
 * Prefixed names require the Secure attribute, which a browser will not accept over plain http —
 * so a local http issuer (config allows that only for localhost and *.test) uses plain names.
 * Production is always https and always prefixed.
 */
export const cookieNamesFor = (secure: boolean): Record<'session' | 'interaction' | 'resume', string> =>
  secure ? { ...COOKIE_NAMES } : { session: 'd3auth_session', interaction: 'd3auth_interaction', resume: 'd3auth_resume' };

/**
 * Ours, not the provider's: the trusted-device cookie (REQ-036). It is kept out of the provider's
 * own cookie names so nothing here can be mistaken for part of the protocol.
 */
export const deviceCookieNameFor = (secure: boolean): string => (secure ? '__Host-d3auth_device' : 'd3auth_device');

export interface ProviderOptions {
  issuer: string;
  db: Db;
  keys: PrivateJwk[];
  hasher: SecretHasher;
  cookieKeys: string[];
  interactionPath: (uid: string) => string;
  /** Shown on the logout confirmation, e.g. "Matthew". */
  operatorDisplayName?: string;
  /** False only for a local http issuer, where prefixed cookie names cannot be used. */
  secureCookies?: boolean;
  /** Conformance-suite clients exempt from PKCE; config refuses this outside *.test issuers. */
  pkceExemptClientIds?: readonly string[];
}

/** Everything goes to the payload table except `Client`, which is served from the App table. */
function clientBackedAdapters(db: Db): AdapterFactory {
  const payloads = createAdapterFactory(db);
  const clients = createClientAdapter(db);
  return (kind: string) => (kind === 'Client' ? clients : payloads(kind));
}

const escapeHtml = (value: unknown): string =>
  String(value).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

export function createProvider(options: ProviderOptions): Provider {
  const pkceExempt = new Set(options.pkceExemptClientIds ?? []);
  const operatorDisplayName = options.operatorDisplayName ?? 'D3 Auth';
  const configuration: Configuration = {
    // Clients come from the App table through the adapter (T-3.1), so registering an app takes
    // effect without a restart. There are deliberately no static clients.
    adapter: clientBackedAdapters(options.db),
    findAccount: createFindAccount(options.db),

    /**
     * Called on every authorization request, before any interaction is decided. This is where
     * deny-by-default actually bites (REQ-051): a person with no grant for this client gets no
     * existing grant back, so the provider raises an interaction, and the interaction refuses
     * them. Without this hook a returning user with a stored provider grant would skip the
     * interaction entirely — and a revocation would not be felt until their tokens expired.
     *
     * When they *do* have access, a grant is minted covering what was asked for, which is what
     * makes the consent screen unnecessary rather than merely hidden (REQ-060).
     */
    async loadExistingGrant(ctx) {
      const accountId = ctx.oidc.session?.accountId;
      const client = ctx.oidc.client;
      if (!accountId || !client) return undefined;

      const access = await effectiveAccess(options.db, { userId: accountId, clientId: client.clientId });
      if (!access.hasGrant) return undefined;

      const grantId = ctx.oidc.result?.consent?.grantId ?? ctx.oidc.session?.grantIdFor(client.clientId);
      if (grantId) {
        const existing = await ctx.oidc.provider.Grant.find(grantId);
        if (existing) return existing;
      }

      const grant = new ctx.oidc.provider.Grant({ accountId, clientId: client.clientId });
      const requested = ctx.oidc.params?.scope;
      grant.addOIDCScope(typeof requested === 'string' && requested !== '' ? requested : 'openid');
      await grant.save();
      return grant;
    },
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

    // The ID token carries the claims the app asked for (REQ-017), rather than making every
    // consumer call userinfo for a display name. Roles join them in Phase 3.
    conformIdTokenClaims: false,

    // PKCE S256 on every client, confidential ones included (REQ-003). v9 has no `plain`.
    pkce: { required: (_ctx, client) => !pkceExempt.has(client.clientId) },
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
      names: cookieNamesFor(options.secureCookies ?? true),
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
      rpInitiatedLogout: {
        enabled: true,
        // Plain HTML, no inline styles or script: this renders under the provider's CSP and
        // still works with JavaScript off (REQ-010).
        logoutSource(ctx, form) {
          ctx.type = 'html';
          ctx.body = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign out</title></head>
<body>
<main>
<h1>Sign out?</h1>
<p>This ends your session with ${escapeHtml(operatorDisplayName)} and the apps that use it.</p>
${form}
<button autofocus type="submit" form="op.logoutForm" value="yes" name="logout">Yes, sign me out</button>
<button type="submit" form="op.logoutForm">No, stay signed in</button>
</main>
</body></html>`;
        },
        // Nothing registered to return to, so land on the console's logged-out screen (I-8).
        postLogoutSuccessSource(ctx) {
          ctx.status = 303;
          ctx.redirect('/login/logged-out');
        },
      },
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
  installHashedClientSecrets(provider, options.db, options.hasher);
  return provider;
}
