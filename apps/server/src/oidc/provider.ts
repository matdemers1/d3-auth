import { isConsoleClient } from '../console/console-client.js';
import { renderSignedOut, renderSignOutQuestion } from '../interaction/signout-pages.js';
import Provider, { errors, type AdapterFactory, type Configuration } from 'oidc-provider';
import type { Db } from '../db.js';
import type { SecretHasher } from '../security/hash.js';
import { createFindAccount } from './account.js';
import { effectiveAccess } from '../authz/effective-roles.js';
import { createAdapterFactory } from './adapter.js';
import { createClientAdapter, installHashedClientSecrets } from './clients.js';
import type { PrivateJwk } from './keys.js';
import { ID_TOKEN_SIGNING_ALG, ROLES_CLAIM, ROLES_SCOPE, SIGNING_ALGS, SUPPORTED_SCOPES, TOKEN_ENDPOINT_AUTH_METHOD } from './protocol.js';
import { DEFAULT_IDLE_DAYS, interactionPolicyWithAbsoluteLifetime, sessionTtl } from './session-lifetime.js';

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
  /** Shown in copy like "Ask Matthew". */
  operatorDisplayName?: string;
  /** The console build, whose shell and stylesheet the sign-out pages are drawn in. */
  consoleDist?: string;
  /** False only for a local http issuer, where prefixed cookie names cannot be used. */
  secureCookies?: boolean;
  /** Conformance-suite clients exempt from PKCE; config refuses this outside *.test issuers. */
  pkceExemptClientIds?: readonly string[];
  /** Idle session lifetime in days, read when a session is saved (Settings → Lifetimes). */
  sessionIdleDays?: () => number;
  /**
   * Resource servers that may be named in an RFC 8707 `resource` parameter — an **allowlist**, not
   * a pattern. Foreman's remote MCP endpoint is the first (Foreman ADR-013). Empty keeps resource
   * indicators off entirely, which is the behaviour every existing deployment already has.
   */
  resourceServers?: readonly string[];
}

/** Everything goes to the payload table except `Client`, which is served from the App table. */
function clientBackedAdapters(db: Db, issuer: string): AdapterFactory {
  const payloads = createAdapterFactory(db);
  const clients = createClientAdapter(db, issuer);
  return (kind: string) => (kind === 'Client' ? clients : payloads(kind));
}

const escapeHtml = (value: unknown): string =>
  String(value).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

export function createProvider(options: ProviderOptions): Provider {
  const pkceExempt = new Set(options.pkceExemptClientIds ?? []);
  const resourceServers = new Set(options.resourceServers ?? []);
  const consoleDist = options.consoleDist ?? '';
  const configuration: Configuration = {
    // Clients come from the App table through the adapter (T-3.1), so registering an app takes
    // effect without a restart. There are deliberately no static clients; the console's own client
    // is served by the same adapter (ADR-005).
    adapter: clientBackedAdapters(options.db, options.issuer),
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
      // First time in this app: no grant is returned, so the provider raises an interaction and
      // the continue-as interstitial gets its one chance to be seen (REQ-059).
      if (access.firstSignInAt === null) return undefined;

      const requested = ctx.oidc.params?.scope;
      const scope = typeof requested === 'string' && requested !== '' ? requested : 'openid';

      /**
       * A grant must cover the **resource** as well as the scope, or the provider keeps raising an
       * interaction for something a granted user has already been allowed — which presents as an
       * endless redirect loop rather than as a refusal, and says nothing about why.
       *
       * Only allowlisted resources are added. An unknown one is left off deliberately, so the
       * token endpoint refuses it in `getResourceServerInfo` rather than being quietly granted here.
       */
      const addResources = (grant: InstanceType<typeof ctx.oidc.provider.Grant>): void => {
        const asked = ctx.oidc.params?.['resource'];
        for (const resource of Array.isArray(asked) ? asked : [asked]) {
          if (typeof resource === 'string' && resourceServers.has(resource)) {
            grant.addResourceScope(resource, scope);
          }
        }
      };

      const grantId = ctx.oidc.result?.consent?.grantId ?? ctx.oidc.session?.grantIdFor(client.clientId);
      if (grantId) {
        const existing = await ctx.oidc.provider.Grant.find(grantId);
        if (existing) {
          // A grant from before this request may predate the resource being asked for — a returning
          // user hitting a new resource server for the first time.
          addResources(existing);
          await existing.save();
          return existing;
        }
      }

      const grant = new ctx.oidc.provider.Grant({ accountId, clientId: client.clientId });
      grant.addOIDCScope(scope);
      addResources(grant);
      await grant.save();
      return grant;
    },
    jwks: { keys: options.keys },
    routes: ROUTES,

    responseTypes: ['code'],
    // `d3:roles` is ours (REQ-052). Apps that do not ask for it never see a roles claim, and an
    // app that does sees only its own.
    scopes: [...SUPPORTED_SCOPES],
    claims: {
      // Declaring `claims` replaces the provider's defaults, and anything undeclared is filtered
      // out of the token — which is how `amr`, `auth_time` and `sid` went missing the first time
      // (REQ-017). The four below belong to no scope: they describe the sign-in itself.
      acr: null,
      amr: null,
      auth_time: null,
      sid: null,
      iss: null,
      // Listed against `openid` as well, because a top-level claim is only *supported*: nothing
      // puts it in a token until a scope asks for it, and REQ-017 says every ID token carries
      // how and when the person proved who they were. `sid` joins them once an app declares a
      // back-channel logout endpoint (T-3.5), which is the only thing it is useful for.
      openid: ['sub', 'amr', 'auth_time'],
      email: ['email', 'email_verified'],
      profile: ['name', 'preferred_username'],
      [ROLES_SCOPE]: [ROLES_CLAIM],
    },
    clientAuthMethods: [TOKEN_ENDPOINT_AUTH_METHOD.confidential_web, TOKEN_ENDPOINT_AUTH_METHOD.public_native],
    clientDefaults: {
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      id_token_signed_response_alg: ID_TOKEN_SIGNING_ALG,
      token_endpoint_auth_method: TOKEN_ENDPOINT_AUTH_METHOD.confidential_web,
    },
    enabledJWA: {
      idTokenSigningAlgValues: [...SIGNING_ALGS],
      userinfoSigningAlgValues: [...SIGNING_ALGS],
      introspectionSigningAlgValues: [...SIGNING_ALGS],
      authorizationSigningAlgValues: [...SIGNING_ALGS],
      requestObjectSigningAlgValues: [...SIGNING_ALGS],
      clientAuthSigningAlgValues: [...SIGNING_ALGS],
      dPoPSigningAlgValues: ['ES256'],
    },

    // The ID token carries the claims the app asked for (REQ-017), rather than making every
    // consumer call userinfo for a display name. Roles join them in Phase 3.
    conformIdTokenClaims: false,

    // PKCE S256 on every client, confidential ones included (REQ-003). v9 has no `plain`, so
    // protocol.ts PKCE_METHOD is the only method there is, and what the connection sheet shows.
    pkce: { required: (_ctx, client) => !pkceExempt.has(client.clientId) },
    allowOmittingSingleRegisteredRedirectUri: false,
    // No browser calls the token, userinfo, introspection or revocation endpoints from another
    // origin: D3 apps keep tokens on their servers (consumer contract, ASVS 10.1.1), and native apps
    // send no Origin at all. The library's default would allow a public client's redirect origin;
    // there is no such client, so every cross-origin call with a client is refused. Discovery and the
    // key set stay open to any origin — they are public by definition (T-5.4).
    clientBasedCORS: () => false,
    clockTolerance: 60,

    ttl: {
      AccessToken: ACCESS_TOKEN_TTL,
      AuthorizationCode: 60,
      IdToken: 60 * 60,
      Interaction: 60 * 60,
      // Idle, capped by the absolute limit (session-lifetime.ts).
      Session: sessionTtl(options.sessionIdleDays ?? (() => DEFAULT_IDLE_DAYS)),
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

    interactions: {
      url: (_ctx, interaction) => options.interactionPath(interaction.uid),
      policy: interactionPolicyWithAbsoluteLifetime(),
    },

    features: {
      devInteractions: { enabled: false },
      introspection: {
        enabled: true,
        allowedPolicy: (_ctx, client) => client.clientAuthMethod !== 'none',
      },
      revocation: { enabled: true },
      // Signed logout tokens to every app a session was used with (REQ-011). It is also what
      // puts `sid` in the ID token, which is how an app knows *which* of its sessions to end.
      backchannelLogout: { enabled: true },
      userinfo: { enabled: true },
      rpInitiatedLogout: {
        enabled: true,
        // Drawn like every other single-task page and server-rendered, so it works with JavaScript
        // off (REQ-010). The two answers say what they do: see interaction/signout-pages.ts.
        async logoutSource(ctx, form) {
          const accountId = ctx.oidc.session?.accountId;
          const person = accountId
            ? await options.db.user.findUnique({ where: { id: accountId }, select: { displayName: true, email: true } })
            : null;
          const client = ctx.oidc.client;
          ctx.type = 'html';
          ctx.body = renderSignOutQuestion(consoleDist, {
            form,
            ...(person ? { person } : {}),
            ...(client && !isConsoleClient(client.clientId) ? { appName: client.clientName ?? client.clientId } : {}),
          });
        },
        // Reached with a client only when that app alone was signed out; otherwise everything was.
        postLogoutSuccessSource(ctx) {
          const client = ctx.oidc.client;
          ctx.type = 'html';
          ctx.body = renderSignedOut(consoleDist, client && !isConsoleClient(client.clientId) ? { onlyApp: client.clientName ?? client.clientId } : {});
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

      /**
       * RFC 8707 resource indicators — the consumer this was waiting for is Foreman's remote MCP
       * endpoint (Foreman ADR-013), which as an OAuth 2.1 resource server **MUST** reject any token
       * not issued for it. That only works if the token says who it is for, so tokens for a
       * resource are **JWTs with `aud` set to the resource**.
       *
       * The allowlist is the load-bearing part. Without it any client could ask for a token
       * audienced at any string it liked, and every resource server in the ecosystem would be one
       * careless audience check away from accepting it.
       */
      resourceIndicators: {
        enabled: resourceServers.size > 0,
        // No default: a request that names no resource keeps getting today's opaque token, so
        // nothing that exists now changes shape underneath it.
        defaultResource: () => undefined,
        useGrantedResource: () => true,
        getResourceServerInfo: (_ctx, resourceIndicator) => {
          if (!resourceServers.has(resourceIndicator)) {
            throw new errors.InvalidTarget('unknown resource server');
          }
          return {
            audience: resourceIndicator,
            // The scopes a resource server may be granted. Narrower than the provider's full set
            // on purpose: `offline_access` is a grant property, not something a resource needs.
            scope: 'openid profile email d3:roles',
            accessTokenTTL: ACCESS_TOKEN_TTL,
            accessTokenFormat: 'jwt',
          };
        },
      },
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
