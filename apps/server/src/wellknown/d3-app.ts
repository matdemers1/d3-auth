import { Router } from 'express';

// The D3 App contract's manifest (AUTH-T-9.1, CON-ADR-003), at /.well-known/d3-app.json.
//
// D3 Auth is the one product with no native session endpoints (AUTH-ADR-008): D3 Constellation
// signs in here through the browser with its preset client, then reaches these APIs with the
// access token that grant mints for D3 Auth's own audience. So the sign-in method is `oidc` and the
// three native session endpoints are null; `me` and `accountApps` take that token.

export const CAPABILITIES = ['d3auth.account', 'd3auth.apps', 'd3auth.sessions', 'd3auth.admin', 'd3auth.audit'] as const;

export function d3AppManifestRouter(input: { issuer: string; version?: string | undefined; revision?: string | undefined }): Router {
  const base = input.issuer.replace(/\/+$/, '');
  const manifest = {
    product: 'd3auth',
    name: 'D3 Auth',
    version: input.version ?? '0.1.0',
    revision: input.revision ?? null,
    contract: 1,
    capabilities: [...CAPABILITIES],
    signIn: { methods: ['oidc'] },
    endpoints: {
      nativeSignIn: null,
      nativeRefresh: null,
      nativeRevoke: null,
      me: `${base}/api/me`,
      link: null,
      inviteAccept: null,
      deleteAccount: null,
      relayRegister: `${base}/api/push/native/register`,
      accountApps: `${base}/api/account/apps`,
      stepUp: `${base}/api/account/step-up`,
    },
  };
  const router = Router();
  router.get('/.well-known/d3-app.json', (_req, res) => {
    res.set('Cache-Control', 'no-store').json(manifest);
  });
  return router;
}

/**
 * `/.well-known/apple-app-site-association` (AUTH-T-9.7): which Apple apps may use this relying
 * party's passkeys. Without it iOS refuses D3 Constellation a passkey for this domain outright, so
 * native step-up could only ever use a code. JSON, at the exact path, never redirected — Apple's
 * fetcher does not follow redirects.
 */
export function appleAppSiteAssociationRouter(appIds: readonly string[]): Router {
  const router = Router();
  const body = JSON.stringify({ webcredentials: { apps: [...appIds] } });
  router.get('/.well-known/apple-app-site-association', (_req, res) => {
    res.set('Cache-Control', 'public, max-age=3600').type('application/json').send(body);
  });
  return router;
}
