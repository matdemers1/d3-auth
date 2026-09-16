#!/usr/bin/env node
// Phase 0 exit demo: a full authorization code + PKCE flow against a running server, printing the
// ID token header and claims. Plays the browser itself (cookie jar + dev login form).
//
//   pnpm dev:up && pnpm example:flow
//
// Defaults match apps/server/dev/seed.dev.json and the .env written by scripts/dev-env.mjs.

import * as client from 'openid-client';

const env = (name, fallback) => process.env[name] ?? fallback;
const issuer = new URL(env('FLOW_ISSUER', 'http://localhost:3000'));
const clientId = env('FLOW_CLIENT_ID', 'dev-web');
const clientSecret = env('FLOW_CLIENT_SECRET', 'dev-web-secret-for-localhost-only-000000');
const redirectUri = env('FLOW_REDIRECT_URI', 'http://localhost:4000/callback');
const email = env('FLOW_EMAIL', 'dev@example.com');
const password = env('FLOW_PASSWORD', 'correct horse battery staple');

const insecure = issuer.protocol === 'http:' ? { execute: [client.allowInsecureRequests] } : {};
const config = await client.discovery(issuer, clientId, undefined, client.ClientSecretBasic(clientSecret), insecure);

const jar = new Map();
async function hop(url, form) {
  const headers = { cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '), accept: 'application/json' };
  const init = { redirect: 'manual', headers };
  if (form) {
    init.method = 'POST';
    headers['content-type'] = 'application/json';
    init.body = JSON.stringify(form);
  }
  const res = await fetch(url, init);
  for (const c of res.headers.getSetCookie()) {
    const [pair] = c.split(';');
    const i = pair.indexOf('=');
    jar.set(pair.slice(0, i), pair.slice(i + 1));
  }
  return res;
}

async function follow(url, form) {
  let res = await hop(url, form);
  let current = new URL(url);
  while (res.status >= 300 && res.status < 400) {
    const next = new URL(res.headers.get('location'), current);
    if (next.origin !== issuer.origin) return { callback: next };
    current = next;
    res = await hop(next.toString());
  }
  return { res, url: current };
}

const verifier = client.randomPKCECodeVerifier();
const state = client.randomState();
const nonce = client.randomNonce();
const authUrl = client.buildAuthorizationUrl(config, {
  redirect_uri: redirectUri,
  scope: 'openid email profile offline_access',
  code_challenge: await client.calculatePKCECodeChallenge(verifier),
  code_challenge_method: 'S256',
  state,
  nonce,
});

let step = await follow(authUrl.toString());
if (!step.callback) {
  // On the sign-in screen: drive the interaction API exactly as the console's form does.
  const uid = step.url.pathname.split('/')[2];
  if (!uid) throw new Error(`Expected the sign-in screen, got ${step.url.pathname} (HTTP ${step.res.status}).`);
  const api = async (path, body) => {
    const res = await hop(`${issuer.origin}/api/interaction/${uid}${path}`, body);
    return res.json();
  };
  const { csrf } = await api('', undefined);
  await api('/identify', { csrf, email });
  const result = await api('/password', { csrf, password });
  if (!result.redirectTo) throw new Error(`Sign-in failed: ${JSON.stringify(result)}`);
  step = await follow(result.redirectTo);
}
if (!step.callback) throw new Error(`Sign-in did not return to the client (HTTP ${step.res.status}). Check the dev seed.`);

const tokens = await client.authorizationCodeGrant(config, step.callback, {
  pkceCodeVerifier: verifier,
  expectedState: state,
  expectedNonce: nonce,
});

const [header] = tokens.id_token.split('.');
console.log('ID token header:', JSON.parse(Buffer.from(header, 'base64url').toString()));
console.log('ID token claims:', tokens.claims());
console.log('Access token is opaque:', !tokens.access_token.includes('.'), `(expires in ${tokens.expires_in}s)`);
console.log('Refresh token issued:', Boolean(tokens.refresh_token));
