#!/usr/bin/env node
// Signs the dev owner in through the real flow and prints the session cookie ZAP scans with
// (T-5.4, REQ-131). An unauthenticated scan of an app that is mostly behind a sign-in would find
// the sign-in and nothing else.
//
//   ZAP_TARGET=http://localhost:3000 node security/zap/session.mjs
//
// It stops once the provider has a session, which is before the continue-as screen: the cookie is
// what matters, not the app it was nominally for.

const target = new URL(process.env.ZAP_TARGET ?? 'http://localhost:3000');
const email = process.env.ZAP_EMAIL ?? 'dev@example.com';
const password = process.env.ZAP_PASSWORD ?? 'correct horse battery staple';

const jar = new Map();
async function hop(url, body) {
  const headers = { accept: 'application/json', cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; ') };
  const init = { redirect: 'manual', headers };
  if (body) {
    init.method = 'POST';
    headers['content-type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await fetch(url, init);
  for (const cookie of res.headers.getSetCookie()) {
    const [pair] = cookie.split(';');
    const at = pair.indexOf('=');
    const value = pair.slice(at + 1);
    if (value === '' || /max-age=0/i.test(cookie)) jar.delete(pair.slice(0, at));
    else jar.set(pair.slice(0, at), value);
  }
  return res;
}

async function follow(url) {
  let res = await hop(url);
  let current = new URL(url);
  while (res.status >= 300 && res.status < 400) {
    const next = new URL(res.headers.get('location'), current);
    if (next.origin !== target.origin) return current;
    current = next;
    res = await hop(next.toString());
  }
  return current;
}

// PKCE is required of every client, even one that will never redeem the code.
const verifier = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
const challenge = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))).toString('base64url');
const auth = new URL('/oidc/auth', target);
auth.search = new URLSearchParams({
  client_id: 'dev-web',
  response_type: 'code',
  scope: 'openid',
  redirect_uri: 'http://localhost:4000/callback',
  code_challenge: challenge,
  code_challenge_method: 'S256',
  state: 'zap',
  nonce: 'zap',
}).toString();

const landed = await follow(auth.toString());
const uid = landed.pathname.split('/')[2];
if (!uid) throw new Error(`expected the sign-in screen, got ${landed.pathname}`);

const api = async (path, body) => (await hop(`${target.origin}/api/interaction/${uid}${path}`, body)).json();
const { csrf } = await api('');
await api('/identify', { csrf, email });
const result = await api('/password', { csrf, password });
if (typeof result.redirectTo !== 'string') throw new Error(`sign-in failed: ${JSON.stringify(result)}`);
await follow(result.redirectTo);

const me = await hop(`${target.origin}/api/me`);
if (me.status !== 200) throw new Error(`no session after signing in (GET /api/me → ${me.status})`);
process.stdout.write([...jar].map(([k, v]) => `${k}=${v}`).join('; '));
