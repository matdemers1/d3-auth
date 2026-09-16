import { randomUUID } from 'node:crypto';
import express, { type Request, type Response } from 'express';
import * as client from 'openid-client';

// A relying party in about a hundred lines, written the way the consumer contract asks
// (API Contract §2): discovery, PKCE with state and nonce, identity by (iss, sub), and a session
// of its own that outlives the ID token. Phase 3 replaces the hand-rolled parts with
// @d3cloud/auth-client; this example exists to prove the provider from the outside.

const ISSUER = process.env.D3AUTH_ISSUER ?? 'http://localhost:3000';
const CLIENT_ID = process.env.D3AUTH_CLIENT_ID ?? 'dev-web';
const CLIENT_SECRET = process.env.D3AUTH_CLIENT_SECRET ?? 'dev-web-secret-for-localhost-only-000000';
const PORT = Number(process.env.PORT ?? 4000);
const BASE_URL = process.env.BASE_URL ?? `http://localhost:${PORT}`;

interface Session {
  /** The only identity key a consumer may use (API Contract §2.4). */
  iss: string;
  sub: string;
  claims: Record<string, unknown>;
  username: string;
  idToken: string;
}

const sessions = new Map<string, Session>();
const pending = new Map<string, { verifier: string; state: string; nonce: string }>();

const issuer = new URL(ISSUER);
const config = await client.discovery(
  issuer,
  CLIENT_ID,
  undefined,
  client.ClientSecretBasic(CLIENT_SECRET),
  // Local development only: the dev stack has no TLS. Deployments use https.
  // eslint-disable-next-line @typescript-eslint/no-deprecated -- the flag is deprecated by design, to stand out
  issuer.protocol === 'http:' ? { execute: [client.allowInsecureRequests] } : {},
);

const app = express();
app.disable('x-powered-by');

const cookie = (req: Request, name: string): string | undefined =>
  req.headers.cookie
    ?.split(';')
    .map((part) => part.trim().split('='))
    .find(([key]) => key === name)?.[1];

const page = (body: string): string =>
  `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Example app</title></head><body><main>${body}</main></body></html>`;

const escape = (value: string): string => value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

app.get('/', (req: Request, res: Response) => {
  const session = sessions.get(cookie(req, 'example_session') ?? '');
  if (!session) {
    res.type('html').send(page('<h1>Example app</h1><p>You are signed out.</p><p><a id="sign-in" href="/login">Sign in with D3 Auth</a></p>'));
    return;
  }
  res.type('html').send(
    page(
      `<h1>Example app</h1><p id="signed-in">Signed in as <strong id="username">${escape(session.username)}</strong></p>` +
        `<pre id="claims">${escape(JSON.stringify(session.claims, null, 2))}</pre>` +
        `<p><a id="sign-out" href="/logout">Sign out</a></p>`,
    ),
  );
});

app.get('/login', async (_req: Request, res: Response) => {
  const verifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const nonce = client.randomNonce();
  pending.set(state, { verifier, state, nonce });

  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: `${BASE_URL}/callback`,
    scope: 'openid profile email',
    code_challenge: await client.calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256',
    state,
    nonce,
  });
  res.redirect(url.toString());
});

app.get('/callback', async (req: Request, res: Response) => {
  const state = typeof req.query.state === 'string' ? req.query.state : '';
  const started = pending.get(state);
  pending.delete(state);
  if (!started) {
    res.status(400).type('html').send(page('<h1>Unexpected sign-in response</h1><p>Start again from the home page.</p>'));
    return;
  }

  try {
    const tokens = await client.authorizationCodeGrant(config, new URL(req.originalUrl, BASE_URL), {
      pkceCodeVerifier: started.verifier,
      expectedState: started.state,
      expectedNonce: started.nonce,
    });
    const claims: Record<string, unknown> = { ...tokens.claims() };
    const text = (value: unknown): string => (typeof value === 'string' ? value : '');
    const sub = text(claims.sub);
    const id = randomUUID();
    sessions.set(id, {
      iss: text(claims.iss),
      sub,
      claims,
      username: text(claims.preferred_username) || sub,
      idToken: tokens.id_token ?? '',
    });
    // The app's own session, which survives an outage of the provider (API Contract §2.7).
    res.set('Set-Cookie', `example_session=${id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`);
    res.redirect('/');
  } catch (err) {
    res.status(400).type('html').send(page(`<h1>Sign-in failed</h1><pre>${escape(err instanceof Error ? err.message : String(err))}</pre>`));
  }
});

app.get('/logout', (req: Request, res: Response) => {
  const id = cookie(req, 'example_session') ?? '';
  const session = sessions.get(id);
  sessions.delete(id);
  res.set('Set-Cookie', 'example_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  if (!session) {
    res.redirect('/');
    return;
  }
  const url = client.buildEndSessionUrl(config, {
    id_token_hint: session.idToken,
    post_logout_redirect_uri: `${BASE_URL}/`,
  });
  res.redirect(url.toString());
});

app.listen(PORT, () => {
  console.log(`Example app on ${BASE_URL}, signing in with ${ISSUER}`);
});
