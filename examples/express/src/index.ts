import { randomUUID, timingSafeEqual } from 'node:crypto';
import { createAuthClient, createBackchannelHandler, identityKey, type AuthClient, type SsoMode } from '@d3cloud/auth-client';
import express, { type Request, type Response } from 'express';

// A dual-login relying party, written the way the consumer contract asks (docs/consumer-contract.md).
//
// It has its own login *and* "Sign in with D3 Auth", which is the harder of the two shapes and
// the one Bindery has. The rules that cost the most to get wrong are the ones this file exists to
// demonstrate: identity is (iss, sub) and never the email; linking is explicit and never
// automatic; the app owns its own session; and a back-channel logout ends that session by `sid`.
//
// Accounts live in memory. This is a demo — the point is the flow, not the storage.

const ISSUER = process.env.D3AUTH_ISSUER ?? 'http://localhost:3000';
const CLIENT_ID = process.env.D3AUTH_CLIENT_ID ?? 'dev-web';
const CLIENT_SECRET = process.env.D3AUTH_CLIENT_SECRET ?? 'dev-web-secret-for-localhost-only-000000';
const PORT = Number(process.env.PORT ?? 4000);
const BASE_URL = process.env.BASE_URL ?? `http://localhost:${PORT}`;
const SSO_MODE = (process.env.D3AUTH_SSO_MODE ?? 'optional') as SsoMode;

interface Account {
  id: string;
  username: string;
  /** The app's own password. Plain text here only because nothing about this is real. */
  password?: string;
  /** `iss#sub`, set when this account is linked to D3 Auth. Never an email (rule 4). */
  linked?: string | undefined;
  roles: string[];
}

interface Session {
  accountId: string;
  /** How they signed in this time, which decides what unlinking may ask for. */
  via: 'local' | 'd3auth';
  /** The provider's session identifier, so a back-channel logout can find this one (rule 6). */
  sid?: string;
  idToken?: string;
  claims?: Readonly<Record<string, unknown>>;
}

// One local account that exists before anybody signs in: the break-glass owner every
// SSO-required app must keep (rule 10).
const accounts = new Map<string, Account>([['owner', { id: 'owner', username: 'owner', password: 'the-local-owner-password', roles: ['admin'] }]]);
const sessions = new Map<string, Session>();
const pending = new Map<string, { verifier: string; state: string; nonce: string; link?: string }>();

let auth: AuthClient | undefined;
try {
  auth = await createAuthClient({
    issuer: ISSUER,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: `${BASE_URL}/callback`,
    ssoMode: SSO_MODE,
    allowInsecureHttp: new URL(ISSUER).protocol === 'http:',
  });
} catch {
  // The provider is down. In `required` mode that is a reason to say so, not to refuse to boot:
  // existing sessions keep working and the local owner can still get in (rule 10).
  console.warn(`could not reach ${ISSUER}; sign-in with D3 Auth is unavailable until it comes back`);
}

const app = express();
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false }));

const cookie = (req: Request, name: string): string | undefined =>
  req.headers.cookie
    ?.split(';')
    .map((part) => part.trim().split('='))
    .find(([key]) => key === name)?.[1];

const sessionOf = (req: Request): { id: string; session: Session; account: Account } | undefined => {
  const id = cookie(req, 'example_session') ?? '';
  const session = sessions.get(id);
  const account = session ? accounts.get(session.accountId) : undefined;
  return session && account ? { id, session, account } : undefined;
};

const escape = (value: string): string => value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

const page = (body: string): string =>
  `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Example app</title></head><body><main>${body}</main></body></html>`;

const startSession = (res: Response, session: Session): void => {
  const id = randomUUID();
  sessions.set(id, session);
  // The app's own session, which outlives the ID token and survives the provider being down.
  res.set('Set-Cookie', `example_session=${id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`);
};

app.get('/', (req: Request, res: Response) => {
  const found = sessionOf(req);
  if (!found) {
    const ssoButton =
      SSO_MODE === 'off'
        ? ''
        : auth
          ? '<p><a id="sign-in" href="/login">Sign in with D3 Auth</a></p>'
          : '<p id="sso-unavailable">Sign-in with D3 Auth is unavailable right now.</p>';
    res.type('html').send(
      page(
        `<h1>Example app</h1><p>You are signed out.</p>${ssoButton}` +
          `<form method="post" action="/local-login"><label>Username <input name="username"></label>` +
          `<label>Password <input name="password" type="password"></label><button id="local-sign-in">Sign in here instead</button></form>`,
      ),
    );
    return;
  }

  const { session, account } = found;
  const link = account.linked
    ? `<p id="linked">Linked to ${escape(account.linked)}</p>` +
      `<form method="post" action="/unlink"><label>Your password here <input name="password" type="password"></label>` +
      `<button id="unlink">Disconnect D3 Auth</button></form>`
    : `<p><a id="connect" href="/login?link=1">Connect D3 Auth</a></p>`;

  res.type('html').send(
    page(
      `<h1>Example app</h1><p id="signed-in">Signed in as <strong id="username">${escape(account.username)}</strong></p>` +
        `<p id="roles">Roles: ${escape(account.roles.join(', ') || 'none')}</p>` +
        `<p id="via">Signed in with ${escape(session.via === 'local' ? 'this app' : 'D3 Auth')}</p>` +
        `<pre id="claims">${escape(JSON.stringify(session.claims ?? {}, null, 2))}</pre>` +
        link +
        `<p><a id="sign-out" href="/logout">Sign out</a></p>`,
    ),
  );
});

/** The app's own login. It is what makes an outage survivable (rule 10). */
app.post('/local-login', (req: Request, res: Response) => {
  const { username, password } = req.body as { username?: string; password?: string };
  const account = [...accounts.values()].find((candidate) => candidate.username === username);
  const expected = Buffer.from(account?.password ?? '');
  const given = Buffer.from(password ?? '');
  const ok = account?.password !== undefined && expected.length === given.length && timingSafeEqual(expected, given);
  if (!account || !ok) {
    res.status(401).type('html').send(page('<h1>That did not match</h1><p><a href="/">Try again</a></p>'));
    return;
  }
  startSession(res, { accountId: account.id, via: 'local' });
  res.redirect('/');
});

app.get('/login', async (req: Request, res: Response) => {
  if (!auth) {
    res.status(503).type('html').send(page('<h1 id="sso-unavailable">Sign-in is unavailable</h1><p>The provider is not reachable. Try again shortly.</p>'));
    return;
  }
  const start = await auth.beginSignIn();
  // Linking (rule 9): the account to attach this identity to is the one already signed in here,
  // never one matched by email afterwards.
  const linkTo = req.query.link === '1' ? sessionOf(req)?.account.id : undefined;
  pending.set(start.state, { ...start, ...(linkTo ? { link: linkTo } : {}) });
  res.redirect(start.url);
});

app.get('/callback', async (req: Request, res: Response) => {
  const state = typeof req.query.state === 'string' ? req.query.state : '';
  const started = pending.get(state);
  pending.delete(state);
  if (!started || !auth) {
    res.status(400).type('html').send(page('<h1>Unexpected sign-in response</h1><p>Start again from the home page.</p>'));
    return;
  }

  try {
    const session = await auth.completeSignIn(new URL(req.originalUrl, BASE_URL), started);
    const key = identityKey(session.identity);

    // Linking: attach this identity to the account that was already signed in here.
    if (started.link) {
      const account = accounts.get(started.link);
      if (account) {
        account.linked = key;
        account.roles = session.identity.roles;
      }
    }

    const existing = [...accounts.values()].find((candidate) => candidate.linked === key);
    // Just-in-time provisioning (rule 8): a successful sign-in is already proof that an admin
    // meant them to be here, because the provider refuses everybody else.
    const account =
      existing ??
      (() => {
        const id = randomUUID();
        const username = typeof session.identity.claims.preferred_username === 'string' ? session.identity.claims.preferred_username : session.identity.sub;
        const created: Account = { id, username, linked: key, roles: session.identity.roles };
        accounts.set(id, created);
        return created;
      })();
    account.roles = session.identity.roles;

    startSession(res, {
      accountId: account.id,
      via: 'd3auth',
      ...(session.sid ? { sid: session.sid } : {}),
      idToken: session.idToken,
      claims: session.identity.claims,
    });
    res.redirect('/');
  } catch (err) {
    res.status(400).type('html').send(page(`<h1>Sign-in failed</h1><pre>${escape(err instanceof Error ? err.message : String(err))}</pre>`));
  }
});

/** Unlinking asks for the local password (rule 9), so a borrowed session cannot cut the link. */
app.post('/unlink', (req: Request, res: Response) => {
  const found = sessionOf(req);
  if (!found) {
    res.redirect('/');
    return;
  }
  const { password } = req.body as { password?: string };
  if (!found.account.password || found.account.password !== password) {
    res.status(401).type('html').send(page('<h1>That password did not match</h1><p><a href="/">Back</a></p>'));
    return;
  }
  found.account.linked = undefined;
  res.redirect('/');
});

/**
 * Back-channel logout (rule 6). Verified, idempotent by `jti`, and it ends *this app's* session
 * rather than trusting the provider to have ended anything here.
 */
const handleLogout = createBackchannelHandler({
  issuer: ISSUER,
  clientId: CLIENT_ID,
  endSession: ({ sid, sub }) => {
    for (const [id, session] of sessions) {
      const account = accounts.get(session.accountId);
      const matchesSession = sid !== undefined && session.sid === sid;
      const matchesPerson = sid === undefined && account?.linked?.endsWith(`#${sub}`) === true;
      if (matchesSession || matchesPerson) sessions.delete(id);
    }
  },
});

app.post('/backchannel-logout', (req: Request, res: Response) => {
  void (async () => {
    const { logout_token: token } = req.body as { logout_token?: string };
    const result = await handleLogout(token ?? '');
    // A rejected token is a bad request, not an outage; a repeat is a success.
    res.status(result.ok ? 200 : 400).end();
  })();
});

app.get('/logout', (req: Request, res: Response) => {
  void (async () => {
    const found = sessionOf(req);
    if (found) sessions.delete(found.id);
    res.set('Set-Cookie', 'example_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');

    // Only an SSO session has anywhere else to be signed out of.
    if (!found || found.session.via !== 'd3auth' || !auth || !found.session.idToken) {
      res.redirect('/');
      return;
    }
    res.redirect(await auth.endSessionUrl({ idToken: found.session.idToken, returnTo: `${BASE_URL}/` }));
  })();
});

app.listen(PORT, () => {
  console.log(`Example app on ${BASE_URL}, signing in with ${ISSUER} (sso mode: ${SSO_MODE})`);
});
