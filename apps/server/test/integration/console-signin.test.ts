import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { safeNext } from '../../src/console/signin.js';
import { Browser, ISSUER, startHarness, USER, type Harness } from './oidc-harness.js';

// Signing in to the console directly (ADR-005). Before this, the console only had a session if an
// app had started a sign-in: signed out, or arriving by typing the address, every page was empty
// and nothing offered a way in.
//
// What must stay true while fixing that: the built-in client opens a person's own account and
// nothing more, a registered app gets no such pass, and `next` never becomes a way off this origin.

let h: Harness;

beforeAll(async () => {
  h = await startHarness();
});

afterAll(async () => {
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
});

const me = (browser: Browser): Promise<Response> =>
  h.opFetch(`${ISSUER}/api/me`, {
    headers: {
      accept: 'application/json',
      'sec-fetch-site': 'same-origin',
      cookie: [...browser.cookies].map(([k, v]) => `${k}=${v}`).join('; '),
    },
  });

/** A person with no grant to anything at all. */
async function guestWithNoAccess(status: 'active' | 'suspended' = 'active'): Promise<{ email: string; password: string }> {
  const suffix = randomBytes(4).toString('hex');
  const email = `nobody-${suffix}@example.com`;
  const password = `a long enough password ${suffix}`;
  const user = await h.service.db.user.create({ data: { email, username: `nobody${suffix}`, displayName: 'Nobody', status } });
  await h.service.db.passwordCredential.create({ data: { userId: user.id, argon2idHash: await h.hasher.hash(password) } });
  return { email, password };
}

describe('the ways in', () => {
  it('sends the bare origin and the bare /login to sign in', async () => {
    for (const path of ['/', '/login']) {
      const res = await h.opFetch(`${ISSUER}${path}`, { redirect: 'manual' });
      expect(res.status).toBe(302);
      expect(res.headers.get('location')).toBe('/signin');
    }
  });

  it('starts an authorization request for the console client, with PKCE, back to this origin', async () => {
    const res = await h.opFetch(`${ISSUER}/signin?next=/admin/people`, { redirect: 'manual' });
    expect(res.status).toBe(303);
    const location = new URL(res.headers.get('location') ?? '');
    expect(location.pathname).toBe('/oidc/auth');
    expect(Object.fromEntries(location.searchParams)).toMatchObject({
      client_id: 'd3auth-console',
      scope: 'openid',
      redirect_uri: `${ISSUER}/signin/callback`,
      code_challenge_method: 'S256',
    });
    expect(res.headers.get('set-cookie')).toMatch(/d3auth_signin=.*HttpOnly/i);
  });
});

describe('signing in', () => {
  it('shows the sign-in form, then returns to the page that asked, signed in', async () => {
    const browser = new Browser(h.opFetch);
    const step = await browser.navigate(`${ISSUER}/signin?next=/admin/people`);
    expect(browser.lastUrl).toMatch(/\/login\/[^/]+$/);

    await browser.login(step.response);
    expect(new URL(browser.lastUrl).pathname).toBe('/admin/people');
    expect((await me(browser)).status).toBe(200);
  });

  it('lets somebody with no grant to any app into their own account, and no further', async () => {
    const credentials = await guestWithNoAccess();
    const browser = new Browser(h.opFetch);
    const step = await browser.navigate(`${ISSUER}/signin`);
    await browser.login(step.response, credentials);
    expect(new URL(browser.lastUrl).pathname).toBe('/account');
    expect((await me(browser)).status).toBe(200);

    // The console's guards still decide what an account may see.
    const admin = await h.opFetch(`${ISSUER}/api/admin/people`, {
      headers: { accept: 'application/json', 'sec-fetch-site': 'same-origin', cookie: [...browser.cookies].map(([k, v]) => `${k}=${v}`).join('; ') },
    });
    expect(admin.status).toBe(403);

    // No audit row claims they were refused: they were not.
    const denied = await h.service.db.auditEvent.count({ where: { event: 'authz.denied', detail: { path: ['clientId'], equals: 'd3auth-console' } } });
    expect(denied).toBe(0);
  });

  it('still refuses a suspended account', async () => {
    const credentials = await guestWithNoAccess('suspended');
    const browser = new Browser(h.opFetch);
    const step = await browser.navigate(`${ISSUER}/signin`);
    const result = await browser.login(step.response, credentials);
    expect(result.leftTo).toBeUndefined();
    expect((await me(browser)).status).toBe(401);
  });

  it('skips the form when already signed in', async () => {
    const browser = new Browser(h.opFetch);
    await browser.login((await browser.navigate(`${ISSUER}/signin`)).response, USER);
    const again = await browser.request(`${ISSUER}/signin?next=/account/security`);
    expect(again.status).toBe(303);
    expect(again.headers.get('location')).toBe('/account/security');
  });

  it('starts again when the callback was not started by this browser', async () => {
    const res = await h.opFetch(`${ISSUER}/signin/callback?code=x&state=forged`, { redirect: 'manual', headers: { cookie: 'd3auth_signin=real.' } });
    expect(res.status).toBe(303);
    expect(res.headers.get('location')).toBe('/signin');
  });
});

describe('signing out', () => {
  it('returns to the sign-in form once the provider has asked', async () => {
    const browser = new Browser(h.opFetch);
    await browser.login((await browser.navigate(`${ISSUER}/signin`)).response, USER);

    const question = await browser.request(
      `${ISSUER}/oidc/session/end?${new URLSearchParams({ client_id: 'd3auth-console', post_logout_redirect_uri: `${ISSUER}/signin` }).toString()}`,
    );
    expect(question.status).toBe(200);
    const html = await question.text();
    const action = /action="([^"]+)"/.exec(html)?.[1] ?? '';
    const xsrf = /name="xsrf" value="([^"]+)"/.exec(html)?.[1] ?? '';
    const confirmed = await browser.request(new URL(action, ISSUER).toString(), { form: { xsrf, logout: 'yes' } });
    expect(confirmed.status).toBe(303);
    expect(confirmed.headers.get('location')).toBe(`${ISSUER}/signin`);
    expect((await me(browser)).status).toBe(401);
  });
});

describe('the signed-out page', () => {
  it('says so, with a way back in, and the question before it names D3 Auth', async () => {
    const page = await h.opFetch(`${ISSUER}/signed-out`);
    expect(page.status).toBe(200);
    expect(await page.text()).toContain('Sign in again');

    const browser = new Browser(h.opFetch);
    await browser.login((await browser.navigate(`${ISSUER}/signin`)).response, USER);
    const question = await browser.request(`${ISSUER}/oidc/session/end?${new URLSearchParams({ client_id: 'd3auth-console', post_logout_redirect_uri: `${ISSUER}/signed-out` }).toString()}`);
    const html = await question.text();
    expect(html).toContain('Sign out of D3 Auth?');
    expect(html).toContain('Signed in as <strong>');
    const xsrf = /name="xsrf" value="([^"]+)"/.exec(html)?.[1] ?? '';
    const confirmed = await browser.request(`${ISSUER}/oidc/session/end/confirm`, { form: { xsrf, logout: 'yes' } });
    expect(confirmed.headers.get('location')).toBe(`${ISSUER}/signed-out`);
  });
});

describe('where next may go', () => {
  it('only to the console or account pages on this origin', () => {
    expect(safeNext('/admin')).toBe('/admin');
    expect(safeNext('/admin/people?q=x')).toBe('/admin/people?q=x');
    expect(safeNext('/account/security')).toBe('/account/security');
    for (const bad of ['//evil.example/admin', 'https://evil.example/admin', '/administrator', '/admin\\@evil.example', '/oidc/auth', '', undefined, ['/admin']]) {
      expect(safeNext(bad)).toBeUndefined();
    }
    expect(safeNext(`/admin${String.fromCharCode(10)}Location: https://evil.example`)).toBeUndefined();
  });
});

describe('what the console client can ask for', () => {
  // offline_access is not in this list because the provider drops it rather than refusing it; the
  // client has no refresh_token grant type, so there is nothing for it to issue either way.
  it('openid and nothing else: never roles, never profile claims', async () => {
    for (const scope of ['openid d3:roles', 'openid email', 'openid profile']) {
      const params = new URLSearchParams({
        client_id: 'd3auth-console',
        response_type: 'code',
        scope,
        redirect_uri: `${ISSUER}/signin/callback`,
        state: 'x',
        code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        code_challenge_method: 'S256',
      });
      const res = await h.opFetch(`${ISSUER}/oidc/auth?${params.toString()}`, { redirect: 'manual' });
      const location = new URL(res.headers.get('location') ?? '', ISSUER);
      expect(location.pathname, scope).toBe('/signin/callback');
      expect(location.searchParams.get('error'), scope).toBe('invalid_scope');
    }
  });

  it('cannot be sent anywhere but this origin', async () => {
    const params = new URLSearchParams({
      client_id: 'd3auth-console',
      response_type: 'code',
      scope: 'openid',
      redirect_uri: 'https://evil.example/cb',
      state: 'x',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      code_challenge_method: 'S256',
    });
    const res = await h.opFetch(`${ISSUER}/oidc/auth?${params.toString()}`, { redirect: 'manual' });
    expect(res.headers.get('location') ?? '').not.toContain('evil.example');
    expect(res.status).toBe(400);
  });
});

describe('the reserved client id', () => {
  it('cannot be registered as an app', async () => {
    const { parseManifest } = await import('../../src/admin/manifest.js');
    const result = parseManifest({ client_id: 'd3auth-console', name: 'Impostor', client_type: 'public_native', redirect_uris: ['com.example:/cb'] });
    expect(result.ok).toBe(false);
  });
});
