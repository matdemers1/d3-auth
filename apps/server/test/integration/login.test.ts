import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { consoleCsp } from '../../src/security/headers.js';
import { authorize, Browser, ISSUER, RP_CALLBACK, startHarness, USER, webClientConfig, type Harness } from './oidc-harness.js';

let h: Harness;
let config: client.Configuration;

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
});

afterAll(async () => {
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
});

/** Starts an authorization request and stops on the sign-in screen, returning its uid. */
async function signInScreen(): Promise<{ browser: Browser; uid: string }> {
  const browser = new Browser(h.opFetch);
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: RP_CALLBACK,
    scope: 'openid email profile',
    code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
    code_challenge_method: 'S256',
    state: client.randomState(),
    nonce: client.randomNonce(),
  });
  const { response } = await browser.navigate(url.toString());
  const uid = new URL(response.url || browser.lastUrl).pathname.split('/')[2] ?? '';
  expect(uid).not.toBe('');
  return { browser, uid };
}

async function attempt(password: string, email = USER.email): Promise<{ status: number; body: Record<string, unknown>; headers: Headers }> {
  const { browser, uid } = await signInScreen();
  const view = (await (await browser.api(uid, '')).json()) as { csrf: string };
  await browser.api(uid, '/identify', { csrf: view.csrf, email });
  const res = await browser.api(uid, '/password', { csrf: view.csrf, password });
  return { status: res.status, body: (await res.json()) as Record<string, unknown>, headers: res.headers };
}

describe('sign-in screen (REQ-076, REQ-086)', () => {
  it('describes the step without saying whether the account exists', async () => {
    const { browser, uid } = await signInScreen();
    const view = (await (await browser.api(uid, '')).json()) as Record<string, unknown>;
    expect(view).toMatchObject({ step: 'identify', clientName: 'Web App', operatorDisplayName: 'Matthew' });
    expect(view.csrf).toEqual(expect.any(String));

    const known = await browser.api(uid, '/identify', { csrf: String(view.csrf), email: USER.email });
    const unknown = await browser.api(uid, '/identify', { csrf: String(view.csrf), email: 'nobody@example.com' });
    expect(known.status).toBe(unknown.status);
    const knownBody = (await known.json()) as { step: string };
    const unknownBody = (await unknown.json()) as { step: string };
    expect(knownBody.step).toBe(unknownBody.step);
  });

  it('gives the same answer for a wrong password and an unknown email', async () => {
    const wrong = await attempt('definitely not the password');
    const unknown = await attempt('definitely not the password', `ghost-${Date.now()}@example.com`);
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body).toEqual(unknown.body);
    expect(String(wrong.body.message)).not.toMatch(/unknown|no account|not found|does not exist|no such/i);
  });

  it('verifies a password even when the account does not exist (REQ-026)', async () => {
    const before = h.passwordVerifications.count;
    await attempt('anything', `ghost-${Date.now()}@example.com`);
    expect(h.passwordVerifications.count).toBe(before + 1);
  });

  it('signs a real person in and records the session and audit trail', async () => {
    const before = new Date();
    const { callback } = await authorize(h, config);
    expect(callback.searchParams.get('code')).toBeTruthy();

    const user = await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } });
    expect(user.lastLoginAt?.getTime()).toBeGreaterThanOrEqual(before.getTime());

    const session = await h.service.db.session.findFirst({
      where: { userId: user.id },
      orderBy: { createdAt: 'desc' },
    });
    expect(session).toMatchObject({ revokedAt: null });
    expect(session?.oidcSessionUid).toEqual(expect.any(String));
    expect(session?.expiresAt.getTime()).toBeGreaterThan(Date.now() + 29 * 24 * 60 * 60 * 1000);

    const events = await h.service.db.auditEvent.findMany({ where: { at: { gte: before } }, orderBy: { id: 'asc' } });
    expect(events.map((e) => e.event)).toEqual(expect.arrayContaining(['login.success', 'session.started']));
    const success = events.find((e) => e.event === 'login.success');
    expect(success).toMatchObject({ actorUserId: user.id, targetType: 'user' });
    expect(success?.detail).toMatchObject({ amr: ['pwd'] });
  });

  it('regenerates the session cookie at login (REQ-030)', async () => {
    const { browser, uid } = await signInScreen();
    const view = (await (await browser.api(uid, '')).json()) as { csrf: string };
    const beforeCookie = browser.cookies.get('__Host-d3auth_session');

    await browser.api(uid, '/identify', { csrf: view.csrf, email: USER.email });
    const res = await browser.api(uid, '/password', { csrf: view.csrf, password: USER.password });
    const { redirectTo } = (await res.json()) as { redirectTo: string };
    await browser.navigate(redirectTo);

    const afterCookie = browser.cookies.get('__Host-d3auth_session');
    expect(afterCookie).toBeTruthy();
    expect(afterCookie).not.toBe(beforeCookie);
  });

  it('records a failure in the audit log without storing the password', async () => {
    const before = new Date();
    await attempt('definitely not the password');
    const events = await h.service.db.auditEvent.findMany({ where: { at: { gte: before }, event: 'login.failure' } });
    expect(events).toHaveLength(1);
    expect(events[0]?.detail).toMatchObject({ email: USER.email, reason: 'bad_password' });
    expect(JSON.stringify(events[0]?.detail)).not.toContain('definitely not the password');
  });
});

describe('CSRF on interaction posts (REQ-031)', () => {
  it('refuses a post with a missing or wrong token', async () => {
    const { browser, uid } = await signInScreen();
    const view = (await (await browser.api(uid, '')).json()) as { csrf: string };

    expect((await browser.api(uid, '/identify', { email: USER.email, csrf: '' })).status).toBe(403);
    expect((await browser.api(uid, '/identify', { email: USER.email, csrf: 'x'.repeat(view.csrf.length) })).status).toBe(403);
    expect((await browser.api(uid, '/identify', { csrf: view.csrf, email: USER.email })).status).toBe(200);
  });
});

describe('throttling (REQ-027, REQ-028)', () => {
  it('blocks the sixth attempt with Retry-After and does no hashing', async () => {
    const email = `throttled-${Date.now()}@example.com`;
    for (let i = 0; i < 5; i++) {
      const res = await attempt('wrong password here', email);
      expect(res.status).toBe(401);
    }

    const verificationsBefore = h.passwordVerifications.count;
    const blocked = await attempt('wrong password here', email);

    expect(blocked.status).toBe(429);
    expect(blocked.body).toMatchObject({ error: 'throttled' });
    expect(Number(blocked.headers.get('retry-after'))).toBeGreaterThan(0);
    expect(h.passwordVerifications.count).toBe(verificationsBefore);
  });

  it('writes an audit event when it throttles', async () => {
    const email = `throttled-audit-${Date.now()}@example.com`;
    const before = new Date();
    for (let i = 0; i < 6; i++) await attempt('wrong password here', email);
    const events = await h.service.db.auditEvent.findMany({ where: { at: { gte: before }, event: 'login.throttled' } });
    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events[0]?.detail).toMatchObject({ email, scope: 'account' });
  });

  it('forgets the counters as soon as the person gets in', async () => {
    const before = h.service.db.throttleCounter;
    for (let i = 0; i < 3; i++) await attempt('wrong password here');
    expect(await before.count({ where: { key: USER.email } })).toBe(1);

    await authorize(h, config);
    expect(await before.count({ where: { key: USER.email } })).toBe(0);
  });
});

describe('security headers (REQ-132)', () => {
  it.each([
    ['/healthz', 200],
    ['/login/nope', 404],
    ['/.well-known/openid-configuration', 200],
  ])('sets them on %s (%i)', async (path) => {
    const res = await h.opFetch(ISSUER + path);
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('referrer-policy')).toBe('no-referrer');
    expect(res.headers.get('x-frame-options')).toBe('DENY');
    expect(res.headers.get('strict-transport-security')).toMatch(/max-age=63072000/);
    expect(res.headers.get('content-security-policy')).toMatch(/frame-ancestors 'none'/);
  });

  it('locks the console down and keeps the provider workable', async () => {
    const console_ = await h.opFetch(`${ISSUER}/healthz`);
    const consoleHeader = console_.headers.get('content-security-policy') ?? '';
    const nonce = /'nonce-([A-Za-z0-9_-]+)'/.exec(consoleHeader)?.[1] ?? '';
    expect(consoleHeader).toBe(consoleCsp(nonce));
    expect(consoleHeader).not.toContain('unsafe-inline');

    const provider = await h.opFetch(`${ISSUER}/oidc/jwks`);
    const csp = provider.headers.get('content-security-policy') ?? '';
    expect(csp).toMatch(/frame-ancestors 'none'/);
    expect(csp).toMatch(/object-src 'none'/);
  });

  it('sets them on an error response too', async () => {
    const res = await h.opFetch(`${ISSUER}/oidc/token`, { method: 'POST' });
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.headers.get('content-security-policy')).toBeTruthy();
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
  });
});

describe('logout (REQ-010)', () => {
  it('asks first, then ends the session and revokes our row', async () => {
    const { callback, verifier, state, nonce, browser } = await authorize(h, config);
    const tokens = await client.authorizationCodeGrant(config, callback, {
      pkceCodeVerifier: verifier,
      expectedState: state,
      expectedNonce: nonce,
    });
    const user = await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } });
    const session = await h.service.db.session.findFirstOrThrow({ where: { userId: user.id, revokedAt: null }, orderBy: { createdAt: 'desc' } });

    const endSession = new URL(`${ISSUER}/oidc/session/end`);
    endSession.searchParams.set('id_token_hint', tokens.id_token ?? '');
    const confirm = await browser.navigate(endSession.toString());
    const html = await confirm.response.text();
    expect(html).toMatch(/Sign out\?/);
    expect(html).toMatch(/Matthew/);

    const xsrf = /name="xsrf" value="([^"]+)"/.exec(html)?.[1] ?? '';
    const done = await browser.navigate(`${ISSUER}/oidc/session/end/confirm`, { form: { xsrf, logout: 'yes' } });
    // Plain HTML, so it says so with JavaScript off too.
    expect(await done.response.text()).toMatch(/You are signed out/);

    const after = await h.service.db.session.findUniqueOrThrow({ where: { id: session.id } });
    expect(after.revokedAt).not.toBeNull();
    const events = await h.service.db.auditEvent.findMany({ where: { event: 'session.logout' }, orderBy: { id: 'desc' }, take: 1 });
    expect(events).toHaveLength(1);
  });

  it('refuses a post-logout redirect that is not registered', async () => {
    const { callback, verifier, state, nonce, browser } = await authorize(h, config);
    const tokens = await client.authorizationCodeGrant(config, callback, { pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce });

    const endSession = new URL(`${ISSUER}/oidc/session/end`);
    endSession.searchParams.set('id_token_hint', tokens.id_token ?? '');
    endSession.searchParams.set('post_logout_redirect_uri', 'https://evil.test/landed');
    const { response, leftTo } = await browser.navigate(endSession.toString());
    expect(leftTo).toBeUndefined();
    expect(response.status).toBeGreaterThanOrEqual(400);
  });
});
