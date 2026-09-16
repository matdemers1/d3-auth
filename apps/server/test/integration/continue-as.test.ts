import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { Browser, grantAccess, ISSUER, NATIVE_CALLBACK, NATIVE_CLIENT, RP_CALLBACK, startHarness, USER, webClientConfig, type Harness } from './oidc-harness.js';

// REQ-059, REQ-060, REQ-016.
//
// The interstitial is not a consent screen: there is nothing to agree to. It exists so that
// somebody arriving at a new app from a long-lived session is told which account is about to be
// used, once, with a way out. Every later sign-in to that app goes straight through.

let h: Harness;
let config: client.Configuration;
let userId: string;

/** Pulls the CSRF token out of the server-rendered interstitial, the way the browser would. */
const csrfFrom = (html: string): string => /name="csrf" value="([^"]*)"/.exec(html)?.[1] ?? '';

const authorizationUrl = async (config_: client.Configuration, redirectUri: string) =>
  client.buildAuthorizationUrl(config_, {
    redirect_uri: redirectUri,
    scope: 'openid',
    code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
    code_challenge_method: 'S256',
    state: client.randomState(),
    nonce: client.randomNonce(),
  });

/** Signs in with the password and stops wherever the flow stops. */
async function signInAndStop(browser: Browser, redirectUri = RP_CALLBACK) {
  const url = await authorizationUrl(config, redirectUri);
  const started = await browser.navigate(url.toString());
  const uid = new URL(started.response.url || browser.lastUrl).pathname.split('/')[2] ?? '';
  const view = (await (await browser.api(uid, '')).json()) as { csrf: string };
  await browser.api(uid, '/identify', { csrf: view.csrf, email: USER.email });
  const done = (await (await browser.api(uid, '/password', { csrf: view.csrf, password: USER.password })).json()) as {
    redirectTo?: string;
  };
  const landed = await browser.navigate(done.redirectTo ?? '');
  return { landed, html: landed.leftTo ? '' : await landed.response.text(), browser };
}

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  userId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
});

afterAll(async () => {
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  await grantAccess(h, userId, 'web-app', ['member']);
  // Nobody has been here before.
  await h.service.db.grant.updateMany({ where: { userId }, data: { firstSignInAt: null } });
});

describe('the first sign-in to an app', () => {
  it('stops to say which account is about to be used (REQ-059)', async () => {
    const { landed, html } = await signInAndStop(new Browser(h.opFetch));

    expect(landed.leftTo).toBeUndefined();
    expect(html).toContain('Continue to Web App');
    expect(html).toContain(USER.username);
    expect(html).toContain('Not you?');
    // Nothing has been issued yet: this is a stop, not a formality after the fact.
    expect(await h.service.db.grant.findFirstOrThrow({ where: { userId, app: { clientId: 'web-app' } } })).toMatchObject({
      firstSignInAt: null,
    });
  });

  it('never asks about scopes (REQ-060)', async () => {
    const { html } = await signInAndStop(new Browser(h.opFetch));
    expect(html).not.toMatch(/scope|permission|allow .* to access/i);
  });

  it('goes on to the app when they continue, and marks the app as seen', async () => {
    const { browser, landed, html } = await signInAndStop(new Browser(h.opFetch));
    const uid = new URL(browser.lastUrl).pathname.split('/')[2] ?? '';
    expect(landed.leftTo).toBeUndefined();

    const continued = (await (await browser.api(uid, '/continue', { csrf: csrfFrom(html) })).json()) as {
      redirectTo?: string;
    };
    const back = await browser.navigate(continued.redirectTo ?? '');
    expect(back.leftTo?.searchParams.get('code')).toBeTruthy();
    expect(await h.service.db.grant.findFirstOrThrow({ where: { userId, app: { clientId: 'web-app' } } })).toMatchObject({
      firstSignInAt: expect.any(Date) as Date,
    });
  });

  it('is shown once: the next sign-in goes straight through', async () => {
    const first = await signInAndStop(new Browser(h.opFetch));
    const uid = new URL(first.browser.lastUrl).pathname.split('/')[2] ?? '';
    const continued = (await (await first.browser.api(uid, '/continue', { csrf: csrfFrom(first.html) })).json()) as {
      redirectTo?: string;
    };
    await first.browser.navigate(continued.redirectTo ?? '');

    // A brand new browser, so this is a fresh sign-in rather than a live session.
    const second = await signInAndStop(new Browser(h.opFetch));
    expect(second.landed.leftTo?.searchParams.get('code')).toBeTruthy();
  });

  it('lets them start again as somebody else', async () => {
    const { browser, html } = await signInAndStop(new Browser(h.opFetch));
    const uid = new URL(browser.lastUrl).pathname.split('/')[2] ?? '';
    const sessionsBefore = await h.service.db.session.count({ where: { userId, revokedAt: null } });

    const switched = (await (await browser.api(uid, '/switch', { csrf: csrfFrom(html) })).json()) as {
      redirectTo?: string;
    };
    expect(switched.redirectTo).toBeTruthy();

    // The session is gone, so the same authorization request asks for a password again.
    expect(await h.service.db.session.count({ where: { userId, revokedAt: null } })).toBeLessThan(sessionsBefore);
    const again = await browser.navigate(switched.redirectTo ?? '');
    expect(again.leftTo).toBeUndefined();
    // Back on the sign-in screen for the same request, rather than bounced to the app with an
    // error: "not you" should cost a password, not the whole journey.
    const page = await again.response.text();
    expect(page).toContain('/api/interaction/');
    expect(page).toContain('Sign in to');
  });
});

describe('a public native client (REQ-016)', () => {
  it('signs in with a custom scheme redirect and no secret', async () => {
    await grantAccess(h, userId, NATIVE_CLIENT.clientId, []);
    await h.service.db.grant.updateMany({ where: { userId }, data: { firstSignInAt: new Date() } });

    const native = await client.discovery(new URL(ISSUER), NATIVE_CLIENT.clientId, undefined, client.None(), {
      [client.customFetch]: (url, options) => h.opFetch(url, options as RequestInit),
    });
    native[client.customFetch] = (url, options) => h.opFetch(url, options as RequestInit);

    const verifier = client.randomPKCECodeVerifier();
    const state = client.randomState();
    const nonce = client.randomNonce();
    const url = client.buildAuthorizationUrl(native, {
      redirect_uri: NATIVE_CALLBACK,
      scope: 'openid',
      code_challenge: await client.calculatePKCECodeChallenge(verifier),
      code_challenge_method: 'S256',
      state,
      nonce,
    });

    const browser = new Browser(h.opFetch);
    const started = await browser.navigate(url.toString());
    const finished = await browser.login(started.response);
    expect(finished.leftTo?.protocol).toBe('com.example.app:');
    expect(finished.leftTo?.searchParams.get('code')).toBeTruthy();

    const tokens = await client.authorizationCodeGrant(native, finished.leftTo ?? new URL(NATIVE_CALLBACK), {
      pkceCodeVerifier: verifier,
      expectedState: state,
      expectedNonce: nonce,
    });
    expect(tokens.claims()?.aud).toBe(NATIVE_CLIENT.clientId);
  });
});

