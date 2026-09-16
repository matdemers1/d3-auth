import * as client from 'openid-client';
import { TOTP, Secret } from 'otpauth';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { Browser, RP_CALLBACK, startHarness, USER, webClientConfig, type Harness } from './oidc-harness.js';

// REQ-036 (trusted device), REQ-041 (never for a suspended account).
//
// The point of the whole feature is one sentence: after a second factor, a browser may be
// remembered for thirty days — and that memory must be revocable, account-bound, and gone the
// moment the account is.

let h: Harness;
let config: client.Configuration;
let userId: string;

const DEVICE_COOKIE = '__Host-d3auth_device';

/** The secret of the enrolment made for the current test, so the test can act like the app. */
let authenticator: TOTP | undefined;

/** Gives the dev user a confirmed authenticator app, which is what makes the factor step appear. */
async function enrolTotp(): Promise<void> {
  const enrolment = await h.service.totp.begin({ userId, accountName: USER.email });
  authenticator = new TOTP({ secret: Secret.fromBase32(enrolment.manualKey) });
  const confirmed = await h.service.totp.confirm({ userId, credentialId: enrolment.credentialId, code: authenticator.generate() });
  expect(confirmed).toBe(true);
}

/**
 * A code that has not been used yet. Confirming an enrolment burns the current step (codes are
 * single use), so the next sign-in has to wait for the step to turn over.
 */
async function totpCode(): Promise<string> {
  if (!authenticator) throw new Error('enrolTotp() first');
  const used = await h.service.db.totpCredential.findFirstOrThrow({ where: { userId } });
  const step = 30 * 1000;
  let at = Date.now();
  while (BigInt(Math.floor(at / step)) <= (used.lastUsedStep ?? -1n)) at += step;
  return authenticator.generate({ timestamp: at });
}

/** Starts an authorization request and stops on the sign-in screen. */
async function signInScreen(browser: Browser): Promise<string> {
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: RP_CALLBACK,
    scope: 'openid email profile',
    code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
    code_challenge_method: 'S256',
    state: client.randomState(),
    nonce: client.randomNonce(),
  });
  const { response } = await browser.navigate(url.toString());
  return new URL(response.url || browser.lastUrl).pathname.split('/')[2] ?? '';
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
  await h.service.db.trustedDevice.deleteMany();
  await h.service.db.totpCredential.deleteMany({ where: { userId } });
  await h.service.db.user.update({ where: { id: userId }, data: { status: 'active' } });
});

describe('the trusted-device offer (REQ-036)', () => {
  it('is only made after a second factor, and only "yes" writes a cookie', async () => {
    await enrolTotp();
    const enrolment = await h.service.db.totpCredential.findFirstOrThrow({ where: { userId } });
    expect(enrolment.confirmedAt).not.toBeNull();

    const browser = new Browser(h.opFetch);
    const uid = await signInScreen(browser);
    const view = (await (await browser.api(uid, '')).json()) as { csrf: string };
    await browser.api(uid, '/identify', { csrf: view.csrf, email: USER.email });

    const afterPassword = (await (await browser.api(uid, '/password', { csrf: view.csrf, password: USER.password })).json()) as {
      step: string;
      factors?: string[];
    };
    // The password alone does not finish the login, and the screen is told what can answer.
    expect(afterPassword).toMatchObject({ step: 'factor', factors: ['totp'] });

    const afterFactor = (await (await browser.api(uid, '/totp', { csrf: view.csrf, code: await totpCode() })).json()) as { step: string };
    expect(afterFactor.step).toBe('trust');

    const declined = await browser.api(uid, '/trust', { csrf: view.csrf, trust: 'false' });
    expect(((await declined.json()) as { step: string }).step).toBe('done');
    expect(browser.setCookieHeaders.join(' ')).not.toContain(DEVICE_COOKIE);
    expect(await h.service.db.trustedDevice.count({ where: { userId } })).toBe(0);
  });

  it('remembers the browser for thirty days when accepted, and skips the factor next time', async () => {
    await enrolTotp();
    const browser = new Browser(h.opFetch);
    const uid = await signInScreen(browser);
    const view = (await (await browser.api(uid, '')).json()) as { csrf: string };
    await browser.api(uid, '/identify', { csrf: view.csrf, email: USER.email });
    await browser.api(uid, '/password', { csrf: view.csrf, password: USER.password });
    await browser.api(uid, '/totp', { csrf: view.csrf, code: await totpCode() });
    const trusted = await browser.api(uid, '/trust', { csrf: view.csrf, trust: 'true' });
    expect(((await trusted.json()) as { step: string }).step).toBe('done');

    const row = await h.service.db.trustedDevice.findFirstOrThrow({ where: { userId } });
    // The cookie is a bearer token: only its hash is kept.
    expect(row.tokenHash).toMatch(/^[0-9a-f]{64}$/);
    expect(browser.cookies.get(DEVICE_COOKIE)).toBeTruthy();
    expect(row.tokenHash).not.toContain(browser.cookies.get(DEVICE_COOKIE) ?? 'x');
    const days = (row.expiresAt.getTime() - Date.now()) / (24 * 60 * 60 * 1000);
    expect(days).toBeGreaterThan(29);
    expect(days).toBeLessThanOrEqual(30);

    // Same browser, new sign-in: the password is enough now.
    const again = new Browser(h.opFetch);
    again.cookies.set(DEVICE_COOKIE, browser.cookies.get(DEVICE_COOKIE) ?? '');
    const nextUid = await signInScreen(again);
    const nextView = (await (await again.api(nextUid, '')).json()) as { csrf: string };
    await again.api(nextUid, '/identify', { csrf: nextView.csrf, email: USER.email });
    const finished = (await (await again.api(nextUid, '/password', { csrf: nextView.csrf, password: USER.password })).json()) as {
      step: string;
      redirectTo?: string;
    };
    expect(finished.step).toBe('done');
    expect(finished.redirectTo).toBeTruthy();
  });

  it('vouches for one account only', async () => {
    await enrolTotp();
    const other = await h.service.db.user.create({
      data: { email: `other-${Date.now()}@example.com`, username: `other${Date.now()}`, displayName: 'Other', status: 'active' },
    });
    const issued = await h.service.trustedDevices.issue({ userId: other.id });
    expect(issued).toBeDefined();

    expect(await h.service.trustedDevices.verify({ userId, token: issued?.token })).toBe(false);
    expect(await h.service.trustedDevices.verify({ userId: other.id, token: issued?.token })).toBe(true);
    await h.service.db.user.delete({ where: { id: other.id } });
  });

  it('is never issued to an account that cannot sign in (REQ-041)', async () => {
    await h.service.db.user.update({ where: { id: userId }, data: { status: 'suspended' } });
    expect(await h.service.trustedDevices.issue({ userId })).toBeUndefined();
  });

  it('stops working once revoked or expired', async () => {
    const issued = await h.service.trustedDevices.issue({ userId, userAgent: 'Test Browser' });
    const token = issued?.token;
    expect(await h.service.trustedDevices.verify({ userId, token })).toBe(true);

    const listed = await h.service.trustedDevices.list({ userId, token });
    expect(listed).toHaveLength(1);
    expect(listed[0]).toMatchObject({ userAgent: 'Test Browser', current: true });

    expect(await h.service.trustedDevices.revoke({ userId, id: listed[0]?.id ?? '' })).toBe(true);
    expect(await h.service.trustedDevices.verify({ userId, token })).toBe(false);
    expect(await h.service.trustedDevices.list({ userId })).toHaveLength(0);

    const later = await h.service.trustedDevices.issue({ userId });
    expect(await h.service.trustedDevices.verify({ userId, token: later?.token, now: new Date(Date.now() + 31 * 24 * 60 * 60 * 1000) })).toBe(
      false,
    );
  });
});
