import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { SESSION_ABSOLUTE_SECONDS } from '../../src/oidc/session-lifetime.js';
import { authorize, Browser, ISSUER, RP_CALLBACK, startHarness, USER, webClientConfig, type Harness } from './oidc-harness.js';

// Session lifetimes (REQ-029; ASVS 5.0 7.3.1, 7.3.2). Found by the security gate: Settings offered
// an idle session lifetime that nothing read, and a session had no absolute limit at all — a busy
// one could stay signed in forever.

let h: Harness;
let config: client.Configuration;
let ownerId: string;

/** The provider's stored session behind a signed-in browser. */
async function storedSession(browser: Browser) {
  const cookie = [...browser.cookies].find(([name]) => name.endsWith('d3auth_session'))?.[1] ?? '';
  return h.service.db.oidcPayload.findFirstOrThrow({ where: { kind: 'Session', id: cookie } });
}

/** Asks for a code with a browser that is already signed in. Returns the code, or null when it had to sign in again. */
async function silentCode(browser: Browser): Promise<string | null> {
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: RP_CALLBACK,
    scope: 'openid',
    code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
    code_challenge_method: 'S256',
    state: client.randomState(),
    nonce: client.randomNonce(),
  });
  const { leftTo } = await browser.navigate(url.toString());
  return leftTo?.searchParams.get('code') ?? null;
}

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  ownerId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
  await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
});

afterAll(async () => {
  await h.service.db.setting.deleteMany({ where: { key: 'lifetimes' } });
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  await h.service.db.setting.deleteMany({ where: { key: 'lifetimes' } });
});

describe('the idle limit', () => {
  it('is the one set in Settings, and applies to the next session saved', async () => {
    await h.service.settings.setLifetimes({ settings: { trustedDeviceDays: 30, sessionDays: 7 }, actorUserId: ownerId });

    const { browser } = await authorize(h, config);
    const stored = await storedSession(browser);
    const days = ((stored.expiresAt?.getTime() ?? 0) - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(6.9);
    expect(days).toBeLessThanOrEqual(7);
  });
});

describe('the absolute limit', () => {
  async function ageSignIn(browser: Browser, seconds: number): Promise<void> {
    const stored = await storedSession(browser);
    const payload = stored.payload as { loginTs: number };
    await h.service.db.oidcPayload.update({
      where: { kind_id: { kind: 'Session', id: stored.id } },
      data: { payload: { ...payload, loginTs: Math.floor(Date.now() / 1000) - seconds } },
    });
  }

  it('lets a recent sign-in straight through', async () => {
    const { browser } = await authorize(h, config);
    await ageSignIn(browser, SESSION_ABSOLUTE_SECONDS - 3600);
    expect(await silentCode(browser)).not.toBeNull();
  });

  it('makes a sign-in older than ninety days prove itself again, however busy the session was', async () => {
    const { browser } = await authorize(h, config);
    await ageSignIn(browser, SESSION_ABSOLUTE_SECONDS + 60);

    // No code: the browser is sent to sign in, as if the app had asked for max_age.
    expect(await silentCode(browser)).toBeNull();

    // And the console, which reads the same session, refuses it too.
    const cookie = [...browser.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    const me = await h.opFetch(`${ISSUER}/api/me`, { headers: { cookie, accept: 'application/json' } });
    expect(me.status).toBe(401);
  });
});
