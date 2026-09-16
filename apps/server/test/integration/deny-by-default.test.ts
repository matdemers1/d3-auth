import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { authorize, Browser, grantAccess, ISSUER, NATIVE_CLIENT, RP_CALLBACK, startHarness, USER, webClientConfig, type Harness } from './oidc-harness.js';

// REQ-051 — the never-regress invariant.
//
// An account with no grant for a client cannot sign in to it. Not "sees an empty app", not "gets
// a consent screen and then fails": `access_denied`, before any interstitial, with an audit row
// naming who was refused and for what. Everything else in Phase 3 sits on top of this, so it is
// tested from every direction a request can arrive from.

let h: Harness;
let config: client.Configuration;
let userId: string;

const WITHOUT_GRANT = { email: 'nogrant@example.com', username: 'nogrant', displayName: 'No Grant', password: 'palisade tumbler wren' };
let strangerId: string;

async function attempt(credentials: { email: string; password: string }, browser = new Browser(h.opFetch)) {
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: RP_CALLBACK,
    scope: 'openid email profile',
    code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
    code_challenge_method: 'S256',
    state: client.randomState(),
    nonce: client.randomNonce(),
  });
  const started = await browser.navigate(url.toString());
  const finished = await browser.login(started.response, credentials);
  return { browser, ...finished };
}

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  userId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;

  const stranger = await h.service.db.user.upsert({
    where: { email: WITHOUT_GRANT.email },
    create: {
      email: WITHOUT_GRANT.email,
      username: WITHOUT_GRANT.username,
      displayName: WITHOUT_GRANT.displayName,
      status: 'active',
      emailVerified: true,
    },
    update: { status: 'active' },
  });
  strangerId = stranger.id;
  await h.service.db.passwordCredential.deleteMany({ where: { userId: strangerId } });
  await h.service.db.passwordCredential.create({
    data: { userId: strangerId, argon2idHash: await h.hasher.hash(WITHOUT_GRANT.password) },
  });
});

afterAll(async () => {
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  // The stranger has an account, a password, and no access to anything.
  await h.service.db.grant.deleteMany({ where: { userId: strangerId } });
});

describe('an account with no grant', () => {
  it('is refused with access_denied and never reaches an interstitial', async () => {
    const { leftTo, response } = await attempt(WITHOUT_GRANT);
    expect(leftTo).toBeDefined();
    expect(leftTo?.searchParams.get('error')).toBe('access_denied');
    expect(leftTo?.searchParams.get('code')).toBeNull();
    // Nothing was rendered to them on the way out: the only stop was the sign-in screen itself.
    expect(response.status).toBeLessThan(400);
  });

  it('writes an audit row naming the person and the app', async () => {
    await attempt(WITHOUT_GRANT);
    const event = await h.service.db.auditEvent.findFirstOrThrow({ where: { event: 'authz.denied' }, orderBy: { id: 'desc' } });
    expect(event).toMatchObject({ actorUserId: strangerId, targetType: 'app' });
    expect(JSON.stringify(event.detail)).toContain('web-app');
  });

  it('leaves no session and no token behind', async () => {
    const before = await h.service.db.oidcPayload.count({ where: { kind: 'AccessToken' } });
    await attempt(WITHOUT_GRANT);

    expect(await h.service.db.session.count({ where: { userId: strangerId, revokedAt: null } })).toBe(0);
    expect(await h.service.db.oidcPayload.count({ where: { kind: 'AccessToken' } })).toBe(before);
    expect(await h.service.db.auditEvent.count({ where: { event: 'login.success', actorUserId: strangerId } })).toBe(0);
  });

  it('is refused for a second app even while signed in to the first', async () => {
    // Signed in to the web app, which they do have access to.
    await grantAccess(h, strangerId);
    const { browser, leftTo } = await attempt(WITHOUT_GRANT);
    expect(leftTo?.searchParams.get('code')).toBeTruthy();

    // The same browser, same session, asking for an app nobody granted them.
    const native = await client.discovery(new URL(ISSUER), NATIVE_CLIENT.clientId, undefined, client.None(), {
      [client.customFetch]: (url, options) => h.opFetch(url, options as RequestInit),
    });
    native[client.customFetch] = (url, options) => h.opFetch(url, options as RequestInit);
    const url = client.buildAuthorizationUrl(native, {
      redirect_uri: 'com.example.app:/cb',
      scope: 'openid',
      code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
      code_challenge_method: 'S256',
      state: client.randomState(),
      nonce: client.randomNonce(),
    });
    const second = await browser.navigate(url.toString());
    expect(second.leftTo?.searchParams.get('error')).toBe('access_denied');
    // No password was asked for: they were already signed in, and the grant still decided.
    expect(second.leftTo?.searchParams.get('code')).toBeNull();
  });

  it('is refused the moment the grant is revoked, even mid-session', async () => {
    await grantAccess(h, strangerId);
    const { browser } = await attempt(WITHOUT_GRANT);

    await h.service.db.grant.deleteMany({ where: { userId: strangerId } });
    const url = client.buildAuthorizationUrl(config, {
      redirect_uri: RP_CALLBACK,
      scope: 'openid',
      code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
      code_challenge_method: 'S256',
      state: client.randomState(),
      nonce: client.randomNonce(),
    });
    const again = await browser.navigate(url.toString());
    expect(again.leftTo?.searchParams.get('error')).toBe('access_denied');
  });

  it('is refused when the app is disabled, however good the grant is', async () => {
    await grantAccess(h, userId);
    const url = client.buildAuthorizationUrl(config, {
      redirect_uri: RP_CALLBACK,
      scope: 'openid',
      code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
      code_challenge_method: 'S256',
      state: client.randomState(),
      nonce: client.randomNonce(),
    });
    await h.service.db.app.update({ where: { clientId: 'web-app' }, data: { enabled: false } });
    try {
      // A disabled app is not a client at all, so this fails at the door — before any sign-in
      // screen, and without telling the caller whether the account exists.
      const { response, leftTo } = await new Browser(h.opFetch).navigate(url.toString());
      expect(leftTo).toBeUndefined();
      expect(response.status).toBeGreaterThanOrEqual(400);
    } finally {
      await h.service.db.app.update({ where: { clientId: 'web-app' }, data: { enabled: true } });
    }
  });
});

describe('an account with a grant', () => {
  it('signs in, and the grant is the only thing that changed', async () => {
    await grantAccess(h, strangerId, 'web-app', ['member']);
    const code = await authorize(h, config, {}, new Browser(h.opFetch), WITHOUT_GRANT);
    expect(code.callback.searchParams.get('code')).toBeTruthy();
  });
});
