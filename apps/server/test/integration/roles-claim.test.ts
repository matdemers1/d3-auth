import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { authorize, Browser, discover, grantAccess, ISSUER, RP_CALLBACK, startHarness, USER, WEB_CLIENT, webClientConfig, type Harness } from './oidc-harness.js';

// REQ-052, REQ-013, REQ-017.
//
// The roles claim is the point of the whole system, and its one absolute rule: a token shows the
// roles this person has *in the app that asked*, and never a hint of any other app. Two apps, two
// role sets, one person — that is what the no-leak test below is for.

let h: Harness;
let webConfig: client.Configuration;
let otherConfig: client.Configuration;
let userId: string;

const OTHER = { clientId: 'other-app', secret: 'another-client-secret-for-the-integration-suite', callback: 'https://other.d3auth.test/cb' };

/** Signs in and comes back with the tokens, for whichever client is asked for. */
async function signIn(config: client.Configuration, redirectUri: string, scope: string) {
  const code = await authorize(h, config, { redirect_uri: redirectUri, scope }, new Browser(h.opFetch));
  return client.authorizationCodeGrant(config, code.callback, {
    pkceCodeVerifier: code.verifier,
    expectedState: code.state,
    expectedNonce: code.nonce,
  });
}

beforeAll(async () => {
  h = await startHarness();
  webConfig = await webClientConfig(h);
  userId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;

  // A second app with roles of its own, so "no leakage" has something to leak.
  const other = await h.service.db.app.upsert({
    where: { clientId: OTHER.clientId },
    create: {
      clientId: OTHER.clientId,
      name: 'The Other App',
      clientType: 'confidential_web',
      clientSecretHash: await h.hasher.hash(OTHER.secret),
      postLogoutRedirectUris: [],
    },
    update: { clientSecretHash: await h.hasher.hash(OTHER.secret), enabled: true },
  });
  await h.service.db.redirectUri.deleteMany({ where: { appId: other.id } });
  await h.service.db.redirectUri.create({ data: { appId: other.id, uri: OTHER.callback } });
  await h.service.db.role.deleteMany({ where: { appId: other.id } });
  await h.service.db.role.createMany({
    data: [
      { appId: other.id, key: 'curator', displayName: 'Curator', sortOrder: 2 },
      { appId: other.id, key: 'reader', displayName: 'Reader', sortOrder: 1 },
    ],
  });

  otherConfig = await discover(h, OTHER.clientId, client.ClientSecretBasic(OTHER.secret));
});

afterAll(async () => {
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  await grantAccess(h, userId, WEB_CLIENT.clientId, ['admin']);
  await grantAccess(h, userId, OTHER.clientId, ['curator', 'reader']);
});

describe('the roles claim', () => {
  it('carries only the roles of the app that asked (REQ-052)', async () => {
    const web = await signIn(webConfig, RP_CALLBACK, 'openid d3:roles');
    const other = await signIn(otherConfig, OTHER.callback, 'openid d3:roles');

    expect(web.claims()?.roles).toEqual(['admin']);
    expect(other.claims()?.roles).toEqual(['curator', 'reader']);

    // The decisive one: neither token mentions the other app's roles anywhere in it.
    expect(JSON.stringify(web.claims())).not.toContain('curator');
    expect(JSON.stringify(web.claims())).not.toContain('reader');
    expect(JSON.stringify(other.claims())).not.toContain('admin');
  });

  it('is absent unless the app asks for it', async () => {
    const tokens = await signIn(webConfig, RP_CALLBACK, 'openid email profile');
    expect(tokens.claims()?.roles).toBeUndefined();

    const info = await client.fetchUserInfo(webConfig, tokens.access_token, userId);
    expect(info.roles).toBeUndefined();
    expect(info.email).toBe(USER.email);
  });

  it('answers the same way at userinfo, scoped to the client holding the token', async () => {
    const web = await signIn(webConfig, RP_CALLBACK, 'openid d3:roles');
    const other = await signIn(otherConfig, OTHER.callback, 'openid d3:roles');

    expect((await client.fetchUserInfo(webConfig, web.access_token, userId)).roles).toEqual(['admin']);
    expect((await client.fetchUserInfo(otherConfig, other.access_token, userId)).roles).toEqual(['curator', 'reader']);
  });

  it('is read at the moment the token is built, so a change lands on the next renewal', async () => {
    const tokens = await signIn(webConfig, RP_CALLBACK, 'openid d3:roles offline_access');
    expect(tokens.claims()?.roles).toEqual(['admin']);

    // Demoted while signed in.
    await grantAccess(h, userId, WEB_CLIENT.clientId, ['member']);
    expect((await client.fetchUserInfo(webConfig, tokens.access_token, userId)).roles).toEqual(['member']);

    const refreshed = await client.refreshTokenGrant(webConfig, tokens.refresh_token ?? '');
    expect(refreshed.claims()?.roles).toEqual(['member']);
  });

  it('never carries groups, under any scope (REQ-053)', async () => {
    const tokens = await signIn(webConfig, RP_CALLBACK, 'openid email profile d3:roles offline_access');
    const everything = JSON.stringify({ id: tokens.claims(), info: await client.fetchUserInfo(webConfig, tokens.access_token, userId) });
    expect(everything).not.toContain('groups');
  });

  it('carries the standard claims a consumer needs to trust it (REQ-013, REQ-017)', async () => {
    const tokens = await signIn(webConfig, RP_CALLBACK, 'openid d3:roles');
    const claims = tokens.claims();
    expect(claims).toMatchObject({
      iss: ISSUER,
      aud: WEB_CLIENT.clientId,
      sub: userId,
      // Who the person proved they were, and when: what a consumer needs to decide about step-up.
      amr: ['pwd'],
    });
    expect(claims?.auth_time).toEqual(expect.any(Number));
    expect(claims?.nonce).toEqual(expect.any(String));
    // `sid` arrives with back-channel logout (T-3.5): it identifies the session an app is being
    // told to end, and means nothing to an app that cannot be told.
    expect(claims?.sid).toBeUndefined();
  });
});
