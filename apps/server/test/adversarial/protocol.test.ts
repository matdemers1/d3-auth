import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  authorize,
  Browser,
  grantAccess,
  ISSUER,
  NATIVE_CALLBACK,
  NATIVE_CLIENT,
  RP_CALLBACK,
  startHarness,
  USER,
  WEB_CLIENT,
  webClientConfig,
  type Harness,
} from '../integration/oidc-harness.js';
import { consoleCaller, tokenRequest } from './support.js';

// Attack class: bending the protocol (REQ-003, REQ-004, REQ-005, REQ-009, REQ-051).
//
// Every case here is somebody holding a real artefact — a code, a refresh token, an access token —
// and trying to use it where, when or as whom it was not issued. The provider library does most
// of this work; the point is to prove our configuration did not quietly switch any of it off, and
// that *our* rules (deny by default, revocation) reach tokens already in somebody's hands.

let h: Harness;
let config: client.Configuration;
let ownerId: string;

const code = (callback: URL): string => callback.searchParams.get('code') ?? '';

/** An authorization URL built by hand, so a mutation is sent exactly as written. */
function rawAuthorize(params: Record<string, string>): string {
  const url = new URL(`${ISSUER}/oidc/auth`);
  const all = { client_id: WEB_CLIENT.clientId, response_type: 'code', scope: 'openid', redirect_uri: RP_CALLBACK, state: 's', nonce: 'n', ...params };
  url.search = new URLSearchParams(all).toString();
  return url.toString();
}

async function tokensFor(): Promise<{ access: string; refresh: string; idToken: string }> {
  const flow = await authorize(h, config);
  const tokens = await client.authorizationCodeGrant(config, flow.callback, {
    pkceCodeVerifier: flow.verifier,
    expectedState: flow.state,
    expectedNonce: flow.nonce,
  });
  return { access: tokens.access_token, refresh: tokens.refresh_token ?? '', idToken: tokens.id_token ?? '' };
}

const userinfoStatus = async (accessToken: string): Promise<number> =>
  (await h.opFetch(`${ISSUER}/oidc/me`, { headers: { authorization: `Bearer ${accessToken}` } })).status;

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  ownerId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
  await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
});

afterAll(async () => {
  await h.service.db.user.update({ where: { id: ownerId }, data: { status: 'active', kind: 'owner' } });
  await grantAccess(h, ownerId, WEB_CLIENT.clientId, ['member']);
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  await h.service.db.user.update({ where: { id: ownerId }, data: { status: 'active' } });
  await grantAccess(h, ownerId, WEB_CLIENT.clientId, ['member']);
});

describe('a stolen authorization code', () => {
  it('cannot be redeemed a second time, and the first redemption is revoked with it', async () => {
    const flow = await authorize(h, config);
    const form = { grant_type: 'authorization_code', code: code(flow.callback), redirect_uri: RP_CALLBACK, code_verifier: flow.verifier };
    const first = await tokenRequest(h, form);
    expect(first.status).toBe(200);

    expect((await tokenRequest(h, form)).body.error).toBe('invalid_grant');
    expect(await userinfoStatus(String(first.body.access_token))).toBe(401);
  });

  it('cannot be redeemed by a different client', async () => {
    const flow = await authorize(h, config);
    const answer = await tokenRequest(
      h,
      { grant_type: 'authorization_code', code: code(flow.callback), redirect_uri: RP_CALLBACK, code_verifier: flow.verifier, client_id: NATIVE_CLIENT.clientId },
      '',
    );
    expect(answer.status).toBeGreaterThanOrEqual(400);
    expect(answer.body.access_token).toBeUndefined();
  });

  it('cannot be redeemed against a different redirect_uri', async () => {
    const flow = await authorize(h, config);
    const answer = await tokenRequest(h, {
      grant_type: 'authorization_code',
      code: code(flow.callback),
      redirect_uri: `${RP_CALLBACK}/other`,
      code_verifier: flow.verifier,
    });
    expect(answer.body.error).toBe('invalid_grant');
  });

  it('is useless without the verifier that belongs to it, even a valid one from another flow', async () => {
    const victim = await authorize(h, config);
    const attacker = await authorize(h, config);
    const answer = await tokenRequest(h, {
      grant_type: 'authorization_code',
      code: code(victim.callback),
      redirect_uri: RP_CALLBACK,
      code_verifier: attacker.verifier,
    });
    expect(answer.body.error).toBe('invalid_grant');
  });
});

describe('a PKCE downgrade', () => {
  const refused = async (params: Record<string, string>, clientId: string = WEB_CLIENT.clientId, redirect = RP_CALLBACK): Promise<void> => {
    const { response, leftTo } = await new Browser(h.opFetch).navigate(rawAuthorize({ client_id: clientId, redirect_uri: redirect, ...params }));
    // Either an error back to the client or an error page; never a login.
    if (leftTo) expect(leftTo.searchParams.get('error')).toBe('invalid_request');
    else expect(response.status).toBeGreaterThanOrEqual(400);
  };

  it('a public client without a challenge is refused', async () => {
    await refused({}, NATIVE_CLIENT.clientId, NATIVE_CALLBACK);
  });

  it('a challenge with no method is refused rather than treated as plain', async () => {
    await refused({ code_challenge: client.randomPKCECodeVerifier() });
  });

  it.each([
    ['plain', { code_challenge: 'a'.repeat(43), code_challenge_method: 'plain' }],
    ['lowercase s256', { code_challenge: 'a'.repeat(43), code_challenge_method: 's256' }],
    ['a made-up method', { code_challenge: 'a'.repeat(43), code_challenge_method: 'S512' }],
    ['a challenge too short to be a SHA-256', { code_challenge: 'abc', code_challenge_method: 'S256' }],
    ['a challenge with characters base64url does not have', { code_challenge: `${'a'.repeat(42)}+`, code_challenge_method: 'S256' }],
  ])('%s is refused', async (_label, params) => {
    await refused(params);
  });
});

describe('a mutated redirect_uri', () => {
  const mutations = [
    `${RP_CALLBACK}/`,
    `${RP_CALLBACK}/..`,
    `${RP_CALLBACK}%2F..`,
    `${RP_CALLBACK}#fragment`,
    `${RP_CALLBACK}?next=https://evil.test`,
    'https://rp.d3auth.test/%63b',
    'https://rp.d3auth.test./cb',
    'https://rp.d3auth.test:443/cb',
    'https://rp.d3auth.test:8443/cb',
    'HTTPS://rp.d3auth.test/cb',
    'https://rp.d3auth.test\\@evil.test/cb',
    'https://rp.d3auth.test@evil.test/cb',
    'https://evil.test/https://rp.d3auth.test/cb',
    '//rp.d3auth.test/cb',
    ' https://rp.d3auth.test/cb',
    'https://rp.d3auth.test/cb\n',
    'https://rр.d3auth.test/cb', // Cyrillic р
    'javascript:alert(1)//https://rp.d3auth.test/cb',
  ];

  it.each(mutations)('never sends anybody to %j', async (redirectUri) => {
    const verifier = client.randomPKCECodeVerifier();
    const url = rawAuthorize({
      redirect_uri: redirectUri,
      code_challenge: await client.calculatePKCECodeChallenge(verifier),
      code_challenge_method: 'S256',
    });
    const { response, leftTo } = await new Browser(h.opFetch).navigate(url);
    expect(leftTo).toBeUndefined();
    expect(response.status).toBe(400);
  });

  it('never sends anybody to a post-logout address that was not registered', async () => {
    const { idToken } = await tokensFor();
    const url = new URL(`${ISSUER}/oidc/session/end`);
    url.search = new URLSearchParams({ id_token_hint: idToken, post_logout_redirect_uri: 'https://evil.test/after', state: 'x' }).toString();
    const { response, leftTo } = await new Browser(h.opFetch).navigate(url.toString());
    expect(leftTo?.host).not.toBe('evil.test');
    expect(response.headers.get('location') ?? '').not.toContain('evil.test');
  });
});

describe('a logout request with nothing to validate its redirect against', () => {
  /** Signs in, then asks to sign out with the given parameters and confirms. Returns where it went. */
  async function logoutAndConfirm(params: Record<string, string>): Promise<{ status: number; location: string; body: string }> {
    const { browser } = await authorize(h, config);
    const url = new URL(`${ISSUER}/oidc/session/end`);
    url.search = new URLSearchParams(params).toString();
    const shown = await browser.request(url.toString());
    const page = await shown.text();
    const xsrf = /name="xsrf" value="([^"]+)"/.exec(page)?.[1];
    if (!xsrf) return { status: shown.status, location: shown.headers.get('location') ?? '', body: page };
    const confirmed = await browser.request(`${ISSUER}/oidc/session/end/confirm`, { form: { xsrf, logout: 'yes' } });
    return { status: confirmed.status, location: confirmed.headers.get('location') ?? '', body: await confirmed.text() };
  }

  it('without an id_token_hint, refuses a post_logout_redirect_uri rather than follow it', async () => {
    const outcome = await logoutAndConfirm({ post_logout_redirect_uri: 'https://evil.test/after', state: 'x' });
    expect(outcome.location).not.toContain('evil.test');
    expect(outcome.body).not.toContain('evil.test');
  });

  it('without an id_token_hint, refuses even a registered one — there is no client to say it is registered for', async () => {
    const outcome = await logoutAndConfirm({ post_logout_redirect_uri: RP_CALLBACK, state: 'x' });
    expect(outcome.location.startsWith(RP_CALLBACK)).toBe(false);
  });
});

describe('a stolen refresh token', () => {
  it('reused after rotation takes the whole family down with it', async () => {
    const { refresh } = await tokensFor();
    const rotated = await tokenRequest(h, { grant_type: 'refresh_token', refresh_token: refresh });
    expect(rotated.status).toBe(200);

    expect((await tokenRequest(h, { grant_type: 'refresh_token', refresh_token: refresh })).body.error).toBe('invalid_grant');
    expect((await tokenRequest(h, { grant_type: 'refresh_token', refresh_token: String(rotated.body.refresh_token) })).body.error).toBe('invalid_grant');
    expect(await userinfoStatus(String(rotated.body.access_token))).toBe(401);
  });

  it('cannot be presented by a different client, or with the wrong secret', async () => {
    const { refresh } = await tokensFor();
    const asNative = await tokenRequest(h, { grant_type: 'refresh_token', refresh_token: refresh, client_id: NATIVE_CLIENT.clientId }, '');
    expect(asNative.body.access_token).toBeUndefined();

    const wrongSecret = await tokenRequest(h, { grant_type: 'refresh_token', refresh_token: refresh }, `${WEB_CLIENT.clientId}:not-the-secret`);
    expect(wrongSecret.body.error).toBe('invalid_client');
  });
});

describe('tokens already handed out, after access is taken away (REQ-051)', () => {
  it('stop working the moment the grant is revoked', async () => {
    const { access, refresh } = await tokensFor();
    expect(await userinfoStatus(access)).toBe(200);

    const call = await consoleCaller(h, config);
    expect((await call(`/api/admin/people/${ownerId}/access/revoke`, { body: { clientId: WEB_CLIENT.clientId } })).status).toBe(200);

    expect(await userinfoStatus(access)).toBe(401);
    const refreshed = await tokenRequest(h, { grant_type: 'refresh_token', refresh_token: refresh });
    expect(refreshed.body.access_token).toBeUndefined();
  });

  it('stop working the moment the person is suspended', async () => {
    const { access, refresh } = await tokensFor();
    const call = await consoleCaller(h, config);

    // The owner cannot suspend themselves, so a second person takes the fall.
    const person = await h.service.db.user.upsert({
      where: { email: 'suspend-me@example.com' },
      create: { email: 'suspend-me@example.com', username: 'suspendme', displayName: 'Suspend Me', status: 'active' },
      update: { status: 'active' },
    });
    await h.service.db.passwordCredential.deleteMany({ where: { userId: person.id } });
    await h.service.db.passwordCredential.create({ data: { userId: person.id, argon2idHash: await h.hasher.hash('suspend me for testing please') } });
    await grantAccess(h, person.id, WEB_CLIENT.clientId, ['member']);
    const theirs = await authorize(h, config, {}, new Browser(h.opFetch), { email: 'suspend-me@example.com', password: 'suspend me for testing please' });
    const tokens = await client.authorizationCodeGrant(config, theirs.callback, {
      pkceCodeVerifier: theirs.verifier,
      expectedState: theirs.state,
      expectedNonce: theirs.nonce,
    });

    expect((await call(`/api/admin/people/${person.id}/suspend`, { body: {} })).status).toBe(200);
    expect(await userinfoStatus(tokens.access_token)).toBe(401);
    expect((await tokenRequest(h, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token ?? '' })).body.access_token).toBeUndefined();

    // The owner's own tokens were never in question.
    expect(await userinfoStatus(access)).toBe(200);
    expect(refresh).not.toBe('');
    await h.service.db.user.deleteMany({ where: { id: person.id } });
  });

  it('stop working when the only group that gave access loses it, and not for anybody else', async () => {
    const call = await consoleCaller(h, config);
    // Access through a group alone: the direct grant goes first.
    const group = (await (await call('/api/admin/groups', { body: { name: `Adversarial ${Date.now()}` } })).json()) as { id: string };
    await call(`/api/admin/groups/${group.id}/members`, { body: { userIds: [ownerId] } });
    await call(`/api/admin/groups/${group.id}/access`, { body: { clientId: WEB_CLIENT.clientId, roles: ['member'] } });

    const withDirect = await tokensFor();
    await h.service.db.grant.deleteMany({ where: { userId: ownerId } });
    // A fresh session: the console caller above is itself an app session, and the grant it rode is gone.
    const groupOnly = await tokensFor();
    expect(await userinfoStatus(groupOnly.access)).toBe(200);

    const console2 = await consoleCaller(h, config);
    expect((await console2(`/api/admin/groups/${group.id}/access/revoke`, { body: { clientId: WEB_CLIENT.clientId } })).status).toBe(200);
    expect(await userinfoStatus(groupOnly.access)).toBe(401);
    expect(await userinfoStatus(withDirect.access)).toBe(401);
    await h.service.db.group.deleteMany({ where: { id: group.id } });
  });

  it('survive a group change for somebody who still has a direct grant', async () => {
    const call = await consoleCaller(h, config);
    const group = (await (await call('/api/admin/groups', { body: { name: `Adversarial ${Date.now()}` } })).json()) as { id: string };
    await call(`/api/admin/groups/${group.id}/members`, { body: { userIds: [ownerId] } });
    await call(`/api/admin/groups/${group.id}/access`, { body: { clientId: WEB_CLIENT.clientId, roles: ['admin'] } });

    const { access } = await tokensFor();
    expect((await call(`/api/admin/groups/${group.id}/remove`, { body: {} })).status).toBe(200);
    // Their direct grant still stands, so nothing they hold should have stopped working.
    expect(await userinfoStatus(access)).toBe(200);
  });

  it('stop working when the account is reset — the lost phone case', async () => {
    const person = await h.service.db.user.upsert({
      where: { email: 'lost-phone@example.com' },
      create: { email: 'lost-phone@example.com', username: 'lostphone', displayName: 'Lost Phone', status: 'active' },
      update: { status: 'active' },
    });
    await h.service.db.passwordCredential.deleteMany({ where: { userId: person.id } });
    await h.service.db.passwordCredential.create({ data: { userId: person.id, argon2idHash: await h.hasher.hash('the phone is at the bottom of a lake') } });
    await grantAccess(h, person.id, WEB_CLIENT.clientId, ['member']);
    const theirs = await authorize(h, config, {}, new Browser(h.opFetch), { email: 'lost-phone@example.com', password: 'the phone is at the bottom of a lake' });
    const tokens = await client.authorizationCodeGrant(config, theirs.callback, {
      pkceCodeVerifier: theirs.verifier,
      expectedState: theirs.state,
      expectedNonce: theirs.nonce,
    });

    const call = await consoleCaller(h, config);
    expect((await call(`/api/admin/people/${person.id}/reset`, { body: {} })).status).toBe(200);

    expect(await userinfoStatus(tokens.access_token)).toBe(401);
    expect((await tokenRequest(h, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token ?? '' })).body.access_token).toBeUndefined();
    await h.service.db.user.deleteMany({ where: { id: person.id } });
  });
});
