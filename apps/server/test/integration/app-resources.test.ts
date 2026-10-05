import * as client from 'openid-client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildFromPreset, findPreset } from '../../src/admin/presets/index.js';
import { Browser, discover, grantAccess, markVisited, startHarness, USER, type Harness } from './oidc-harness.js';

/**
 * Resource servers derived from registered apps (AUTH-T-9.3, AUTH-ADR-008).
 *
 * D3 Constellation signs in once with its preset client and mints, from that one grant, a token
 * for each product's audience — the origin of the product's registered home URL. What is tested
 * hardest is who may mint what: only Constellation's client may name an app's audience, only for
 * an app the person holds a grant to, and a grant taken away stops the next refresh.
 */

const ISSUER_SELF = 'https://op.d3auth.test';
const BINDERY = 'https://bindery.d3auth.test';
const POSTROOM = 'https://mail.d3auth.test';
const CONSTELLATION = { clientId: 'd3-constellation', redirect: 'd3constellation://oauth/d3auth' };

let h: Harness;
let userId = '';

const decode = (jwt: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(jwt.split('.')[1] ?? '', 'base64url').toString('utf8')) as Record<string, unknown>;

async function registerApp(clientId: string, homeUrl: string | null, extra: { preset?: string; clientType?: 'public_native' | 'confidential_web'; redirect?: string } = {}): Promise<void> {
  const db = h.service.db;
  // Another file in this run may have registered the same app: these files share one database.
  await db.app.deleteMany({ where: { clientId } });
  await db.app.create({
    data: {
      clientId,
      name: clientId,
      clientType: extra.clientType ?? 'confidential_web',
      homeUrl,
      ...(extra.preset ? { preset: extra.preset } : {}),
      redirectUris: { create: [{ uri: extra.redirect ?? `${homeUrl ?? 'https://x.d3auth.test'}/cb` }] },
    },
  });
}

/** Authorization code + PKCE as D3 Constellation does it, then the code exchanged. */
async function signIn(
  clientId: string,
  redirect: string,
  resources: string[],
  opts: { browser?: Browser; prompt?: string } = {},
): Promise<{ config: client.Configuration; tokens: client.TokenEndpointResponse; browser: Browser }> {
  const config = await discover(h, clientId, client.None());
  const params: Record<string, string> = { redirect_uri: redirect, scope: 'openid offline_access', prompt: opts.prompt ?? 'consent' };
  const browser = opts.browser ?? new Browser(h.opFetch);
  // openid-client takes one value per key, so the resources go on the URL by hand.
  const verifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const url = client.buildAuthorizationUrl(config, {
    ...params,
    code_challenge: await client.calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256',
    state,
  });
  for (const resource of resources) url.searchParams.append('resource', resource);
  let step = await browser.navigate(url.toString());
  if (!step.leftTo && opts.prompt !== 'none') step = await browser.login(step.response, USER);
  if (!step.leftTo) throw new Error(`authorization did not return: ${String(step.response.status)}`);
  const callback = new URL(step.leftTo.toString());
  if (callback.searchParams.has('error')) throw new Error(`${callback.searchParams.get('error') ?? 'error'}: ${callback.searchParams.get('error_description') ?? ''}`);
  const tokens = await client.authorizationCodeGrant(config, callback, { pkceCodeVerifier: verifier, expectedState: state }, resources[0] ? { resource: resources[0] } : {});
  return { config, tokens, browser };
}

const refreshFor = (config: client.Configuration, refreshToken: string, resource: string) =>
  client.refreshTokenGrant(config, refreshToken, { resource });

beforeAll(async () => {
  h = await startHarness();
  userId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
  // Registered the way an owner does it: the preset, one step (AUTH-T-9.2).
  const preset = findPreset('constellation');
  const built = preset ? buildFromPreset(preset, {}) : null;
  if (!built?.ok) throw new Error('the constellation preset did not build');
  await h.service.db.app.deleteMany({ where: { clientId: CONSTELLATION.clientId } });
  await h.service.apps.register({ manifest: built.manifest, actorUserId: userId, preset: { key: 'constellation', inputs: {} } });
  await registerApp('bindery', `${BINDERY}/`);
  await registerApp('postroom', `${POSTROOM}/`);
  for (const clientId of [CONSTELLATION.clientId, 'bindery', 'postroom']) {
    await grantAccess(h, userId, clientId);
    await markVisited(h, userId, clientId);
  }
});

afterAll(async () => {
  await h.close();
});

describe('one Constellation grant, a token per product', () => {
  it('mints tokens audienced at each granted app and at D3 Auth itself, from one refresh token', async () => {
    const { config, tokens } = await signIn(CONSTELLATION.clientId, CONSTELLATION.redirect, [BINDERY, POSTROOM, ISSUER_SELF]);
    expect(decode(tokens.access_token)['aud']).toBe(BINDERY);
    const refresh = tokens.refresh_token ?? '';
    expect(refresh).not.toBe('');

    const postroom = await refreshFor(config, refresh, POSTROOM);
    expect(decode(postroom.access_token)['aud']).toBe(POSTROOM);
    const self = await refreshFor(config, postroom.refresh_token ?? refresh, ISSUER_SELF);
    expect(decode(self.access_token)['aud']).toBe(ISSUER_SELF);
    // No roles in a resource token: each product reads its own (AUTH-ADR-008).
    expect(decode(self.access_token)['roles']).toBeUndefined();
  });

  it('an app registered later is requestable at once, through a silent re-authorization', async () => {
    const first = await signIn(CONSTELLATION.clientId, CONSTELLATION.redirect, [BINDERY, ISSUER_SELF]);
    await registerApp('shipyard', 'https://shipyard.d3auth.test/');
    await grantAccess(h, userId, 'shipyard');
    // prompt=none with the same browser session: no sign-in page, no consent, a code at once.
    const again = await signIn(CONSTELLATION.clientId, CONSTELLATION.redirect, ['https://shipyard.d3auth.test', BINDERY, ISSUER_SELF], {
      browser: first.browser,
      prompt: 'none',
    });
    expect(decode(again.tokens.access_token)['aud']).toBe('https://shipyard.d3auth.test');
    const bindery = await refreshFor(again.config, again.tokens.refresh_token ?? '', BINDERY);
    expect(decode(bindery.access_token)['aud']).toBe(BINDERY);
  });
});

describe('who may mint what (adversarial)', () => {
  it('refuses a resource no app or allowlist names, and near-misses of a real one', async () => {
    for (const resource of ['https://evil.d3auth.test', `${BINDERY}/`, `${BINDERY}/api`, 'https://bindery.d3auth.test.evil.example', 'http://bindery.d3auth.test']) {
      await expect(signIn(CONSTELLATION.clientId, CONSTELLATION.redirect, [resource]), resource).rejects.toThrow();
    }
  });

  it('refuses an app audience to any client but Constellation', async () => {
    await registerApp('lookalike', null, { clientType: 'public_native', redirect: 'com.lookalike:/cb' });
    await grantAccess(h, userId, 'lookalike');
    await markVisited(h, userId, 'lookalike');
    await expect(signIn('lookalike', 'com.lookalike:/cb', [BINDERY])).rejects.toThrow();
    await expect(signIn('lookalike', 'com.lookalike:/cb', [ISSUER_SELF])).rejects.toThrow();
    // It can still sign in for itself: only the foreign audience is refused.
    await expect(signIn('lookalike', 'com.lookalike:/cb', [])).resolves.toBeDefined();
  });

  it("refuses an app the person has no grant to, and stops refreshing one whose grant is taken away", async () => {
    await registerApp('foreman', 'https://foreman.d3auth.test/');
    // No grant to Foreman: it is not added to the grant, so the token endpoint refuses it.
    const { config, tokens } = await signIn(CONSTELLATION.clientId, CONSTELLATION.redirect, [BINDERY, 'https://foreman.d3auth.test', ISSUER_SELF]);
    await expect(refreshFor(config, tokens.refresh_token ?? '', 'https://foreman.d3auth.test')).rejects.toThrow();

    // That refusal must not burn the refresh token: a burned one comes back as reuse and revokes
    // the whole grant, signing the person out of every product for one they lack.
    const app = await h.service.db.app.findUniqueOrThrow({ where: { clientId: 'bindery' } });
    const working = await refreshFor(config, tokens.refresh_token ?? '', BINDERY);
    expect(decode(working.access_token)['aud']).toBe(BINDERY);
    await h.service.db.grant.delete({ where: { userId_appId: { userId, appId: app.id } } });
    await expect(refreshFor(config, working.refresh_token ?? '', BINDERY)).rejects.toThrow();
    // …and the grant survives it: D3 Auth's own audience still refreshes with the same token.
    const self = await refreshFor(config, working.refresh_token ?? '', ISSUER_SELF);
    expect(decode(self.access_token)['aud']).toBe(ISSUER_SELF);
    await grantAccess(h, userId, 'bindery');
  });

  it('prompt=none stays refused for every other native client', async () => {
    const first = await signIn('lookalike', 'com.lookalike:/cb', []);
    await expect(signIn('lookalike', 'com.lookalike:/cb', [], { browser: first.browser, prompt: 'none' })).rejects.toThrow(/interaction_required/);
  });

  it('a disabled app has no audience', async () => {
    await h.service.db.app.update({ where: { clientId: 'postroom' }, data: { enabled: false } });
    try {
      await expect(signIn(CONSTELLATION.clientId, CONSTELLATION.redirect, [POSTROOM])).rejects.toThrow();
    } finally {
      await h.service.db.app.update({ where: { clientId: 'postroom' }, data: { enabled: true } });
    }
  });
});

