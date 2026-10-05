import * as client from 'openid-client';
import { Secret, TOTP } from 'otpauth';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildFromPreset, findPreset } from '../../src/admin/presets/index.js';
import { Browser, discover, grantAccess, ISSUER, markVisited, startHarness, USER, type Harness } from './oidc-harness.js';

/**
 * D3 Constellation on D3 Auth's own APIs (AUTH-T-9.1, AUTH-T-9.4, AUTH-T-9.5, AUTH-T-9.6).
 *
 * The app holds no cookie: it presents the token its grant mints for D3 Auth's own audience. That
 * token reaches /api/me, the account and the admin APIs; anything else is refused; owner and
 * account changes still want fresh proof, which the app gives with a code or a passkey and never a
 * password; and every refusal it sees is problem+json.
 */

const CONSTELLATION = { clientId: 'd3-constellation', redirect: 'd3constellation://oauth/d3auth' };
const BINDERY = 'https://bindery.d3auth.test';
const PROBLEM = 'https://d3cloud.io/problems/';

let h: Harness;
let userId = '';
let selfToken = '';
let binderyToken = '';
let refreshToken = '';
let config: client.Configuration;

const call = (path: string, init: { token?: string; method?: string; body?: unknown; headers?: Record<string, string> } = {}) =>
  h.opFetch(`${ISSUER}${path}`, {
    method: init.method ?? (init.body === undefined ? 'GET' : 'POST'),
    headers: {
      accept: 'application/json',
      ...(init.token ? { authorization: `Bearer ${init.token}` } : {}),
      ...(init.body === undefined ? {} : { 'content-type': 'application/json' }),
      ...init.headers,
    },
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });

async function problemOf(res: Response): Promise<{ type: string; status: number; [k: string]: unknown }> {
  expect(res.headers.get('content-type')).toMatch(/^application\/problem\+json/);
  const body = (await res.json()) as { type: string; status: number };
  expect(body.status).toBe(res.status);
  return body;
}

beforeAll(async () => {
  h = await startHarness();
  const db = h.service.db;
  userId = (await db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
  await db.user.update({ where: { id: userId }, data: { kind: 'owner' } });
  if (!(await db.app.findUnique({ where: { clientId: CONSTELLATION.clientId } }))) {
    const preset = findPreset('constellation');
    const built = preset ? buildFromPreset(preset, {}) : null;
    if (!built?.ok) throw new Error('the constellation preset did not build');
    await h.service.apps.register({ manifest: built.manifest, actorUserId: userId, preset: { key: 'constellation', inputs: {} } });
  }
  await db.app.upsert({
    where: { clientId: 'bindery' },
    create: { clientId: 'bindery', name: 'Bindery', clientType: 'confidential_web', homeUrl: `${BINDERY}/`, preset: 'bindery', redirectUris: { create: [{ uri: `${BINDERY}/cb` }] } },
    update: { homeUrl: `${BINDERY}/`, preset: 'bindery', enabled: true },
  });
  for (const id of [CONSTELLATION.clientId, 'bindery']) {
    await grantAccess(h, userId, id);
    await markVisited(h, userId, id);
  }

  // Signed in the way the app does it: code + PKCE in the browser, then a token per audience.
  config = await discover(h, CONSTELLATION.clientId, client.None());
  const verifier = client.randomPKCECodeVerifier();
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: CONSTELLATION.redirect,
    scope: 'openid offline_access',
    prompt: 'consent',
    code_challenge: await client.calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256',
    state: 'st',
  });
  url.searchParams.append('resource', ISSUER);
  url.searchParams.append('resource', BINDERY);
  const browser = new Browser(h.opFetch);
  let step = await browser.navigate(url.toString());
  if (!step.leftTo) step = await browser.login(step.response, USER);
  if (!step.leftTo) throw new Error('no callback');
  const tokens = await client.authorizationCodeGrant(config, step.leftTo, { pkceCodeVerifier: verifier, expectedState: 'st' }, { resource: ISSUER });
  selfToken = tokens.access_token;
  const bindery = await client.refreshTokenGrant(config, tokens.refresh_token ?? '', { resource: BINDERY });
  binderyToken = bindery.access_token;
  refreshToken = bindery.refresh_token ?? '';
});

afterAll(async () => {
  await h.close();
});

describe('the manifest (AUTH-T-9.1)', () => {
  it('names D3 Auth, signs in through the browser, and points at the APIs its token reaches', async () => {
    const res = await call('/.well-known/d3-app.json');
    expect(res.status).toBe(200);
    const manifest = (await res.json()) as { product: string; contract: number; signIn: { methods: string[] }; endpoints: Record<string, string | null> };
    expect(manifest).toMatchObject({ product: 'd3auth', contract: 1, signIn: { methods: ['oidc'] } });
    expect(manifest.endpoints).toMatchObject({
      nativeSignIn: null,
      nativeRefresh: null,
      nativeRevoke: null,
      me: `${ISSUER}/api/me`,
      accountApps: `${ISSUER}/api/account/apps`,
    });
  });
});

describe('the app token on D3 Auth’s APIs (AUTH-T-9.4, AUTH-T-9.5)', () => {
  it('answers me with the contract’s names and the console’s', async () => {
    const res = await call('/api/me', { token: selfToken });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ accountId: userId, id: userId, email: USER.email, roles: ['owner'], kind: 'owner' });
  });

  it('lists the account’s apps with each one’s home and resource', async () => {
    const res = await call('/api/account/apps', { token: selfToken });
    expect(res.status).toBe(200);
    const { apps } = (await res.json()) as { apps: { clientId: string; product?: string; homeUrl: string | null; resource: string | null; roles: string[]; grantedAt: string }[] };
    expect(apps.find((app) => app.clientId === 'bindery')).toMatchObject({ product: 'bindery', homeUrl: `${BINDERY}/`, resource: BINDERY, roles: [] });
  });

  it('refuses a product’s token, a forged one and none at all, as problems', async () => {
    for (const token of [binderyToken, `${selfToken.slice(0, -4)}AAAA`, 'not-a-jwt']) {
      const res = await call('/api/me', { token });
      expect(res.status).toBe(401);
      expect((await problemOf(res)).type).toBe(`${PROBLEM}session_revoked`);
    }
    // The console's own requests keep their shape.
    const console = await call('/api/me');
    expect(console.status).toBe(401);
    expect(console.headers.get('content-type')).toMatch(/^application\/json/);
  });

  it('a change that needs fresh proof asks for it, takes a code with no password, then goes through', async () => {
    const before = await call('/api/account/sessions/revoke-others', { token: selfToken, body: {} });
    const asked = await problemOf(before);
    expect(asked).toMatchObject({ type: `${PROBLEM}step_up_required`, status: 403, maxAgeSeconds: 300 });

    // No factor yet: the app cannot step up, and says why.
    const none = await call('/api/account/step-up', { token: selfToken, body: { code: '000000' } });
    expect((await problemOf(none)).code).toBe('factor_required');

    const enrolment = await h.service.totp.begin({ userId, accountName: USER.email });
    const authenticator = new TOTP({ secret: Secret.fromBase32(enrolment.manualKey) });
    expect(await h.service.totp.confirm({ userId, credentialId: enrolment.credentialId, code: authenticator.generate() })).toBe(true);

    const wrong = await call('/api/account/step-up', { token: selfToken, body: { code: '000000', password: 'ignored' } });
    expect((await problemOf(wrong)).type).toBe(`${PROBLEM}invalid_code`);

    const code = authenticator.generate({ timestamp: Date.now() + 30_000 });
    const stepped = await call('/api/account/step-up', { token: selfToken, body: { code } });
    expect(stepped.status).toBe(200);
    expect(((await stepped.json()) as { ok: boolean; until: string }).ok).toBe(true);
    expect(await h.service.db.nativeStepUp.count({ where: { userId } })).toBe(1);

    const after = await call('/api/account/sessions/revoke-others', { token: selfToken, body: {} });
    expect(after.status).toBe(200);
  });

  it('taking away access to Constellation ends its token at once, not at expiry', async () => {
    const app = await h.service.db.app.findUniqueOrThrow({ where: { clientId: CONSTELLATION.clientId } });
    await h.service.db.grant.delete({ where: { userId_appId: { userId, appId: app.id } } });
    try {
      expect((await call('/api/me', { token: selfToken })).status).toBe(401);
    } finally {
      await grantAccess(h, userId, CONSTELLATION.clientId);
    }
    expect(refreshToken).not.toBe('');
  });
});
