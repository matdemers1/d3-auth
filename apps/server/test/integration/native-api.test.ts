import { createECDH } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import * as client from 'openid-client';
import { openEnvelope } from '../../src/push/envelope.js';
import { signRelayRequest } from '../../src/push/relay.js';
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

describe('push through the relay (AUTH-T-10.4)', () => {
  const pushes: { path: string; timestamp: string; signature: string; raw: string }[] = [];
  let relay: Server;
  let relayUrl = '';
  let answer = 202;
  beforeAll(async () => {
    relay = createServer((req, res) => {
      let raw = '';
      req.on('data', (chunk: Buffer) => (raw += chunk.toString()));
      req.on('end', () => {
        pushes.push({ path: req.url ?? '', timestamp: String(req.headers['x-d3-relay-timestamp']), signature: String(req.headers['x-d3-relay-signature']), raw });
        res.writeHead(answer);
        res.end('{}');
      });
    });
    await new Promise<void>((resolve) => relay.listen(0, '127.0.0.1', () => { resolve(); }));
    relayUrl = `http://127.0.0.1:${String((relay.address() as AddressInfo).port)}`;
  });
  afterAll(() => {
    relay.close();
  });
  const device = () => {
    const pair = createECDH('prime256v1');
    pair.generateKeys();
    return pair;
  };
  const register = (token: string, key: ReturnType<typeof device>, registration: string, url = relayUrl) =>
    call('/api/push/native/register', { token, body: { devicePublicKey: key.getPublicKey().toString('base64'), relay: { url, registration, sendKey: `send-key-${registration}-0123456789` }, categories: ['d3auth.login'] } });
  const waitFor = async (registration: string) => {
    for (let i = 0; i < 80; i++) {
      const found = pushes.find((p) => p.path === `/v1/push/${registration}`);
      if (found !== undefined) return found;
      await new Promise((r) => setTimeout(r, 25));
    }
    throw new Error('no push');
  };

  it('the manifest names the endpoint', async () => {
    const manifest = (await (await call('/.well-known/d3-app.json')).json()) as { endpoints: Record<string, string> };
    expect(manifest.endpoints['relayRegister']).toBe(`${ISSUER}/api/push/native/register`);
  });

  it('the app’s token registers, and one d3auth.registered notification arrives only the device can open', async () => {
    const key = device();
    expect((await register(selfToken, key, 'reg-auth')).status).toBe(204);
    const pushed = await waitFor('reg-auth');
    expect(pushed.signature).toBe(signRelayRequest('send-key-reg-auth-0123456789', pushed.timestamp, pushed.raw));
    const payload = JSON.parse(openEnvelope(key, (JSON.parse(pushed.raw) as { ciphertext: string }).ciphertext).toString()) as Record<string, unknown>;
    expect(payload).toMatchObject({ v: 1, category: 'd3auth.registered' });
    const row = await h.service.db.relayRegistration.findFirstOrThrow({ where: { registration: 'reg-auth' } });
    expect(Buffer.from(row.sendKeySealed).toString('utf8')).not.toContain('send-key');
  });

  it('refuses a bad registration, plain http off loopback, a product’s token and no token', async () => {
    const key = device();
    expect((await call('/api/push/native/register', { token: selfToken, body: { devicePublicKey: key.getPublicKey().toString('base64') } })).status).toBe(400);
    expect((await register(selfToken, key, 'plain', 'http://relay.example.com')).status).toBe(400);
    expect((await register(binderyToken, key, 'bindery-token')).status).toBe(401);
    expect((await call('/api/push/native/register', { body: {} })).status).toBe(401);
  });

  it('a 410 from the relay forgets the registration', async () => {
    const key = device();
    answer = 410;
    try {
      expect((await register(selfToken, key, 'reg-gone')).status).toBe(204);
      await waitFor('reg-gone');
      for (let i = 0; i < 40 && (await h.service.db.relayRegistration.count({ where: { registration: 'reg-gone' } })) > 0; i++) await new Promise((r) => setTimeout(r, 25));
      expect(await h.service.db.relayRegistration.count({ where: { registration: 'reg-gone' } })).toBe(0);
    } finally {
      answer = 202;
    }
  });
});

describe('passkeys for the app (AUTH-T-9.7)', () => {
  it('serves apple-app-site-association naming D3 Constellation, as JSON, with no redirect', async () => {
    const res = await call('/.well-known/apple-app-site-association');
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toMatch(/^application\/json/);
    expect(await res.json()).toEqual({ webcredentials: { apps: ['GC63HV279B.io.d3cloud.constellation'] } });
  });
});

describe('inviting with groups and grants (AUTH-T-9.8)', () => {
  it('refuses an unknown group, app or role, and sends nothing', async () => {
    for (const [body, code] of [
      [{ email: 'x1@example.com', groupIds: ['00000000-0000-7000-8000-000000000000'] }, 'unknown_group'],
      [{ email: 'x2@example.com', grants: [{ clientId: 'no-such-app', roles: [] }] }, 'no_such_app'],
      [{ email: 'x3@example.com', grants: [{ clientId: 'bindery', roles: ['emperor'] }] }, 'unknown_roles'],
    ] as const) {
      const res = await call('/api/admin/invites', { token: selfToken, body });
      expect(res.status).toBe(400);
      expect((await problemOf(res))['code']).toBe(code);
    }
    expect(await h.service.db.invite.count({ where: { email: { in: ['x1@example.com', 'x2@example.com', 'x3@example.com'] } } })).toBe(0);
  });

  it('stores what it was given for the accept to apply', async () => {
    const res = await call('/api/admin/invites', { token: selfToken, body: { email: 'kim@example.com', grants: [{ clientId: 'bindery', roles: [] }] } });
    expect(res.status).toBe(201);
    const row = await h.service.db.invite.findFirstOrThrow({ where: { email: 'kim@example.com' } });
    expect(row.initialGrants).toEqual({ groupIds: [], grants: [{ clientId: 'bindery', roles: [] }] });
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
