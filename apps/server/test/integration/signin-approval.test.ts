import { createECDH, randomUUID } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import * as client from 'openid-client';
import { Secret, TOTP } from 'otpauth';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildFromPreset, findPreset } from '../../src/admin/presets/index.js';
import { openEnvelope } from '../../src/push/envelope.js';
import { Browser, discover, grantAccess, ISSUER, markVisited, RP_CALLBACK, startHarness, USER, WEB_CLIENT, webClientConfig, type Harness } from './oidc-harness.js';

/**
 * Sign-in approval with number matching, and login alerts (AUTH-T-10.5, d3-app-contract
 * spec/sign-in-approval.md). A browser at the second factor asks the phone; the phone reads three
 * numbers and picks the browser's; one answer decides; a wrong number or a denial refuses the
 * sign-in and leaves the code; two minutes and it is gone. A sign-in that did not come through the
 * phone tells the phone it happened.
 */

const CONSTELLATION = { clientId: 'd3-constellation', redirect: 'd3constellation://oauth/d3auth' };
const PASSWORD = 'a password for the approval tests';

let h: Harness;
let relay: Server;
let relayUrl = '';
const pushes: { path: string; raw: string }[] = [];

interface Person { id: string; email: string; token: string; key: ReturnType<typeof createECDH>; code: (offsetMs?: number) => string }

const call = (path: string, init: { token?: string; body?: unknown } = {}) =>
  h.opFetch(`${ISSUER}${path}`, {
    method: init.body === undefined ? 'GET' : 'POST',
    headers: {
      accept: 'application/json',
      ...(init.token ? { authorization: `Bearer ${init.token}` } : {}),
      ...(init.body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });

async function pushFor(registration: string, category: string, after = 0): Promise<Record<string, unknown>> {
  for (let i = 0; i < 80; i++) {
    for (const p of pushes.slice(after)) {
      if (p.path !== `/v1/push/${registration}`) continue;
      return p;
    }
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`no ${category} push`);
}
const opened = (person: Person, raw: string) =>
  JSON.parse(openEnvelope(person.key, (JSON.parse(raw) as { ciphertext: string }).ciphertext).toString()) as Record<string, unknown>;

/** A person with an authenticator, signed in on the phone, their device registered for approvals. */
async function person(opts: { register?: boolean } = {}): Promise<Person & { registration: string }> {
  const db = h.service.db;
  const email = `approver-${randomUUID()}@example.com`;
  const user = await db.user.create({
    data: { email, username: `approver-${randomUUID().slice(0, 8)}`, displayName: 'Approver', kind: 'guest', status: 'active', passwordCredentials: { create: { argon2idHash: await h.hasher.hash(PASSWORD) } } },
  });
  for (const id of [CONSTELLATION.clientId, WEB_CLIENT.clientId]) {
    await grantAccess(h, user.id, id, id === WEB_CLIENT.clientId ? ['member'] : []);
    await markVisited(h, user.id, id);
  }
  const config = await discover(h, CONSTELLATION.clientId, client.None());
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
  const browser = new Browser(h.opFetch);
  let step = await browser.navigate(url.toString());
  if (!step.leftTo) step = await browser.login(step.response, { email, password: PASSWORD });
  if (!step.leftTo) throw new Error('no callback');
  const tokens = await client.authorizationCodeGrant(config, step.leftTo, { pkceCodeVerifier: verifier, expectedState: 'st' }, { resource: ISSUER });
  const enrolment = await h.service.totp.begin({ userId: user.id, accountName: email });
  const authenticator = new TOTP({ secret: Secret.fromBase32(enrolment.manualKey) });
  expect(await h.service.totp.confirm({ userId: user.id, credentialId: enrolment.credentialId, code: authenticator.generate() })).toBe(true);
  const key = createECDH('prime256v1');
  key.generateKeys();
  const registration = `reg-${randomUUID()}`;
  if (opts.register !== false) {
    const res = await call('/api/push/native/register', {
      token: tokens.access_token,
      body: { devicePublicKey: key.getPublicKey().toString('base64'), relay: { url: relayUrl, registration, sendKey: `send-key-${registration}` }, categories: ['d3auth.signin-approval', 'd3auth.login'] },
    });
    expect(res.status).toBe(204);
  }
  return { id: user.id, email, token: tokens.access_token, key, registration, code: (offsetMs = 30_000) => authenticator.generate({ timestamp: Date.now() + offsetMs }) };
}

/** A laptop signing in to the web app, stopped at the second factor. */
async function laptopAtFactor(who: { email: string }): Promise<{ browser: Browser; uid: string; csrf: string; factors: string[] }> {
  const config = await webClientConfig(h);
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: RP_CALLBACK,
    scope: 'openid',
    code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
    code_challenge_method: 'S256',
    state: 'st',
  });
  const browser = new Browser(h.opFetch);
  const step = await browser.navigate(url.toString());
  const signedIn = await browser.login(step.response, { email: who.email, password: PASSWORD });
  expect(signedIn.body['step']).toBe('factor');
  const uid = new URL(browser.lastUrl).pathname.split('/')[2] ?? '';
  const view = (await (await browser.api(uid, '')).json()) as { csrf: string };
  return { browser, uid, csrf: view.csrf, factors: signedIn.body['factors'] as string[] };
}

beforeAll(async () => {
  relay = createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk: Buffer) => (raw += chunk.toString()));
    req.on('end', () => {
      pushes.push({ path: req.url ?? '', raw });
      res.writeHead(202);
      res.end('{}');
    });
  });
  await new Promise<void>((resolve) => relay.listen(0, '127.0.0.1', () => { resolve(); }));
  relayUrl = `http://127.0.0.1:${String((relay.address() as AddressInfo).port)}`;
  h = await startHarness();
  const db = h.service.db;
  const ownerId = (await db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
  if (!(await db.app.findUnique({ where: { clientId: CONSTELLATION.clientId } }))) {
    const preset = findPreset('constellation');
    const built = preset ? buildFromPreset(preset, {}) : null;
    if (!built?.ok) throw new Error('the constellation preset did not build');
    await h.service.apps.register({ manifest: built.manifest, actorUserId: ownerId, preset: { key: 'constellation', inputs: {} } });
  }
});

afterAll(async () => {
  relay.close();
  await h.close();
});

describe('sign-in approval (AUTH-T-10.5)', () => {
  it('is offered only beside a code, and only with a registered device', async () => {
    const unregistered = await person({ register: false });
    expect((await laptopAtFactor(unregistered)).factors).toEqual(['totp']);
    const registered = await person();
    expect((await laptopAtFactor(registered)).factors).toEqual(['totp', 'push']);
  });

  it('approves a laptop sign-in from the phone by picking the number it shows', async () => {
    const who = await person();
    const laptop = await laptopAtFactor(who);
    const seen = pushes.length;
    const started = (await (await laptop.browser.api(laptop.uid, '/approval', { csrf: laptop.csrf })).json()) as { approvalId: string; number: number; expiresAt: string };
    expect(started.number).toBeGreaterThanOrEqual(10);
    expect(started.number).toBeLessThanOrEqual(99);
    expect(Date.parse(started.expiresAt) - Date.now()).toBeLessThanOrEqual(2 * 60 * 1000);

    const pushed = await pushFor(who.registration, 'd3auth.signin-approval', seen);
    expect(opened(who, pushed['raw'] as string)).toMatchObject({ category: 'd3auth.signin-approval', link: `d3constellation://${new URL(ISSUER).host}/d3auth/approval/${started.approvalId}` });

    // Still pending until the phone answers.
    expect(await (await laptop.browser.api(laptop.uid, `/approval/${started.approvalId}`, { csrf: laptop.csrf })).json()).toMatchObject({ status: 'pending' });

    const view = (await (await call(`/api/account/approvals/${started.approvalId}`, { token: who.token })).json()) as { id: string; browser: string; choices: number[]; expiresAt: string };
    expect(view.choices).toHaveLength(3);
    expect(new Set(view.choices).size).toBe(3);
    expect(view.choices).toContain(started.number);
    expect(view.choices.every((n) => n >= 10 && n <= 99)).toBe(true);

    const answered = await call(`/api/account/approvals/${started.approvalId}`, { token: who.token, body: { number: started.number } });
    expect(await answered.json()).toEqual({ result: 'approved' });
    // One answer per approval.
    expect((await call(`/api/account/approvals/${started.approvalId}`, { token: who.token, body: { number: started.number } })).status).toBe(410);
    expect((await call(`/api/account/approvals/${started.approvalId}`, { token: who.token })).status).toBe(410);

    const done = (await (await laptop.browser.api(laptop.uid, `/approval/${started.approvalId}`, { csrf: laptop.csrf })).json()) as { step?: string; redirectTo?: string; status?: string };
    // A factor answered on a browser that is not trusted yet goes on to the trust offer.
    expect(done.step === 'trust' || typeof done.redirectTo === 'string').toBe(true);
    // Spent: asking again does not sign in twice.
    expect((await laptop.browser.api(laptop.uid, `/approval/${started.approvalId}`, { csrf: laptop.csrf })).status).toBe(409);
  });

  it('refuses the sign-in on a wrong number or a denial, and the code still works', async () => {
    const who = await person();
    for (const answer of [{ wrongNumber: true }, { deny: true }]) {
      const laptop = await laptopAtFactor(who);
      const started = (await (await laptop.browser.api(laptop.uid, '/approval', { csrf: laptop.csrf })).json()) as { approvalId: string; number: number };
      const view = (await (await call(`/api/account/approvals/${started.approvalId}`, { token: who.token })).json()) as { choices: number[] };
      const wrong = view.choices.find((n) => n !== started.number) ?? 0;
      const body = 'deny' in answer ? { deny: true } : { number: wrong };
      const result = (await (await call(`/api/account/approvals/${started.approvalId}`, { token: who.token, body })).json()) as { result: string };
      expect(result.result).toBe('deny' in answer ? 'denied' : 'wrong_number');
      const refused = await laptop.browser.api(laptop.uid, `/approval/${started.approvalId}`, { csrf: laptop.csrf });
      expect(refused.status).toBe(401);
      expect(((await refused.json()) as { status: string }).status).toBe(result.result);
      await h.service.db.throttleCounter.deleteMany();
      // Enrolment burned this step's code; the test forgets that rather than waiting for the next one.
      await h.service.db.totpCredential.updateMany({ where: { userId: who.id }, data: { lastUsedStep: null } });
      await h.service.db.totpCredential.updateMany({ where: { userId: who.id }, data: { lastUsedStep: null } });
    const code = await laptop.browser.api(laptop.uid, '/totp', { csrf: laptop.csrf, code: who.code(0) });
      expect(code.status).toBe(200);
    }
  });

  it('expires after two minutes', async () => {
    const who = await person();
    const laptop = await laptopAtFactor(who);
    const started = (await (await laptop.browser.api(laptop.uid, '/approval', { csrf: laptop.csrf })).json()) as { approvalId: string; number: number };
    await h.service.db.signinApproval.update({ where: { id: started.approvalId }, data: { expiresAt: new Date(Date.now() - 1000) } });
    expect((await call(`/api/account/approvals/${started.approvalId}`, { token: who.token })).status).toBe(410);
    expect(await (await call(`/api/account/approvals/${started.approvalId}`, { token: who.token, body: { number: started.number } })).json()).toEqual({ result: 'expired' });
    expect(await (await laptop.browser.api(laptop.uid, `/approval/${started.approvalId}`, { csrf: laptop.csrf })).json()).toMatchObject({ status: 'expired' });
  });

  it('never shows one person’s approval to another', async () => {
    const owner = await person();
    const stranger = await person();
    const laptop = await laptopAtFactor(owner);
    const started = (await (await laptop.browser.api(laptop.uid, '/approval', { csrf: laptop.csrf })).json()) as { approvalId: string; number: number };
    expect((await call(`/api/account/approvals/${started.approvalId}`, { token: stranger.token })).status).toBe(404);
    expect((await call(`/api/account/approvals/${started.approvalId}`, { token: stranger.token, body: { number: started.number } })).status).toBe(404);
  });

  it('tells the phone about a sign-in it did not approve', async () => {
    const who = await person();
    const laptop = await laptopAtFactor(who);
    const seen = pushes.length;
    await h.service.db.throttleCounter.deleteMany();
    await h.service.db.totpCredential.updateMany({ where: { userId: who.id }, data: { lastUsedStep: null } });
    const code = await laptop.browser.api(laptop.uid, '/totp', { csrf: laptop.csrf, code: who.code(0) });
    expect(code.status).toBe(200);
    const trust = await laptop.browser.api(laptop.uid, '/trust', { csrf: laptop.csrf, trust: 'false' });
    expect(trust.status).toBe(200);
    const pushed = await pushFor(who.registration, 'd3auth.login', seen);
    expect(opened(who, pushed['raw'] as string)).toMatchObject({ category: 'd3auth.login', title: 'New sign-in to D3 Auth', link: `d3constellation://${new URL(ISSUER).host}/d3auth/sessions` });
  });
});
