import * as client from 'openid-client';
import { Secret, TOTP } from 'otpauth';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { authorize, Browser, grantAccess, RP_CALLBACK, startHarness, USER, WEB_CLIENT, webClientConfig, type Harness } from '../integration/oidc-harness.js';

// Attack class: getting past the sign-in without the things it asks for (REQ-026, REQ-027,
// REQ-033, REQ-036, REQ-037).
//
// The sign-in is a state machine precisely so that nobody can reach "done" by posting to the
// right URL in the wrong order. These attacks post to the right URLs in the wrong order, replay
// codes that already worked, hammer the password step to see whether the hashing work still
// happens, and time the answer for an account that exists against one that does not.

let h: Harness;
let config: client.Configuration;

const PERSON = { email: 'credentials-target@example.com', password: 'a long and honest passphrase' };
let personId: string;
let authenticator: TOTP;

/** Starts an authorization request and returns the interaction uid with its CSRF token. */
async function signInScreen(browser: Browser, extra: Record<string, string> = {}): Promise<{ uid: string; csrf: string }> {
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: RP_CALLBACK,
    scope: 'openid',
    code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
    code_challenge_method: 'S256',
    state: client.randomState(),
    nonce: client.randomNonce(),
    ...extra,
  });
  const { response } = await browser.navigate(url.toString());
  const uid = new URL(response.url || browser.lastUrl).pathname.split('/')[2] ?? '';
  const view = (await (await browser.api(uid, '')).json()) as { csrf: string };
  return { uid, csrf: view.csrf };
}

const json = async (response: Response): Promise<Record<string, unknown>> => (await response.json()) as Record<string, unknown>;

/** The next code nobody has used, waiting for the step to turn over if the current one is spent. */
async function freshCode(): Promise<string> {
  const used = await h.service.db.totpCredential.findFirstOrThrow({ where: { userId: personId } });
  const step = 30_000;
  let at = Date.now();
  while (BigInt(Math.floor(at / step)) <= (used.lastUsedStep ?? -1n)) at += step;
  return authenticator.generate({ timestamp: at });
}

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  const person = await h.service.db.user.upsert({
    where: { email: PERSON.email },
    create: { email: PERSON.email, username: 'credtarget', displayName: 'Credentials Target', status: 'active' },
    update: { status: 'active' },
  });
  personId = person.id;
  await h.service.db.passwordCredential.deleteMany({ where: { userId: personId } });
  await h.service.db.passwordCredential.create({ data: { userId: personId, argon2idHash: await h.hasher.hash(PERSON.password) } });
  await grantAccess(h, personId, WEB_CLIENT.clientId, ['member']);
  await h.service.db.appVisit.deleteMany({ where: { userId: personId } });
});

afterAll(async () => {
  await h.service.db.user.deleteMany({ where: { id: personId } });
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  await h.service.db.trustedDevice.deleteMany({ where: { userId: personId } });
  await h.service.db.totpCredential.deleteMany({ where: { userId: personId } });
});

async function enrolTotp(): Promise<void> {
  const enrolment = await h.service.totp.begin({ userId: personId, accountName: PERSON.email });
  authenticator = new TOTP({ secret: Secret.fromBase32(enrolment.manualKey) });
  expect(await h.service.totp.confirm({ userId: personId, credentialId: enrolment.credentialId, code: authenticator.generate() })).toBe(true);
}

describe('the steps, out of order', () => {
  it('a factor cannot be answered before the password', async () => {
    await enrolTotp();
    const browser = new Browser(h.opFetch);
    const { uid, csrf } = await signInScreen(browser);
    await browser.api(uid, '/identify', { csrf, email: PERSON.email });
    const skipped = await browser.api(uid, '/totp', { csrf, code: await freshCode() });
    expect(skipped.status).toBe(409);
  });

  it('the trusted-device answer cannot stand in for the factor', async () => {
    await enrolTotp();
    const browser = new Browser(h.opFetch);
    const { uid, csrf } = await signInScreen(browser);
    await browser.api(uid, '/identify', { csrf, email: PERSON.email });
    expect(await json(await browser.api(uid, '/password', { csrf, password: PERSON.password }))).toMatchObject({ step: 'factor' });

    const trust = await browser.api(uid, '/trust', { csrf, trust: 'true' });
    expect(trust.status).toBe(409);
    expect(await h.service.db.trustedDevice.count({ where: { userId: personId } })).toBe(0);
  });

  it('the continue-as answer cannot stand in for signing in at all', async () => {
    const browser = new Browser(h.opFetch);
    const { uid, csrf } = await signInScreen(browser);
    await browser.api(uid, '/identify', { csrf, email: PERSON.email });
    // No password. Nobody is signed in on this browser.
    const response = await browser.api(uid, '/continue', { csrf });
    // Refused as a step out of order — not a crash, and certainly not a code.
    expect(response.status).toBe(409);
    expect(h.logLines.join('\n')).not.toMatch(/"level":50.*continue/);
  });

  it('the continue-as answer cannot skip a re-authentication the app asked for (prompt=login)', async () => {
    const browser = new Browser(h.opFetch);
    // A real session first, on this browser.
    await authorize(h, config, {}, browser, PERSON);

    // The app now insists on a fresh sign-in, and somebody at the keyboard tries to skip it.
    const { uid, csrf } = await signInScreen(browser, { prompt: 'login' });
    const answer = await json(await browser.api(uid, '/continue', { csrf }));
    const next = typeof answer.redirectTo === 'string' ? await browser.navigate(answer.redirectTo) : undefined;
    expect(next?.leftTo?.searchParams.get('code') ?? null).toBeNull();
  });

  it('an interaction started in one browser cannot be finished from another', async () => {
    const victim = new Browser(h.opFetch);
    const { uid, csrf } = await signInScreen(victim);
    await victim.api(uid, '/identify', { csrf, email: PERSON.email });

    const attacker = new Browser(h.opFetch);
    const stolen = await attacker.api(uid, '/password', { csrf, password: PERSON.password });
    expect(stolen.status).toBeGreaterThanOrEqual(400);
  });
});

describe('a replayed authenticator code (REQ-033)', () => {
  it('works once, and is refused on the very next sign-in even inside its window', async () => {
    await enrolTotp();
    const code = await freshCode();

    const first = new Browser(h.opFetch);
    const one = await signInScreen(first);
    await first.api(one.uid, '/identify', { csrf: one.csrf, email: PERSON.email });
    await first.api(one.uid, '/password', { csrf: one.csrf, password: PERSON.password });
    expect(await json(await first.api(one.uid, '/totp', { csrf: one.csrf, code }))).toMatchObject({ step: 'trust' });

    const second = new Browser(h.opFetch);
    const two = await signInScreen(second);
    await second.api(two.uid, '/identify', { csrf: two.csrf, email: PERSON.email });
    await second.api(two.uid, '/password', { csrf: two.csrf, password: PERSON.password });
    const replay = await second.api(two.uid, '/totp', { csrf: two.csrf, code });
    expect(replay.status).toBe(401);
  });

  it('cannot be guessed at without the throttle noticing', async () => {
    await enrolTotp();
    const browser = new Browser(h.opFetch);
    const { uid, csrf } = await signInScreen(browser);
    await browser.api(uid, '/identify', { csrf, email: PERSON.email });
    await browser.api(uid, '/password', { csrf, password: PERSON.password });

    const statuses: number[] = [];
    for (let attempt = 0; attempt < 8; attempt += 1) {
      statuses.push((await browser.api(uid, '/totp', { csrf, code: String(attempt).padStart(6, '0') })).status);
    }
    expect(statuses).toContain(429);
  });
});

describe('the cost of a throttled attempt (REQ-027, REQ-028)', () => {
  async function passwordAttempt(email: string, password: string): Promise<number> {
    const browser = new Browser(h.opFetch);
    const { uid, csrf } = await signInScreen(browser);
    await browser.api(uid, '/identify', { csrf, email });
    return (await browser.api(uid, '/password', { csrf, password })).status;
  }

  it('does no hashing once an account is throttled — not even for the right password', async () => {
    for (let attempt = 0; attempt < 5; attempt += 1) await passwordAttempt(PERSON.email, 'wrong');
    const before = h.passwordVerifications.count;

    expect(await passwordAttempt(PERSON.email, 'wrong again')).toBe(429);
    expect(await passwordAttempt(PERSON.email, PERSON.password)).toBe(429);
    expect(h.passwordVerifications.count).toBe(before);
  });

  it('throttles an address that does not exist the same way, so the throttle says nothing about who is real', async () => {
    const statuses: number[] = [];
    for (let attempt = 0; attempt < 6; attempt += 1) statuses.push(await passwordAttempt('nobody-at-all@example.com', 'guess'));
    const real: number[] = [];
    await h.service.db.throttleCounter.deleteMany();
    for (let attempt = 0; attempt < 6; attempt += 1) real.push(await passwordAttempt(PERSON.email, 'guess'));
    expect(statuses).toEqual(real);
  });
});

describe('timing (REQ-026)', () => {
  it('an account that does not exist answers in about the time one that does', async () => {
    const sample = async (email: string): Promise<number> => {
      await h.service.db.throttleCounter.deleteMany();
      const browser = new Browser(h.opFetch);
      const { uid, csrf } = await signInScreen(browser);
      await browser.api(uid, '/identify', { csrf, email });
      const started = performance.now();
      await browser.api(uid, '/password', { csrf, password: 'definitely not it' });
      return performance.now() - started;
    };
    const median = (values: number[]): number => {
      const sorted = [...values].sort((a, b) => a - b);
      return sorted[Math.floor(sorted.length / 2)] ?? 0;
    };

    // Warm both paths first, then interleave so drift hits both equally.
    await sample(PERSON.email);
    await sample('warmup-nobody@example.com');
    const known: number[] = [];
    const unknown: number[] = [];
    for (let round = 0; round < 15; round += 1) {
      known.push(await sample(PERSON.email));
      unknown.push(await sample(`nobody-${String(round)}@example.com`));
    }

    const ratio = median(unknown) / median(known);
    expect(ratio).toBeGreaterThan(0.8);
    expect(ratio).toBeLessThan(1.2);
  });
});

describe('a password that is right, for an account that may not sign in', () => {
  it('a suspended account gets the same answer as a wrong password', async () => {
    await h.service.db.user.update({ where: { id: personId }, data: { status: 'suspended' } });
    try {
      const browser = new Browser(h.opFetch);
      const { uid, csrf } = await signInScreen(browser);
      await browser.api(uid, '/identify', { csrf, email: PERSON.email });
      const suspended = await browser.api(uid, '/password', { csrf, password: PERSON.password });

      await h.service.db.throttleCounter.deleteMany();
      const other = new Browser(h.opFetch);
      const again = await signInScreen(other);
      await other.api(again.uid, '/identify', { csrf: again.csrf, email: USER.email });
      const wrong = await other.api(again.uid, '/password', { csrf: again.csrf, password: 'not the password' });

      expect(suspended.status).toBe(wrong.status);
      expect(await suspended.json()).toEqual(await wrong.json());
    } finally {
      await h.service.db.user.update({ where: { id: personId }, data: { status: 'active' } });
    }
  });
});
