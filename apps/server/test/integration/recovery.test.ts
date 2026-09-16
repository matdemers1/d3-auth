import * as client from 'openid-client';
import { TOTP, Secret } from 'otpauth';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { authorize, Browser, ISSUER, startHarness, webClientConfig, type Harness } from './oidc-harness.js';

// Break-glass (REQ-122).
//
// The scenario is a real one: the only admin has lost the phone holding their only factor. They
// still know their password; nothing can answer the second step. A shell on the host mints a
// link, and opening it clears the factors and opens a short password-only window.

let h: Harness;
let config: client.Configuration;

const OWNER = { email: 'breakglass@example.com', username: 'breakglass', displayName: 'Break Glass', password: 'lattice cobalt sundial' };
let ownerId: string;

/** Signs in and returns the id token's claims, or the step it got stuck on. */
async function signIn(): Promise<{ amr?: string[] | undefined; stuckAt?: string }> {
  const browser = new Browser(h.opFetch);
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: 'https://rp.d3auth.test/cb',
    scope: 'openid email profile',
    code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
    code_challenge_method: 'S256',
    state: client.randomState(),
    nonce: client.randomNonce(),
  });
  const started = await browser.navigate(url.toString());
  const attempt = await browser.login(started.response, { email: OWNER.email, password: OWNER.password });
  if (!attempt.leftTo) return { stuckAt: String(attempt.body.step) };

  const session = await h.service.db.session.findFirstOrThrow({ where: { userId: ownerId }, orderBy: { createdAt: 'desc' } });
  expect(session.userId).toBe(ownerId);
  const event = await h.service.db.auditEvent.findFirstOrThrow({ where: { event: 'login.success', actorUserId: ownerId }, orderBy: { id: 'desc' } });
  return { amr: (event.detail as { amr?: string[] }).amr };
}

async function giveThemAFactor(): Promise<void> {
  const enrolment = await h.service.totp.begin({ userId: ownerId, accountName: OWNER.email });
  const app = new TOTP({ secret: Secret.fromBase32(enrolment.manualKey) });
  await h.service.totp.confirm({ userId: ownerId, credentialId: enrolment.credentialId, code: app.generate() });
}

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  const owner = await h.service.db.user.upsert({
    where: { email: OWNER.email },
    create: { email: OWNER.email, username: OWNER.username, displayName: OWNER.displayName, kind: 'owner', status: 'active' },
    update: { kind: 'owner', status: 'active' },
  });
  ownerId = owner.id;
  await h.service.db.passwordCredential.deleteMany({ where: { userId: ownerId } });
  await h.service.db.passwordCredential.create({ data: { userId: ownerId, argon2idHash: await h.hasher.hash(OWNER.password) } });
});

afterAll(async () => {
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  await h.service.db.totpCredential.deleteMany({ where: { userId: ownerId } });
  await h.service.db.session.deleteMany({ where: { userId: ownerId } });
});

describe('the recovery link', () => {
  it('opens a password-only window and clears the factor that could not be used', async () => {
    await giveThemAFactor();
    // Without recovery they get as far as the factor step and no further.
    expect(await signIn()).toMatchObject({ stuckAt: 'factor' });

    const minted = await h.service.recovery.mint({ email: OWNER.email, minutes: 15 });
    expect(minted.url).toContain(`${ISSUER}/login/recover/`);

    // The link is a URL a person opens in a browser, so open it as one.
    const opened = await h.opFetch(minted.url, { headers: { accept: 'text/html' } });
    expect(opened.status).toBe(200);
    expect(await opened.text()).toContain('Recovery is ready');
    expect(await h.service.db.totpCredential.count({ where: { userId: ownerId } })).toBe(0);

    // Now the password alone signs in, and says so in `amr`.
    expect(await signIn()).toMatchObject({ amr: ['pwd', 'recovery'] });
  });

  it('works exactly once', async () => {
    const minted = await h.service.recovery.mint({ email: OWNER.email });
    expect((await h.opFetch(minted.url, { headers: { accept: 'text/html' } })).status).toBe(200);

    const again = await h.opFetch(minted.url, { headers: { accept: 'text/html' } });
    expect(again.status).toBe(410);
    expect(await again.text()).toContain('expired');
  });

  it('closes the window as soon as it has been used', async () => {
    const minted = await h.service.recovery.mint({ email: OWNER.email });
    await h.opFetch(minted.url, { headers: { accept: 'text/html' } });
    expect(await h.service.recovery.armed(ownerId)).toBe(true);

    expect(await signIn()).toMatchObject({ amr: ['pwd', 'recovery'] });
    expect(await h.service.recovery.armed(ownerId)).toBe(false);

    // A second sign-in is an ordinary one again.
    expect(await signIn()).toMatchObject({ amr: ['pwd'] });
  });

  it('ends the sessions and trusted devices the lost device might still hold', async () => {
    const { browser } = await authorize(h, config, {}, new Browser(h.opFetch), { email: OWNER.email, password: OWNER.password });
    expect(browser.cookies.size).toBeGreaterThan(0);
    await h.service.trustedDevices.issue({ userId: ownerId });
    expect(await h.service.db.session.count({ where: { userId: ownerId, revokedAt: null } })).toBe(1);

    const minted = await h.service.recovery.mint({ email: OWNER.email });
    await h.opFetch(minted.url, { headers: { accept: 'text/html' } });

    expect(await h.service.db.session.count({ where: { userId: ownerId, revokedAt: null } })).toBe(0);
    expect(await h.service.db.trustedDevice.count({ where: { userId: ownerId, revokedAt: null } })).toBe(0);
  });

  it('refuses an unknown account and an unknown token', async () => {
    await expect(h.service.recovery.mint({ email: 'nobody@example.com' })).rejects.toThrow(/No account/);
    expect((await h.opFetch(`${ISSUER}/login/recover/not-a-real-token`, { headers: { accept: 'text/html' } })).status).toBe(410);
  });

  it('is audited at every step, without the token', async () => {
    const minted = await h.service.recovery.mint({ email: OWNER.email });
    await h.opFetch(minted.url, { headers: { accept: 'text/html' } });
    await signIn();

    const events = await h.service.db.auditEvent.findMany({
      where: { event: { in: ['recovery.minted', 'recovery.claimed', 'recovery.used'] }, targetId: ownerId },
      orderBy: { id: 'desc' },
      take: 3,
    });
    expect(events.map((event) => event.event).sort()).toEqual(['recovery.claimed', 'recovery.minted', 'recovery.used']);
    const token = minted.url.split('/').pop() ?? '';
    expect(JSON.stringify(events.map((event) => event.detail))).not.toContain(token);
  });
});
