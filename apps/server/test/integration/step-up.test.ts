import { TOTP, Secret } from 'otpauth';
import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { STEP_UP_WINDOW_MS } from '../../src/console/auth.js';
import { authorize, Browser, ISSUER, startHarness, USER, webClientConfig, type Harness } from './oidc-harness.js';

// REQ-037: owner-only actions need proof that the person at the keyboard is still the owner.
//
// The threat is a session left open on a desk. Everything behind this guard changes what the
// whole system trusts — which apps exist, which keys sign — so signing in an hour ago is not
// good enough, and neither is a password alone for somebody who holds a factor.

let h: Harness;
let config: client.Configuration;
let ownerId: string;

type Call = (path: string, body?: unknown) => Promise<Response>;

async function consoleSession(): Promise<{ call: Call; sessionUid: string }> {
  const { browser } = await authorize(h, config, {}, new Browser(h.opFetch));
  const cookie = [...browser.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  const row = await h.service.db.session.findFirstOrThrow({ where: { userId: ownerId }, orderBy: { createdAt: 'desc' } });
  return {
    sessionUid: row.oidcSessionUid ?? '',
    call: (path, body) =>
      h.opFetch(`${ISSUER}${path}`, {
        method: body === undefined ? 'GET' : 'POST',
        headers: {
          cookie,
          accept: 'application/json',
          'sec-fetch-site': 'same-origin',
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      }),
  };
}

/** Moves this session's sign-in far enough into the past that the window has closed. */
async function goStale(sessionUid: string): Promise<void> {
  const long = new Date(Date.now() - STEP_UP_WINDOW_MS - 60_000);
  await h.service.db.session.updateMany({ where: { oidcSessionUid: sessionUid }, data: { steppedUpAt: long } });
  const stored = await h.service.provider.Session.findByUid(sessionUid);
  if (stored) {
    stored.loginTs = Math.floor(long.getTime() / 1000);
    await stored.save(60 * 60);
  }
}

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  ownerId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
  await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
});

afterAll(async () => {
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  await h.service.db.totpCredential.deleteMany({ where: { userId: ownerId } });
});

describe('owner-only actions', () => {
  it('go through for a few minutes after signing in', async () => {
    const { call } = await consoleSession();
    // Reading is not guarded; changing is.
    expect((await call('/api/admin/keys')).status).toBe(200);
    expect((await call('/api/admin/keys/generate', { alg: 'ES256' })).status).toBe(201);
    await h.service.db.signingKey.deleteMany({ where: { status: 'next' } });
  });

  it('are refused once the window has passed, with a reason a screen can act on', async () => {
    const { call, sessionUid } = await consoleSession();
    await goStale(sessionUid);

    const answer = await call('/api/admin/keys/generate', { alg: 'ES256' });
    expect(answer.status).toBe(401);
    expect(await answer.json()).toMatchObject({ error: 'step_up_required' });

    // Reading still works: the guard is about changing things, not about hiding them.
    expect((await call('/api/admin/keys')).status).toBe(200);
  });

  it('apply to registering and changing apps too', async () => {
    const { call, sessionUid } = await consoleSession();
    await goStale(sessionUid);
    const manifest = {
      client_id: `stale-${Date.now()}`,
      name: 'Stale',
      client_type: 'confidential_web',
      redirect_uris: ['https://stale.d3auth.test/cb'],
    };
    expect((await call('/api/admin/apps', { manifest })).status).toBe(401);
    // Previewing changes nothing, so it is not guarded.
    expect((await call('/api/admin/apps/preview', { manifest })).status).toBe(200);
  });
});

describe('proving it is you again', () => {
  it('takes the password, and then the action goes through', async () => {
    const { call, sessionUid } = await consoleSession();
    await goStale(sessionUid);

    expect((await call('/api/account/step-up', { password: 'not the password' })).status).toBe(401);
    const proved = await call('/api/account/step-up', { password: USER.password });
    expect(proved.status).toBe(200);
    expect(await proved.json()).toMatchObject({ ok: true, until: expect.any(String) as string });

    expect((await call('/api/admin/keys/generate', { alg: 'ES256' })).status).toBe(201);
    await h.service.db.signingKey.deleteMany({ where: { status: 'next' } });
  });

  it('is not satisfied by a password alone when they hold a factor', async () => {
    // Signed in first: enrolling before this would put the factor step in the way of the
    // sign-in itself, which is a different test.
    const { call, sessionUid } = await consoleSession();
    const enrolment = await h.service.totp.begin({ userId: ownerId, accountName: USER.email });
    const app = new TOTP({ secret: Secret.fromBase32(enrolment.manualKey) });
    await h.service.totp.confirm({ userId: ownerId, credentialId: enrolment.credentialId, code: app.generate() });
    await goStale(sessionUid);

    const passwordOnly = await call('/api/account/step-up', { password: USER.password });
    expect(passwordOnly.status).toBe(401);
    expect(await passwordOnly.json()).toMatchObject({ error: 'factor_required' });

    // A code from the app they enrolled finishes it.
    const used = await h.service.db.totpCredential.findFirstOrThrow({ where: { userId: ownerId } });
    const step = 30 * 1000;
    let at = Date.now();
    while (BigInt(Math.floor(at / step)) <= (used.lastUsedStep ?? -1n)) at += step;
    const withFactor = await call('/api/account/step-up', { password: USER.password, code: app.generate({ timestamp: at }) });
    expect(withFactor.status).toBe(200);
  });

  it('is audited', async () => {
    const { call, sessionUid } = await consoleSession();
    await goStale(sessionUid);
    await call('/api/account/step-up', { password: USER.password });

    const event = await h.service.db.auditEvent.findFirstOrThrow({ where: { event: 'auth.step_up' }, orderBy: { id: 'desc' } });
    expect(event.actorUserId).toBe(ownerId);
  });
});
