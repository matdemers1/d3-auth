import type * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { STEP_UP_WINDOW_MS } from '../../src/console/auth.js';
import { startHarness, USER, webClientConfig, type Harness } from '../integration/oidc-harness.js';
import { consoleCaller, type Call } from './support.js';

// Attack class: a session somebody left open (ASVS 5.0 7.5.1, 7.5.2; found by the gate, F-10).
//
// The person walked away from a signed-in browser minutes ago. Whoever sits down cannot see the
// password, but they have the session. The dangerous thing they could do is not read a page — it
// is plant something that outlasts the session: their own passkey or authenticator app, which
// keeps them in after a password change. Or remove the real person's factor, or sign every other
// device out so the real person cannot see what is happening.
//
// Each of those now needs proof from within the last five minutes, as owner-only console actions
// already did.

let h: Harness;
let config: client.Configuration;
let ownerId: string;

/** Signs in, then makes that sign-in older than the step-up window, like a browser left on a desk. */
async function leftOnADesk(): Promise<Call> {
  const call = await consoleCaller(h, config);
  const row = await h.service.db.session.findFirstOrThrow({ where: { userId: ownerId }, orderBy: { createdAt: 'desc' } });
  const long = new Date(Date.now() - STEP_UP_WINDOW_MS - 60_000);
  await h.service.db.session.update({ where: { id: row.id }, data: { steppedUpAt: long } });
  const stored = await h.service.provider.Session.findByUid(row.oidcSessionUid ?? '');
  if (stored) {
    stored.loginTs = Math.floor(long.getTime() / 1000);
    await stored.save(60 * 60);
  }
  return call;
}

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  ownerId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
});

afterAll(async () => {
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  await h.service.db.totpCredential.deleteMany({ where: { userId: ownerId } });
});

describe('a borrowed session', () => {
  it.each([
    ['start adding a passkey', '/api/account/passkeys/begin'],
    ['finish adding a passkey', '/api/account/passkeys/finish'],
    ['start adding an authenticator app', '/api/account/totp/begin'],
    ['confirm an authenticator app', '/api/account/totp/confirm'],
    ['sign every other device out', '/api/account/sessions/revoke-others'],
  ])('cannot %s', async (_label, path) => {
    const call = await leftOnADesk();
    const answer = await call(path, { body: {} });
    expect(answer.status).toBe(401);
    expect(await answer.json()).toMatchObject({ error: 'step_up_required' });
  });

  it('cannot remove the factor the real person relies on', async () => {
    const enrolment = await h.service.totp.begin({ userId: ownerId, accountName: USER.email });
    const call = await leftOnADesk();
    const answer = await call(`/api/account/totp/${enrolment.credentialId}/remove`, { body: {} });
    expect(answer.status).toBe(401);
    expect(await h.service.db.totpCredential.count({ where: { id: enrolment.credentialId } })).toBe(1);
  });

  it('can do all of it once the person proves it is still them', async () => {
    const call = await leftOnADesk();
    const proved = await call('/api/account/step-up', { body: { password: USER.password } });
    expect(proved.status).toBe(200);
    expect((await call('/api/account/totp/begin', { body: {} })).status).toBe(200);
  });

  it('can still read what it could read before — the guard is about changing things', async () => {
    const call = await leftOnADesk();
    expect((await call('/api/account/factors')).status).toBe(200);
    expect((await call('/api/account/sessions')).status).toBe(200);
  });
});
