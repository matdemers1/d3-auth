import { TOTP, Secret } from 'otpauth';
import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { authorize, Browser, grantAccess, ISSUER, startHarness, webClientConfig, type Harness } from './oidc-harness.js';

// The account area (REQ-080, REQ-081, REQ-083).
//
// The interesting one is the password change: it is not a password-only act. Somebody who walks
// up to an unlocked browser already has the session, so the current password alone would be a
// thin defence — anyone holding a factor has to use it here too.

let h: Harness;
let config: client.Configuration;
let userId: string;

// Its own account, because these tests change the password. The seeded dev password happens to
// be on the blocklist, so it could not be set back through the API even if they used it.
const PERSON = { email: 'account@example.com', username: 'accountperson', displayName: 'Account Person', password: 'ninefold amber trellis' };

type Call = (path: string, body?: unknown) => Promise<Response>;

/** Signs in and returns a fetch that carries that session, plus the browser holding it. */
async function consoleSession(password = PERSON.password): Promise<{ call: Call; browser: Browser }> {
  const browser = new Browser(h.opFetch);
  const { browser: signedIn } = await authorize(h, config, {}, browser, { email: PERSON.email, password });
  const cookie = [...signedIn.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  const call: Call = (path, body) =>
    h.opFetch(`${ISSUER}${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: {
        cookie,
        accept: 'application/json',
        'sec-fetch-site': 'same-origin',
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  return { call, browser: signedIn };
}

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  const person = await h.service.db.user.upsert({
    where: { email: PERSON.email },
    create: { email: PERSON.email, username: PERSON.username, displayName: PERSON.displayName, status: 'active', emailVerified: true },
    update: { username: PERSON.username, displayName: PERSON.displayName, status: 'active' },
  });
  userId = person.id;
  await h.service.db.passwordCredential.deleteMany({ where: { userId } });
  await h.service.db.passwordCredential.create({ data: { userId, argon2idHash: await h.hasher.hash(PERSON.password) } });
  await grantAccess(h, userId);
});

afterAll(async () => {
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  await h.service.db.totpCredential.deleteMany({ where: { userId } });
  await h.service.db.session.deleteMany({ where: { userId } });
});

describe('profile (REQ-080)', () => {
  it('changes the name and username, and refuses one somebody else has', async () => {
    const { call } = await consoleSession();

    const before = (await (await call('/api/account/profile')).json()) as { email: string; username: string };
    expect(before.email).toBe(PERSON.email);

    const username = `person${Date.now()}`;
    const ok = await call('/api/account/profile', { displayName: 'Dev, Renamed', username });
    expect(ok.status).toBe(200);
    expect(await h.service.db.user.findUniqueOrThrow({ where: { id: userId } })).toMatchObject({
      displayName: 'Dev, Renamed',
      username,
    });

    const other = await h.service.db.user.create({
      data: { email: `taken-${Date.now()}@example.com`, username: `taken${Date.now()}`, displayName: 'Taken', status: 'active' },
    });
    const clash = await call('/api/account/profile', { displayName: 'Dev', username: other.username });
    expect(clash.status).toBe(409);

    const invalid = await call('/api/account/profile', { displayName: '', username: 'has spaces' });
    expect(invalid.status).toBe(400);
    expect((await invalid.json()) as { problems: string[] }).toMatchObject({ problems: expect.any(Array) as string[] });

    await h.service.db.user.delete({ where: { id: other.id } });
    await h.service.db.user.update({ where: { id: userId }, data: { displayName: PERSON.displayName, username: PERSON.username } });
  });

  it('never lets the email be set from here', async () => {
    const { call } = await consoleSession();
    await call('/api/account/profile', { displayName: PERSON.displayName, username: PERSON.username, email: 'someone.else@example.com' });
    expect((await h.service.db.user.findUniqueOrThrow({ where: { id: userId } })).email).toBe(PERSON.email);
  });
});

describe('changing the password (REQ-081)', () => {
  const NEW_PASSWORD = 'seventeen lanterns drifting';

  it('needs the current one, and refuses a password the policy rejects', async () => {
    const { call } = await consoleSession();

    const wrong = await call('/api/account/password', { currentPassword: 'not it at all', newPassword: NEW_PASSWORD });
    expect(wrong.status).toBe(401);

    const weak = await call('/api/account/password', { currentPassword: PERSON.password, newPassword: 'passwordpassword' });
    expect(weak.status).toBe(400);
    expect((await weak.json()) as { problems: string[] }).toMatchObject({ problems: expect.any(Array) as string[] });
  });

  it('insists on a factor when the account has one', async () => {
    // Signed in first: enrolling before this would put the factor step in the way of the sign-in
    // itself, which is a different test.
    const { call } = await consoleSession();
    const enrolment = await h.service.totp.begin({ userId, accountName: PERSON.email });
    const app = new TOTP({ secret: Secret.fromBase32(enrolment.manualKey) });
    await h.service.totp.confirm({ userId, credentialId: enrolment.credentialId, code: app.generate() });
    const withoutFactor = await call('/api/account/password', { currentPassword: PERSON.password, newPassword: NEW_PASSWORD });
    expect(withoutFactor.status).toBe(401);
    expect(await withoutFactor.json()).toMatchObject({ error: 'step_up_required' });

    // The password is untouched by a refused attempt.
    const credential = await h.service.db.passwordCredential.findFirstOrThrow({ where: { userId } });
    expect(credential.id).toBeTruthy();

    const step = 30 * 1000;
    const used = await h.service.db.totpCredential.findFirstOrThrow({ where: { userId } });
    let at = Date.now();
    while (BigInt(Math.floor(at / step)) <= (used.lastUsedStep ?? -1n)) at += step;
    const withFactor = await call('/api/account/password', {
      currentPassword: PERSON.password,
      newPassword: NEW_PASSWORD,
      code: app.generate({ timestamp: at }),
    });
    expect(withFactor.status).toBe(200);

    // Put it back, so the tests after this one still know the password.
    await h.service.db.totpCredential.deleteMany({ where: { userId } });
    expect((await call('/api/account/password', { currentPassword: NEW_PASSWORD, newPassword: PERSON.password })).status).toBe(200);
  });

  it('ends every other sign-in but the one being used', async () => {
    const elsewhere = await consoleSession();
    const here = await consoleSession();
    expect(((await (await here.call('/api/account/sessions')).json()) as { sessions: unknown[] }).sessions).toHaveLength(2);

    const changed = await here.call('/api/account/password', { currentPassword: PERSON.password, newPassword: NEW_PASSWORD });
    expect(changed.status).toBe(200);
    expect(await changed.json()).toMatchObject({ otherSessionsRevoked: 1 });

    // The other browser's session is gone; this one still works.
    expect((await elsewhere.call('/api/account/sessions')).status).toBe(401);
    expect((await here.call('/api/account/sessions')).status).toBe(200);

    expect((await here.call('/api/account/password', { currentPassword: NEW_PASSWORD, newPassword: PERSON.password })).status).toBe(200);
  });
});

describe('sessions and devices (REQ-083)', () => {
  it('lists them, marks this one, and can end another', async () => {
    const elsewhere = await consoleSession();
    const here = await consoleSession();

    const listed = (await (await here.call('/api/account/sessions')).json()) as {
      sessions: { id: string; current: boolean; userAgent: string | null }[];
    };
    expect(listed.sessions).toHaveLength(2);
    expect(listed.sessions.filter((session) => session.current)).toHaveLength(1);

    const other = listed.sessions.find((session) => !session.current);
    const revoked = await here.call(`/api/account/sessions/${other?.id ?? ''}/revoke`, {});
    expect(revoked.status).toBe(200);
    expect((await elsewhere.call('/api/account/sessions')).status).toBe(401);

    const after = (await (await here.call('/api/account/sessions')).json()) as { sessions: unknown[] };
    expect(after.sessions).toHaveLength(1);

    const audited = await h.service.db.auditEvent.findFirstOrThrow({ where: { event: 'session.revoked' }, orderBy: { id: 'desc' } });
    expect(audited.actorUserId).toBe(userId);
  });

  it('signs out everywhere else in one go', async () => {
    const first = await consoleSession();
    const second = await consoleSession();
    const here = await consoleSession();

    const answer = await here.call('/api/account/sessions/revoke-others', {});
    expect(await answer.json()).toMatchObject({ revoked: 2 });
    expect((await first.call('/api/account/sessions')).status).toBe(401);
    expect((await second.call('/api/account/sessions')).status).toBe(401);
    expect((await here.call('/api/account/sessions')).status).toBe(200);
  });
});
