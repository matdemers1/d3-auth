import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { authorize, Browser, ISSUER, startHarness, USER, webClientConfig, type Harness } from './oidc-harness.js';

// REQ-038 (states) and REQ-039 (admin reset).
//
// The rule both share: an account is only as suspended, or as reset, as its live sessions. A
// status column changed while the SSO cookie still worked would stop nothing.

let h: Harness;
let config: client.Configuration;
let ownerId: string;

type Call = (path: string, body?: unknown) => Promise<Response>;

const PERSON_PASSWORD = 'thimble orchard verdigris';

async function consoleSession(credentials?: { email: string; password: string }): Promise<Call> {
  const browser = new Browser(h.opFetch);
  const { browser: signedIn } = await authorize(h, config, {}, browser, credentials);
  const cookie = [...signedIn.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  return (path, body) =>
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
}

/** A guest who can actually sign in, so their sessions are real ones. */
async function aPerson(): Promise<{ id: string; email: string; password: string }> {
  const email = `person-${Date.now()}-${Math.random().toString(36).slice(2, 7)}@example.com`;
  const person = await h.service.db.user.create({
    data: { email, username: email.split('@')[0] ?? '', displayName: 'A Person', status: 'active', emailVerified: true },
  });
  await h.service.db.passwordCredential.create({
    data: { userId: person.id, argon2idHash: await h.hasher.hash(PERSON_PASSWORD) },
  });
  return { id: person.id, email, password: PERSON_PASSWORD };
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
  await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner', status: 'active' } });
});

describe('suspending somebody (REQ-038)', () => {
  it('ends their sessions and their trusted devices, not just their status', async () => {
    const person = await aPerson();
    const theirs = await consoleSession({ email: person.email, password: person.password });
    await h.service.trustedDevices.issue({ userId: person.id });
    expect((await theirs('/api/me')).status).toBe(200);

    const admin = await consoleSession();
    const suspended = await admin(`/api/admin/people/${person.id}/suspend`, {});
    expect(suspended.status).toBe(200);
    expect(await suspended.json()).toMatchObject({ status: 'suspended', sessionsEnded: 1 });

    // The session they were holding is gone, and so is the device that skipped their factor.
    expect((await theirs('/api/me')).status).toBe(401);
    expect(await h.service.db.trustedDevice.count({ where: { userId: person.id, revokedAt: null } })).toBe(0);

    // And they cannot sign in again: the answer is the same one a wrong password gets.
    const browser = new Browser(h.opFetch);
    const attempt = await authorize(h, config, {}, browser, { email: person.email, password: person.password }).catch(
      (err: unknown) => err,
    );
    expect(attempt).toBeInstanceOf(Error);
  });

  it('lets them back in', async () => {
    const person = await aPerson();
    const admin = await consoleSession();
    await admin(`/api/admin/people/${person.id}/suspend`, {});
    expect((await admin(`/api/admin/people/${person.id}/reactivate`, {})).status).toBe(200);

    const theirs = await consoleSession({ email: person.email, password: person.password });
    expect((await theirs('/api/me')).status).toBe(200);
  });

  it('refuses the owner and yourself', async () => {
    const admin = await consoleSession();
    expect((await admin(`/api/admin/people/${ownerId}/suspend`, {})).status).toBe(409);
  });
});

describe('resetting an account (REQ-039)', () => {
  it('clears every credential, ends every session, and mails a link that keeps the same account', async () => {
    const person = await aPerson();
    const enrolment = await h.service.totp.begin({ userId: person.id, accountName: person.email });
    expect(enrolment.credentialId).toBeTruthy();
    const theirs = await consoleSession({ email: person.email, password: person.password });
    await h.service.trustedDevices.issue({ userId: person.id });

    const admin = await consoleSession();
    const reset = await admin(`/api/admin/people/${person.id}/reset`, {});
    expect(reset.status).toBe(200);
    const body = (await reset.json()) as { url: string; sessionsEnded: number };
    expect(body.url).toContain('/login/invite/');
    expect(body.sessionsEnded).toBe(1);

    expect(await h.service.db.passwordCredential.count({ where: { userId: person.id } })).toBe(0);
    expect(await h.service.db.totpCredential.count({ where: { userId: person.id } })).toBe(0);
    expect(await h.service.db.webauthnCredential.count({ where: { userId: person.id } })).toBe(0);
    expect(await h.service.db.trustedDevice.count({ where: { userId: person.id, revokedAt: null } })).toBe(0);
    expect((await theirs('/api/me')).status).toBe(401);

    // The link sets them up again on the *same* account, so their sub and history survive.
    const token = body.url.split('/').pop() ?? '';
    const accepted = await h.service.invites.accept({
      token,
      username: `back${Date.now()}`,
      displayName: 'A Person, Again',
      password: 'marigold cornice thunder',
    });
    expect(accepted).toMatchObject({ ok: true, userId: person.id });

    const audited = await h.service.db.auditEvent.findFirstOrThrow({ where: { event: 'person.reset' }, orderBy: { id: 'desc' } });
    expect(audited).toMatchObject({ actorUserId: ownerId, targetId: person.id });
  });

  it('is not something an admin can do to the owner', async () => {
    const admin = await consoleSession();
    expect((await admin(`/api/admin/people/${ownerId}/reset`, {})).status).toBe(409);
  });

  it('is refused to a guest entirely', async () => {
    const person = await aPerson();
    const victim = await aPerson();
    const theirs = await consoleSession({ email: person.email, password: person.password });
    expect((await theirs(`/api/admin/people/${victim.id}/reset`, {})).status).toBe(403);
  });
});
