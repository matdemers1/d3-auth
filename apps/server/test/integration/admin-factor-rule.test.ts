import { TOTP, Secret } from 'otpauth';
import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { authorize, Browser, ISSUER, startHarness, USER, webClientConfig, type Harness } from './oidc-harness.js';

// REQ-035: an account cannot be made an admin without a way to prove it is them.
//
// Checked here, at the moment the power is granted, rather than at sign-in — by sign-in it would
// already be an admin without a factor, which is the state the rule exists to prevent.

let h: Harness;
let config: client.Configuration;
let ownerId: string;

/** Signs in as the owner and returns a fetch that carries the console session. */
async function consoleSession(): Promise<(path: string, body?: unknown) => Promise<Response>> {
  const { browser } = await authorize(h, config, {}, new Browser(h.opFetch));
  const cookie = [...browser.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
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

async function personWithoutFactors(): Promise<string> {
  const person = await h.service.db.user.create({
    data: { email: `person-${Date.now()}@example.com`, username: `person${Date.now()}`, displayName: 'A Person', status: 'active' },
  });
  return person.id;
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

describe('making somebody an admin (REQ-035)', () => {
  it('is refused while they hold no verified factor', async () => {
    const call = await consoleSession();
    const targetId = await personWithoutFactors();

    const res = await call(`/api/admin/people/${targetId}/kind`, { kind: 'admin' });
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ error: 'factor_required' });
    expect((await h.service.db.user.findUniqueOrThrow({ where: { id: targetId } })).kind).toBe('guest');
  });

  it('goes through once they have one, and is audited', async () => {
    const call = await consoleSession();
    const targetId = await personWithoutFactors();

    const enrolment = await h.service.totp.begin({ userId: targetId, accountName: 'person@example.com' });
    const app = new TOTP({ secret: Secret.fromBase32(enrolment.manualKey) });
    // An *unconfirmed* enrolment proves nothing, so it must not be enough.
    expect((await call(`/api/admin/people/${targetId}/kind`, { kind: 'admin' })).status).toBe(409);

    await h.service.totp.confirm({ userId: targetId, credentialId: enrolment.credentialId, code: app.generate() });
    const res = await call(`/api/admin/people/${targetId}/kind`, { kind: 'admin' });
    expect(res.status).toBe(200);
    expect((await h.service.db.user.findUniqueOrThrow({ where: { id: targetId } })).kind).toBe('admin');

    const event = await h.service.db.auditEvent.findFirstOrThrow({ where: { event: 'person.kind_changed' }, orderBy: { id: 'desc' } });
    expect(event).toMatchObject({ actorUserId: ownerId, targetId });
  });

  it('is not something an admin can do to themselves', async () => {
    await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'admin' } });
    const call = await consoleSession();
    const targetId = await personWithoutFactors();
    // requireOwner: an admin promoting other admins is how one compromised admin becomes many.
    expect((await call(`/api/admin/people/${targetId}/kind`, { kind: 'admin' })).status).toBe(403);
  });

  it('leaves the owner alone', async () => {
    const call = await consoleSession();
    const res = await call(`/api/admin/people/${ownerId}/kind`, { kind: 'guest' });
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ error: 'owner_unchanged' });
  });
});

describe('removing the last factor (REQ-042)', () => {
  it('is refused for an admin and allowed for a guest', async () => {
    const call = await consoleSession();
    const enrolment = await h.service.totp.begin({ userId: ownerId, accountName: USER.email });
    const app = new TOTP({ secret: Secret.fromBase32(enrolment.manualKey) });
    await h.service.totp.confirm({ userId: ownerId, credentialId: enrolment.credentialId, code: app.generate() });

    const refused = await call(`/api/account/totp/${enrolment.credentialId}/remove`, {});
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ error: 'last_factor' });

    // The same account, without the admin powers, may remove it.
    await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'guest' } });
    const allowed = await call(`/api/account/totp/${enrolment.credentialId}/remove`, {});
    expect(allowed.status).toBe(200);
    expect(await h.service.db.totpCredential.count({ where: { userId: ownerId } })).toBe(0);
  });
});
