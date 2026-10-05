import { randomUUID } from 'node:crypto';
import * as client from 'openid-client';
import { Secret, TOTP } from 'otpauth';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DELETION_GRACE_MS, purgeDeletedAccounts } from '../../src/account/deletion.js';
import { buildFromPreset, findPreset } from '../../src/admin/presets/index.js';
import { createAuditWriter } from '../../src/audit/writer.js';
import { createLogger } from '../../src/log.js';
import { Browser, discover, grantAccess, ISSUER, markVisited, startHarness, USER, type Harness } from './oidc-harness.js';

/**
 * Deleting your account from D3 Constellation (AUTH-T-10.3, AUTH-ADR-009): the app's own-audience
 * token, the host name typed out and a current code; the last owner refused; every session and
 * grant ended at once; the row deleted once the grace period has passed, on a test clock; an admin's
 * reactivation cancelling it. The conformance suite cannot reach this — D3 Auth has no native
 * sign-in for it to start from (AUTH-ADR-008) — so these tests are the proof.
 */

const CONSTELLATION = { clientId: 'd3-constellation', redirect: 'd3constellation://oauth/d3auth' };
const PROBLEM = 'https://d3cloud.io/problems/';
const HOST = new URL(ISSUER).hostname;

let h: Harness;
const quiet = createLogger({ level: 'silent', destination: { write: () => undefined } });
let ownerId = '';

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
const problemType = async (res: Response) => ((await res.json()) as { type: string }).type;

/** A person signed in the way the app does it, holding the token for D3 Auth's own audience. */
async function person(kind: 'owner' | 'admin' | 'guest' = 'guest'): Promise<{ id: string; token: string; code: (offsetMs?: number) => string }> {
  const db = h.service.db;
  const email = `leaver-${randomUUID()}@example.com`;
  const password = 'a password for the deletion tests';
  const user = await db.user.create({
    data: { email, username: `leaver-${randomUUID().slice(0, 8)}`, displayName: 'Leaver', kind, status: 'active', passwordCredentials: { create: { argon2idHash: await h.hasher.hash(password) } } },
  });
  await grantAccess(h, user.id, CONSTELLATION.clientId);
  await markVisited(h, user.id, CONSTELLATION.clientId);
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
  if (!step.leftTo) step = await browser.login(step.response, { email, password });
  if (!step.leftTo) throw new Error('no callback');
  const tokens = await client.authorizationCodeGrant(config, step.leftTo, { pkceCodeVerifier: verifier, expectedState: 'st' }, { resource: ISSUER });
  // The authenticator comes after signing in, so the sign-in itself stays a password one.
  const enrolment = await h.service.totp.begin({ userId: user.id, accountName: email });
  const authenticator = new TOTP({ secret: Secret.fromBase32(enrolment.manualKey) });
  expect(await h.service.totp.confirm({ userId: user.id, credentialId: enrolment.credentialId, code: authenticator.generate() })).toBe(true);
  return { id: user.id, token: tokens.access_token, code: (offsetMs = 30_000) => authenticator.generate({ timestamp: Date.now() + offsetMs }) };
}

beforeAll(async () => {
  h = await startHarness();
  const db = h.service.db;
  ownerId = (await db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
  await db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
  if (!(await db.app.findUnique({ where: { clientId: CONSTELLATION.clientId } }))) {
    const preset = findPreset('constellation');
    const built = preset ? buildFromPreset(preset, {}) : null;
    if (!built?.ok) throw new Error('the constellation preset did not build');
    await h.service.apps.register({ manifest: built.manifest, actorUserId: ownerId, preset: { key: 'constellation', inputs: {} } });
  }
});

afterAll(async () => {
  await h.close();
});

describe('deleting your account from the app (AUTH-T-10.3)', () => {
  it('the manifest names the endpoint, and inviteAccept stays null', async () => {
    const manifest = (await (await call('/.well-known/d3-app.json')).json()) as { endpoints: Record<string, string | null> };
    expect(manifest.endpoints['deleteAccount']).toBe(`${ISSUER}/api/account/delete`);
    expect(manifest.endpoints['inviteAccept']).toBeNull();
  });

  it('refuses a wrong code, a mismatched confirmation and anybody without the app’s token', async () => {
    const who = await person();
    const right = who.code();
    const wrong = await call('/api/account/delete', { token: who.token, body: { confirmation: HOST, totp: String((Number(right) + 3) % 1_000_000).padStart(6, '0') } });
    expect(wrong.status).toBe(401);
    expect(await problemType(wrong)).toBe(`${PROBLEM}invalid_code`);
    const mismatch = await call('/api/account/delete', { token: who.token, body: { confirmation: 'example.com', totp: right } });
    expect(mismatch.status).toBe(422);
    expect(((await mismatch.json()) as { detail: string }).detail).toContain(HOST);
    expect((await call('/api/account/delete', { body: { confirmation: HOST, totp: right } })).status).toBe(401);
    expect((await h.service.db.user.findUniqueOrThrow({ where: { id: who.id } })).status).toBe('active');
  });

  it('refuses the last owner, and lets an owner go once there is another', async () => {
    const db = h.service.db;
    // Every other owner out of the way for a moment, so "the last" is this one; restored after.
    const others = await db.user.findMany({ where: { kind: 'owner', status: 'active' }, select: { id: true } });
    await db.user.updateMany({ where: { id: { in: others.map((o) => o.id) } }, data: { status: 'suspended' } });
    try {
      const owner = await person('owner');
      const last = await call('/api/account/delete', { token: owner.token, body: { confirmation: HOST, totp: owner.code() } });
      expect(last.status).toBe(409);
      expect(await problemType(last)).toBe(`${PROBLEM}last_owner`);
      const second = await person('owner');
      expect((await call('/api/account/delete', { token: second.token, body: { confirmation: HOST, totp: second.code() } })).status).toBe(202);
    } finally {
      await db.user.updateMany({ where: { id: { in: others.map((o) => o.id) } }, data: { status: 'active' } });
    }
  });

  it('suspends at once, ends every session and grant, and deletes the person after the grace period', async () => {
    const db = h.service.db;
    const who = await person();
    expect(await db.oidcPayload.count({ where: { kind: 'Grant', payload: { path: ['accountId'], equals: who.id } } })).toBeGreaterThan(0);
    const res = await call('/api/account/delete', { token: who.token, body: { confirmation: HOST.toUpperCase(), totp: who.code() } });
    expect(res.status).toBe(202);
    const { graceUntil } = (await res.json()) as { graceUntil: string };
    expect(Date.parse(graceUntil)).toBeGreaterThanOrEqual(Date.now() + 24 * 3_600_000 - 60_000);

    expect((await db.user.findUniqueOrThrow({ where: { id: who.id } })).status).toBe('suspended');
    expect(await db.oidcPayload.count({ where: { kind: 'Grant', payload: { path: ['accountId'], equals: who.id } } })).toBe(0);
    expect(await db.session.count({ where: { userId: who.id, revokedAt: null } })).toBe(0);
    expect((await call('/api/me', { token: who.token })).status).toBe(401);

    const audit = createAuditWriter(db, quiet);
    await purgeDeletedAccounts({ db, audit }, new Date(Date.now() + DELETION_GRACE_MS - 60_000));
    expect(await db.user.count({ where: { id: who.id } })).toBe(1);
    await purgeDeletedAccounts({ db, audit }, new Date(Date.now() + DELETION_GRACE_MS + 60_000));
    expect(await db.user.count({ where: { id: who.id } })).toBe(0);
    expect(await db.grant.count({ where: { userId: who.id } })).toBe(0);
    expect(await db.auditEvent.count({ where: { targetId: who.id, event: 'person.purged' } })).toBe(1);
    expect(await db.auditEvent.count({ where: { targetId: who.id, event: 'person.deletion_requested' } })).toBe(1);
  });

  it('is cancelled when an admin reactivates the account inside the grace period', async () => {
    const db = h.service.db;
    const who = await person();
    expect((await call('/api/account/delete', { token: who.token, body: { confirmation: HOST, totp: who.code() } })).status).toBe(202);
    // What the console's Reactivate writes.
    await db.user.update({ where: { id: who.id }, data: { status: 'active', deleteAfter: null } });
    await purgeDeletedAccounts({ db, audit: createAuditWriter(db, quiet) }, new Date(Date.now() + DELETION_GRACE_MS + 60_000));
    expect(await db.user.findUniqueOrThrow({ where: { id: who.id } })).toMatchObject({ status: 'active', deleteAfter: null });
  });
});
