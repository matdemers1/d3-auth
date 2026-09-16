import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { effectiveAccess } from '../../src/authz/effective-roles.js';
import { authorize, Browser, ISSUER, startHarness, USER, webClientConfig, type Harness } from './oidc-harness.js';

// REQ-049, REQ-047: a grant is one person, one app, and roles that app actually declares.

let h: Harness;
let config: client.Configuration;
let ownerId: string;
let personId: string;

type Call = (path: string, body?: unknown) => Promise<Response>;

async function consoleSession(): Promise<Call> {
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

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  ownerId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
  await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });

  const person = await h.service.db.user.upsert({
    where: { email: 'granted@example.com' },
    create: { email: 'granted@example.com', username: 'granted', displayName: 'Granted Person', status: 'active' },
    update: { status: 'active' },
  });
  personId = person.id;
});

afterAll(async () => {
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  await h.service.db.grant.deleteMany({ where: { userId: personId } });
});

describe('granting access', () => {
  it('gives one person one app with roles, and says who did it', async () => {
    const call = await consoleSession();
    const granted = await call(`/api/admin/people/${personId}/access`, { clientId: 'web-app', roles: ['member'] });
    expect(granted.status).toBe(200);
    expect(await granted.json()).toMatchObject({ userId: personId, roles: ['member'], grantedBy: 'Dev Person' });

    expect(await effectiveAccess(h.service.db, { userId: personId, clientId: 'web-app' })).toMatchObject({
      hasGrant: true,
      roles: ['member'],
      // Nobody has signed in to this app yet, which is what shows them the interstitial once.
      firstSignInAt: null,
    });

    const event = await h.service.db.auditEvent.findFirstOrThrow({ where: { event: 'grant.created' }, orderBy: { id: 'desc' } });
    expect(event).toMatchObject({ actorUserId: ownerId, targetId: personId });
  });

  it('refuses a role the app has never declared', async () => {
    const call = await consoleSession();
    const answer = await call(`/api/admin/people/${personId}/access`, { clientId: 'web-app', roles: ['member', 'wizard'] });
    expect(answer.status).toBe(400);
    expect(await answer.json()).toMatchObject({ error: 'unknown_roles', detail: ['wizard'] });
    // Nothing was written: a refused grant is not a half-made one.
    expect(await effectiveAccess(h.service.db, { userId: personId, clientId: 'web-app' })).toMatchObject({ hasGrant: false });
  });

  it('replaces the roles on a second grant rather than adding a second grant', async () => {
    const call = await consoleSession();
    await call(`/api/admin/people/${personId}/access`, { clientId: 'web-app', roles: ['member'] });
    const changed = await call(`/api/admin/people/${personId}/access`, { clientId: 'web-app', roles: ['admin'] });
    expect(await changed.json()).toMatchObject({ roles: ['admin'] });
    expect(await h.service.db.grant.count({ where: { userId: personId } })).toBe(1);

    const event = await h.service.db.auditEvent.findFirstOrThrow({ where: { event: 'grant.changed' }, orderBy: { id: 'desc' } });
    expect(JSON.stringify(event.detail)).toContain('admin');
  });

  it('keeps a grant with no roles, because the app decides what that means', async () => {
    const call = await consoleSession();
    await call(`/api/admin/people/${personId}/access`, { clientId: 'web-app', roles: [] });
    expect(await effectiveAccess(h.service.db, { userId: personId, clientId: 'web-app' })).toMatchObject({ hasGrant: true, roles: [] });
  });

  it('lists who has access to an app, and what one person can reach', async () => {
    const call = await consoleSession();
    await call(`/api/admin/people/${personId}/access`, { clientId: 'web-app', roles: ['member'] });

    const forApp = (await (await call('/api/admin/apps/web-app/access')).json()) as { access: { userId: string; roles: string[] }[] };
    expect(forApp.access.find((row) => row.userId === personId)).toMatchObject({ roles: ['member'] });

    const forUser = (await (await call(`/api/admin/people/${personId}/access`)).json()) as { access: { clientId: string }[] };
    expect(forUser.access.map((row) => row.clientId)).toEqual(['web-app']);
  });

  it('revokes, and says so once', async () => {
    const call = await consoleSession();
    await call(`/api/admin/people/${personId}/access`, { clientId: 'web-app', roles: ['member'] });

    expect((await call(`/api/admin/people/${personId}/access/revoke`, { clientId: 'web-app' })).status).toBe(200);
    expect(await effectiveAccess(h.service.db, { userId: personId, clientId: 'web-app' })).toMatchObject({ hasGrant: false });
    expect((await call(`/api/admin/people/${personId}/access/revoke`, { clientId: 'web-app' })).status).toBe(404);
  });

  it('is refused to a guest', async () => {
    await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'guest' } });
    try {
      const call = await consoleSession();
      expect((await call(`/api/admin/people/${personId}/access`, { clientId: 'web-app', roles: [] })).status).toBe(403);
    } finally {
      await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
    }
  });
});
