import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { effectiveAccess } from '../../src/authz/effective-roles.js';
import { authorize, Browser, ISSUER, RP_CALLBACK, startHarness, USER, WEB_CLIENT, webClientConfig, type Harness } from './oidc-harness.js';

// REQ-053, REQ-068: groups hand out access to several people at once — and never appear in a
// token. An app is told what somebody may do, which is its business; how the operator organises
// people is not.

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
    where: { email: 'grouped@example.com' },
    create: { email: 'grouped@example.com', username: 'grouped', displayName: 'Grouped Person', status: 'active' },
    update: { status: 'active' },
  });
  personId = person.id;
});

afterAll(async () => {
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  await h.service.db.group.deleteMany({});
  await h.service.db.grant.deleteMany({ where: { userId: personId } });
});

describe('a group', () => {
  it('gives its members access, and takes it away when it is deleted', async () => {
    const call = await consoleSession();
    const group = (await (await call('/api/admin/groups', { name: 'Editors', description: 'People who edit' })).json()) as { id: string };

    await call(`/api/admin/groups/${group.id}/members`, { userIds: [personId] });
    await call(`/api/admin/groups/${group.id}/access`, { clientId: WEB_CLIENT.clientId, roles: ['member'] });

    expect(await effectiveAccess(h.service.db, { userId: personId, clientId: WEB_CLIENT.clientId })).toMatchObject({
      hasGrant: true,
      roles: ['member'],
      from: { direct: false, groups: ['Editors'] },
    });

    expect((await call(`/api/admin/groups/${group.id}/remove`, {})).status).toBe(200);
    expect(await effectiveAccess(h.service.db, { userId: personId, clientId: WEB_CLIENT.clientId })).toMatchObject({ hasGrant: false });
  });

  it('refuses a role the app has never declared', async () => {
    const call = await consoleSession();
    const group = (await (await call('/api/admin/groups', { name: 'Editors' })).json()) as { id: string };
    const answer = await call(`/api/admin/groups/${group.id}/access`, { clientId: WEB_CLIENT.clientId, roles: ['wizard'] });
    expect(answer.status).toBe(400);
    expect(await answer.json()).toMatchObject({ error: 'unknown_roles', detail: ['wizard'] });
  });

  it('refuses a name that is already taken, and an empty one', async () => {
    const call = await consoleSession();
    expect((await call('/api/admin/groups', { name: 'Editors' })).status).toBe(200);
    expect((await call('/api/admin/groups', { name: 'Editors' })).status).toBe(409);
    expect((await call('/api/admin/groups', { name: '   ' })).status).toBe(400);
  });

  it('lists members and the apps it reaches', async () => {
    const call = await consoleSession();
    const group = (await (await call('/api/admin/groups', { name: 'Editors' })).json()) as { id: string };
    await call(`/api/admin/groups/${group.id}/members`, { userIds: [personId, ownerId] });
    await call(`/api/admin/groups/${group.id}/access`, { clientId: WEB_CLIENT.clientId, roles: ['member'] });

    const listed = (await (await call('/api/admin/groups')).json()) as { groups: { name: string; memberCount: number; appCount: number }[] };
    expect(listed.groups).toMatchObject([{ name: 'Editors', memberCount: 2, appCount: 1 }]);

    const detail = (await (await call(`/api/admin/groups/${group.id}`)).json()) as {
      members: { userId: string }[];
      grants: { clientId: string; roles: string[] }[];
    };
    expect(detail.members.map((member) => member.userId).sort()).toEqual([personId, ownerId].sort());
    expect(detail.grants).toMatchObject([{ clientId: WEB_CLIENT.clientId, roles: ['member'] }]);
  });

  it('is refused to a guest', async () => {
    await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'guest' } });
    try {
      const call = await consoleSession();
      expect((await call('/api/admin/groups')).status).toBe(403);
    } finally {
      await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
    }
  });
});

describe('what a token says about groups', () => {
  it('says nothing at all (REQ-053)', async () => {
    const call = await consoleSession();
    const group = (await (await call('/api/admin/groups', { name: 'Secret Society' })).json()) as { id: string };
    await call(`/api/admin/groups/${group.id}/members`, { userIds: [ownerId] });
    await call(`/api/admin/groups/${group.id}/access`, { clientId: WEB_CLIENT.clientId, roles: ['admin'] });

    // The owner's own direct grant is gone; the group is the only thing letting them in.
    await h.service.db.grant.deleteMany({ where: { userId: ownerId } });

    const code = await authorize(h, config, { redirect_uri: RP_CALLBACK, scope: 'openid email profile d3:roles' }, new Browser(h.opFetch));
    const tokens = await client.authorizationCodeGrant(config, code.callback, {
      pkceCodeVerifier: code.verifier,
      expectedState: code.state,
      expectedNonce: code.nonce,
    });

    // The role arrived — through the group — and the group itself did not.
    expect(tokens.claims()?.roles).toEqual(['admin']);
    const everything = JSON.stringify({
      id: tokens.claims(),
      info: await client.fetchUserInfo(config, tokens.access_token, ownerId),
    });
    expect(everything).not.toContain('Secret Society');
    expect(everything).not.toContain('groups');
  });
});
