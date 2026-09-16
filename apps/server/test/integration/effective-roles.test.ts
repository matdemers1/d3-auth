import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { effectiveAccess } from '../../src/authz/effective-roles.js';
import { startHarness, USER, WEB_CLIENT, type Harness } from './oidc-harness.js';

// REQ-050: effective roles are the **union** of direct grants and group grants.
//
// The four cases the plan asks for — direct only, group only, both overlapping, both disjoint —
// plus the ones that decide whether somebody can sign in at all. Union, never intersection, and
// never "the group wins": somebody given admin directly and member through a group has both.

let h: Harness;
let userId: string;
let appId: string;
let roleIds: Map<string, string>;

const access = () => effectiveAccess(h.service.db, { userId, clientId: WEB_CLIENT.clientId });

/** Gives the fixture user a direct grant with these roles. */
async function directGrant(...roles: string[]): Promise<void> {
  const grant = await h.service.db.grant.upsert({
    where: { userId_appId: { userId, appId } },
    create: { userId, appId },
    update: {},
  });
  await h.service.db.grantRole.deleteMany({ where: { grantId: grant.id } });
  await h.service.db.grantRole.createMany({ data: roles.map((key) => ({ grantId: grant.id, roleId: roleIds.get(key) ?? '' })) });
}

/** Puts them in a group that has these roles. */
async function groupGrant(name: string, ...roles: string[]): Promise<void> {
  const group = await h.service.db.group.upsert({ where: { name }, create: { name }, update: {} });
  await h.service.db.groupMember.upsert({
    where: { groupId_userId: { groupId: group.id, userId } },
    create: { groupId: group.id, userId },
    update: {},
  });
  const grant = await h.service.db.groupGrant.upsert({
    where: { groupId_appId: { groupId: group.id, appId } },
    create: { groupId: group.id, appId },
    update: {},
  });
  await h.service.db.groupGrantRole.deleteMany({ where: { groupGrantId: grant.id } });
  await h.service.db.groupGrantRole.createMany({ data: roles.map((key) => ({ groupGrantId: grant.id, roleId: roleIds.get(key) ?? '' })) });
}

beforeAll(async () => {
  h = await startHarness();
  userId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
  const app = await h.service.db.app.findUniqueOrThrow({ where: { clientId: WEB_CLIENT.clientId }, include: { roles: true } });
  appId = app.id;
  // A third role, so "disjoint" has something to be disjoint with.
  await h.service.db.role.upsert({
    where: { appId_key: { appId, key: 'guest' } },
    create: { appId, key: 'guest', displayName: 'Guest', sortOrder: 0 },
    update: {},
  });
  const roles = await h.service.db.role.findMany({ where: { appId } });
  roleIds = new Map(roles.map((role) => [role.key, role.id]));
});

afterAll(async () => {
  await h.close();
});

beforeEach(async () => {
  await h.service.db.grant.deleteMany({ where: { userId } });
  await h.service.db.groupMember.deleteMany({ where: { userId } });
  await h.service.db.group.deleteMany({});
});

describe('the four cases', () => {
  it('direct only', async () => {
    await directGrant('member');
    expect(await access()).toMatchObject({ hasGrant: true, roles: ['member'], from: { direct: true, groups: [] } });
  });

  it('group only — and the group is what lets them in at all', async () => {
    await groupGrant('Editors', 'member');
    expect(await access()).toMatchObject({ hasGrant: true, roles: ['member'], from: { direct: false, groups: ['Editors'] } });
  });

  it('both, overlapping — the same role twice is still one role', async () => {
    await directGrant('member');
    await groupGrant('Editors', 'member');
    const answer = await access();
    expect(answer.roles).toEqual(['member']);
    expect(answer.from).toEqual({ direct: true, groups: ['Editors'] });
  });

  it('both, disjoint — they get all of it, highest first', async () => {
    await directGrant('guest');
    await groupGrant('Editors', 'admin');
    const answer = await access();
    // `admin` sorts above `guest` by the app's own manifest order, not alphabetically.
    expect(answer.roles).toEqual(['admin', 'guest']);
  });
});

describe('what the union does not do', () => {
  it('gives nobody access without a grant of either kind (REQ-051)', async () => {
    expect(await access()).toMatchObject({ hasGrant: false, roles: [] });
  });

  it('ignores a group they are not in', async () => {
    const group = await h.service.db.group.create({ data: { name: 'Somebody Else' } });
    const grant = await h.service.db.groupGrant.create({ data: { groupId: group.id, appId } });
    await h.service.db.groupGrantRole.create({ data: { groupGrantId: grant.id, roleId: roleIds.get('admin') ?? '' } });
    expect(await access()).toMatchObject({ hasGrant: false });
  });

  it('takes the access away when they leave the group', async () => {
    await groupGrant('Editors', 'admin');
    expect(await access()).toMatchObject({ hasGrant: true });

    await h.service.db.groupMember.deleteMany({ where: { userId } });
    expect(await access()).toMatchObject({ hasGrant: false, roles: [] });
  });

  it('refuses a disabled app however many grants point at it', async () => {
    await directGrant('admin');
    await groupGrant('Editors', 'member');
    await h.service.db.app.update({ where: { id: appId }, data: { enabled: false } });
    try {
      expect(await access()).toMatchObject({ hasGrant: false, roles: [] });
    } finally {
      await h.service.db.app.update({ where: { id: appId }, data: { enabled: true } });
    }
  });

  it('keeps a grant with no roles, because the app decides what that means', async () => {
    await directGrant();
    expect(await access()).toMatchObject({ hasGrant: true, roles: [] });
  });
});
