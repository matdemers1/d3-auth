import { randomBytes } from 'node:crypto';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { createInvites, type Invites } from '../../src/admin/invites.js';
import { createAuditWriter } from '../../src/audit/writer.js';
import { effectiveAccess } from '../../src/authz/effective-roles.js';
import { createLogger } from '../../src/log.js';
import { createMailAdapter } from '../../src/mail/adapter.js';
import { createSecretHasher } from '../../src/security/hash.js';
import { testDb, unique } from './helpers.js';

// AUTH-T-9.8: an invite carries the groups and app grants the admin chose, and accepting it creates
// the person already holding them — in one transaction, with an audit event for each.

const db = testDb();
const hasher = createSecretHasher(randomBytes(32));
const logger = createLogger({ level: 'silent', destination: { write: () => undefined } });
let invites: Invites;
let admin: { id: string };

const tokenFrom = (url: string): string => url.split('/').pop() ?? '';
const PASSWORD = 'a long and uncommon passphrase for invites';

beforeEach(async () => {
  invites = createInvites({
    db,
    mail: createMailAdapter({ name: 'test', send: () => Promise.resolve() }, logger),
    hasher,
    audit: createAuditWriter(db, logger),
    template: { operatorDisplayName: 'Matthew', issuer: 'https://op.d3auth.test' },
  });
  admin = await db.user.create({
    data: { email: `admin-${unique()}@example.com`, username: `admin${unique()}`, displayName: 'Admin', kind: 'owner', status: 'active' },
  });
});

afterAll(async () => {
  await db.$disconnect();
});

async function appWithRoles(clientId: string) {
  return db.app.create({
    data: {
      clientId,
      name: clientId,
      clientType: 'confidential_web',
      redirectUris: { create: [{ uri: `https://${clientId}.d3auth.test/cb` }] },
      roles: { create: [{ key: 'admin', displayName: 'Admin', sortOrder: 2 }, { key: 'member', displayName: 'Member', sortOrder: 1, isDefault: true }] },
    },
  });
}

describe('an invite with initial access (AUTH-T-9.8)', () => {
  it('creates the person already in the groups and holding the grants, each audited', async () => {
    const clientId = `app-${unique()}`;
    await appWithRoles(clientId);
    const group = await db.group.create({ data: { name: `family-${unique()}` } });
    const email = `kim-${unique()}@example.com`;
    const created = await invites.create({ email, invitedByUserId: admin.id, initialAccess: { groupIds: [group.id], grants: [{ clientId, roles: ['member'] }] } });

    const accepted = await invites.accept({ token: tokenFrom(created.url), username: `kim${unique()}`, displayName: 'Kim', password: PASSWORD });
    expect(accepted.ok).toBe(true);
    if (!accepted.ok) return;

    expect(await db.groupMember.findUnique({ where: { groupId_userId: { groupId: group.id, userId: accepted.userId } } })).not.toBeNull();
    const access = await effectiveAccess(db, { userId: accepted.userId, clientId });
    expect(access).toMatchObject({ hasGrant: true, roles: ['member'] });
    const events = await db.auditEvent.findMany({ where: { detail: { path: ['userId'], equals: accepted.userId } } });
    expect(events.map((e) => e.event).sort()).toEqual(['grant.created', 'group.members_changed']);
    expect(events.every((e) => e.actorUserId === admin.id)).toBe(true);
  });

  it('skips a group or app removed since the invite was sent, and still creates the person', async () => {
    const clientId = `gone-${unique()}`;
    const app = await appWithRoles(clientId);
    const group = await db.group.create({ data: { name: `gone-${unique()}` } });
    const created = await invites.create({
      email: `lee-${unique()}@example.com`,
      invitedByUserId: admin.id,
      initialAccess: { groupIds: [group.id], grants: [{ clientId, roles: ['admin'] }] },
    });
    await db.group.delete({ where: { id: group.id } });
    await db.app.delete({ where: { id: app.id } });
    const accepted = await invites.accept({ token: tokenFrom(created.url), username: `lee${unique()}`, displayName: 'Lee', password: PASSWORD });
    expect(accepted.ok).toBe(true);
  });

  it('an invite from before AUTH-T-9.8 (an empty list) still accepts with no access', async () => {
    const created = await invites.create({ email: `old-${unique()}@example.com`, invitedByUserId: admin.id });
    const accepted = await invites.accept({ token: tokenFrom(created.url), username: `old${unique()}`, displayName: 'Old', password: PASSWORD });
    expect(accepted.ok).toBe(true);
    if (!accepted.ok) return;
    expect(await db.grant.count({ where: { userId: accepted.userId } })).toBe(0);
  });
});
