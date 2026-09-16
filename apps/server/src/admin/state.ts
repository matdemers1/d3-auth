import { z } from 'zod';
import { AUDIT_EVENTS } from '../audit/events.js';
import type { AuditWriter } from '../audit/writer.js';
import type { Db } from '../db.js';

// Exporting and importing the administrative state (REQ-072).
//
// What this is: the shape of an instance — which apps exist, what roles they declare, who is in
// which group, who may reach what. Enough to stand the same configuration up somewhere else, or
// to put it back after the database is gone.
//
// What this deliberately is **not**: a backup. It carries no password hashes, no passkeys, no
// TOTP secrets, no signing keys, no client secrets, no session or token state. A file full of
// credentials is a different object with different handling, and the backup bundle (P6) is where
// that belongs.
//
// The consequence, stated plainly because it will surprise somebody: after an import, people
// exist but cannot sign in until they are re-enrolled, and every confidential app is **secret
// pending** until its secret is rotated (R-11). The console shows both.

export const STATE_VERSION = 1;

const roleSchema = z.object({
  key: z.string().min(1),
  display: z.string().min(1),
  description: z.string().default(''),
  default: z.boolean().default(false),
});

const appSchema = z.object({
  client_id: z.string().min(1),
  name: z.string().min(1),
  description: z.string().default(''),
  client_type: z.enum(['confidential_web', 'public_native']),
  redirect_uris: z.array(z.string()).default([]),
  post_logout_redirect_uris: z.array(z.string()).default([]),
  backchannel_logout_uri: z.string().optional(),
  roles_claim_name: z.string().default('roles'),
  enabled: z.boolean().default(true),
  roles: z.array(roleSchema).default([]),
});

const personSchema = z.object({
  email: z.email(),
  username: z.string().min(1),
  display_name: z.string().min(1),
  kind: z.enum(['owner', 'admin', 'guest']),
  status: z.enum(['invited', 'active', 'suspended']),
  /** Per app: the roles this person holds directly. */
  grants: z.array(z.object({ client_id: z.string(), roles: z.array(z.string()).default([]) })).default([]),
});

const groupSchema = z.object({
  name: z.string().min(1),
  description: z.string().default(''),
  /** Emails, because ids do not survive a move between instances. */
  members: z.array(z.email()).default([]),
  grants: z.array(z.object({ client_id: z.string(), roles: z.array(z.string()).default([]) })).default([]),
});

export const stateSchema = z.object({
  version: z.literal(STATE_VERSION),
  exported_at: z.string().optional(),
  apps: z.array(appSchema).default([]),
  people: z.array(personSchema).default([]),
  groups: z.array(groupSchema).default([]),
  /** Settings without their secrets, which stay behind by design. */
  settings: z.record(z.string(), z.unknown()).default({}),
});

export type AdminState = z.output<typeof stateSchema>;

export interface ImportPlan {
  apps: { create: string[]; update: string[]; unchanged: string[] };
  people: { create: string[]; update: string[]; unchanged: string[] };
  groups: { create: string[]; update: string[]; unchanged: string[] };
  /** Confidential apps that will arrive without a secret and cannot be signed in to (R-11). */
  secretPending: string[];
  /** People who will exist but cannot sign in until they are re-enrolled. */
  needsReEnrolment: string[];
  /** Anything the file asks for that cannot be done, with the reason. */
  problems: string[];
}

/** Everything an operator would need to rebuild this instance's shape elsewhere. */
export async function exportState(db: Db): Promise<AdminState> {
  const [apps, people, groups, settings] = await Promise.all([
    db.app.findMany({ include: { redirectUris: true, roles: { orderBy: { sortOrder: 'desc' } } }, orderBy: { clientId: 'asc' } }),
    db.user.findMany({
      orderBy: { email: 'asc' },
      include: { grants: { include: { app: { select: { clientId: true } }, roles: { include: { role: true } } } } },
    }),
    db.group.findMany({
      orderBy: { name: 'asc' },
      include: {
        members: { include: { user: { select: { email: true } } } },
        grants: { include: { app: { select: { clientId: true } }, roles: { include: { role: true } } } },
      },
    }),
    db.setting.findMany(),
  ]);

  return {
    version: STATE_VERSION,
    exported_at: new Date().toISOString(),
    apps: apps.map((app) => ({
      client_id: app.clientId,
      name: app.name,
      description: app.description,
      client_type: app.clientType,
      redirect_uris: app.redirectUris.map((row) => row.uri),
      post_logout_redirect_uris: app.postLogoutRedirectUris,
      ...(app.backchannelLogoutUri ? { backchannel_logout_uri: app.backchannelLogoutUri } : {}),
      roles_claim_name: app.rolesClaimName,
      enabled: app.enabled,
      roles: app.roles.map((role) => ({
        key: role.key,
        display: role.displayName,
        description: role.description,
        default: role.isDefault,
      })),
    })),
    people: people.map((person) => ({
      email: person.email,
      username: person.username,
      display_name: person.displayName,
      kind: person.kind,
      status: person.status,
      grants: person.grants.map((grant) => ({
        client_id: grant.app.clientId,
        roles: grant.roles.map((entry) => entry.role.key),
      })),
    })),
    groups: groups.map((group) => ({
      name: group.name,
      description: group.description,
      members: group.members.map((member) => member.user.email),
      grants: group.grants.map((grant) => ({
        client_id: grant.app.clientId,
        roles: grant.roles.map((entry) => entry.role.key),
      })),
    })),
    // Values only. The sealed halves are not in here and cannot be.
    settings: Object.fromEntries(settings.map((row) => [row.key, row.value])),
  };
}

/** What importing this file would do, without doing any of it. */
export async function planImport(db: Db, state: AdminState): Promise<ImportPlan> {
  const [existingApps, existingPeople, existingGroups] = await Promise.all([
    db.app.findMany({ select: { clientId: true, clientSecretHash: true } }),
    db.user.findMany({ select: { email: true, id: true } }),
    db.group.findMany({ select: { name: true } }),
  ]);

  const appIds = new Set(existingApps.map((app) => app.clientId));
  const emails = new Set(existingPeople.map((person) => person.email));
  const groupNames = new Set(existingGroups.map((group) => group.name));
  const knownEmails = new Set([...emails, ...state.people.map((person) => person.email)]);

  const problems: string[] = [];
  const declaredApps = new Set(state.apps.map((app) => app.client_id));
  const allApps = new Set([...declaredApps, ...appIds]);

  for (const person of state.people) {
    for (const grant of person.grants) {
      if (!allApps.has(grant.client_id)) problems.push(`${person.email} is granted "${grant.client_id}", which is not in this file.`);
    }
  }
  for (const group of state.groups) {
    for (const member of group.members) {
      if (!knownEmails.has(member)) problems.push(`Group "${group.name}" lists ${member}, who is not in this file.`);
    }
    for (const grant of group.grants) {
      if (!allApps.has(grant.client_id)) problems.push(`Group "${group.name}" is granted "${grant.client_id}", which is not in this file.`);
    }
  }

  // A passkey is a way in as much as a password is, so both count. Somebody already here with
  // either one is not "re-enrol me"; somebody the file invents has neither.
  const withCredentials = await db.user.findMany({
    where: {
      email: { in: state.people.map((person) => person.email) },
      OR: [{ passwordCredentials: { some: {} } }, { webauthnCredentials: { some: {} } }],
    },
    select: { email: true },
  });
  const canSignIn = new Set(withCredentials.map((row) => row.email));

  return {
    apps: {
      create: state.apps.filter((app) => !appIds.has(app.client_id)).map((app) => app.client_id),
      update: state.apps.filter((app) => appIds.has(app.client_id)).map((app) => app.client_id),
      unchanged: [],
    },
    people: {
      create: state.people.filter((person) => !emails.has(person.email)).map((person) => person.email),
      update: state.people.filter((person) => emails.has(person.email)).map((person) => person.email),
      unchanged: [],
    },
    groups: {
      create: state.groups.filter((group) => !groupNames.has(group.name)).map((group) => group.name),
      update: state.groups.filter((group) => groupNames.has(group.name)).map((group) => group.name),
      unchanged: [],
    },
    // A confidential app arriving without a secret cannot be signed in to until one is rotated.
    secretPending: state.apps
      .filter((app) => app.client_type === 'confidential_web')
      .filter((app) => !existingApps.find((existing) => existing.clientId === app.client_id)?.clientSecretHash)
      .map((app) => app.client_id),
    needsReEnrolment: state.people.filter((person) => !canSignIn.has(person.email)).map((person) => person.email),
    problems,
  };
}

export interface ImportResult extends ImportPlan {
  applied: boolean;
}

/**
 * Applies the file. Additive by design: it creates and updates what the file describes and
 * removes nothing, because an import is usually "bring this configuration in", not "make this
 * instance identical to that one". Deleting is something an operator does deliberately, in the
 * console, where they can see what they are deleting.
 */
export async function importState(
  db: Db,
  state: AdminState,
  options: { dryRun?: boolean; actorUserId?: string | undefined; audit?: AuditWriter },
): Promise<ImportResult> {
  const plan = await planImport(db, state);
  if (options.dryRun) return { ...plan, applied: false };

  for (const app of state.apps) {
    const data = {
      name: app.name,
      description: app.description,
      clientType: app.client_type,
      postLogoutRedirectUris: app.post_logout_redirect_uris,
      backchannelLogoutUri: app.backchannel_logout_uri ?? null,
      rolesClaimName: app.roles_claim_name,
      enabled: app.enabled,
    };
    const saved = await db.app.upsert({ where: { clientId: app.client_id }, create: { clientId: app.client_id, ...data }, update: data });

    await db.redirectUri.deleteMany({ where: { appId: saved.id, uri: { notIn: app.redirect_uris.length > 0 ? app.redirect_uris : [''] } } });
    for (const uri of app.redirect_uris) {
      await db.redirectUri.upsert({ where: { appId_uri: { appId: saved.id, uri } }, create: { appId: saved.id, uri }, update: {} });
    }
    for (const [index, role] of app.roles.entries()) {
      const roleData = {
        displayName: role.display,
        description: role.description,
        sortOrder: app.roles.length - index,
        isDefault: role.default,
      };
      await db.role.upsert({
        where: { appId_key: { appId: saved.id, key: role.key } },
        create: { appId: saved.id, key: role.key, ...roleData },
        update: roleData,
      });
    }
  }

  for (const person of state.people) {
    // Created without credentials: an imported person cannot sign in until they are re-enrolled.
    const saved = await db.user.upsert({
      where: { email: person.email },
      create: {
        email: person.email,
        username: person.username,
        displayName: person.display_name,
        kind: person.kind,
        status: person.status === 'active' ? 'invited' : person.status,
      },
      update: { username: person.username, displayName: person.display_name, kind: person.kind },
    });

    for (const grant of person.grants) {
      const app = await db.app.findUnique({ where: { clientId: grant.client_id }, include: { roles: true } });
      if (!app) continue;
      const saved_grant = await db.grant.upsert({
        where: { userId_appId: { userId: saved.id, appId: app.id } },
        create: { userId: saved.id, appId: app.id },
        update: {},
      });
      await db.grantRole.deleteMany({ where: { grantId: saved_grant.id } });
      await db.grantRole.createMany({
        data: app.roles.filter((role) => grant.roles.includes(role.key)).map((role) => ({ grantId: saved_grant.id, roleId: role.id })),
      });
    }
  }

  for (const group of state.groups) {
    const saved = await db.group.upsert({
      where: { name: group.name },
      create: { name: group.name, description: group.description },
      update: { description: group.description },
    });
    const members = await db.user.findMany({ where: { email: { in: group.members } }, select: { id: true } });
    await db.groupMember.deleteMany({ where: { groupId: saved.id } });
    await db.groupMember.createMany({ data: members.map((member) => ({ groupId: saved.id, userId: member.id })) });

    for (const grant of group.grants) {
      const app = await db.app.findUnique({ where: { clientId: grant.client_id }, include: { roles: true } });
      if (!app) continue;
      const savedGrant = await db.groupGrant.upsert({
        where: { groupId_appId: { groupId: saved.id, appId: app.id } },
        create: { groupId: saved.id, appId: app.id },
        update: {},
      });
      await db.groupGrantRole.deleteMany({ where: { groupGrantId: savedGrant.id } });
      await db.groupGrantRole.createMany({
        data: app.roles.filter((role) => grant.roles.includes(role.key)).map((role) => ({ groupGrantId: savedGrant.id, roleId: role.id })),
      });
    }
  }

  await options.audit?.write({
    event: AUDIT_EVENTS.stateImported,
    ...(options.actorUserId ? { actorUserId: options.actorUserId } : {}),
    targetType: 'app',
    detail: {
      apps: plan.apps.create.length + plan.apps.update.length,
      people: plan.people.create.length + plan.people.update.length,
      groups: plan.groups.create.length + plan.groups.update.length,
      secretPending: plan.secretPending,
    },
  });

  return { ...plan, applied: true };
}
