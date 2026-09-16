import { AUDIT_EVENTS } from '../audit/events.js';
import type { AuditWriter } from '../audit/writer.js';
import type { Db } from '../db.js';

// Groups (REQ-053, REQ-068).
//
// A group is a way to give the same access to several people at once, and to take it away the
// same way. It is an administrative convenience, not an identity: a group **never appears in a
// token or in userinfo**, and nothing an app receives can tell it which groups somebody is in.
// That keeps the apps' view of a person to what they may do, which is the only part that is
// theirs to know.

export interface GroupMemberView {
  userId: string;
  displayName: string;
  email: string;
}

export interface GroupGrantView {
  clientId: string;
  name: string;
  roles: string[];
}

export interface GroupView {
  id: string;
  name: string;
  description: string;
  members: GroupMemberView[];
  grants: GroupGrantView[];
}

export class GroupError extends Error {
  constructor(
    readonly code: 'not_found' | 'name_taken' | 'no_such_app' | 'no_such_user' | 'unknown_roles' | 'invalid',
    message: string,
    readonly detail?: unknown,
  ) {
    super(message);
    this.name = 'GroupError';
  }
}

export interface Groups {
  list(): Promise<(Omit<GroupView, 'members' | 'grants'> & { memberCount: number; appCount: number })[]>;
  get(id: string): Promise<GroupView | undefined>;
  create(input: { name: string; description?: string; actorUserId: string; ip?: string | undefined }): Promise<GroupView>;
  rename(input: { id: string; name: string; description?: string; actorUserId: string; ip?: string | undefined }): Promise<GroupView>;
  remove(input: { id: string; actorUserId: string; ip?: string | undefined }): Promise<boolean>;
  setMembers(input: { id: string; userIds: string[]; actorUserId: string; ip?: string | undefined }): Promise<GroupView>;
  /** Gives the whole group these roles in this app; an empty list means access with no roles. */
  setGrant(input: { id: string; clientId: string; roles: string[]; actorUserId: string; ip?: string | undefined }): Promise<GroupView>;
  revokeGrant(input: { id: string; clientId: string; actorUserId: string; ip?: string | undefined }): Promise<boolean>;
  /** Everyone whose access changes when this group does, for back-channel logout (REQ-056). */
  membersOf(id: string): Promise<string[]>;
}

const NAME = /^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,63}$/u;

const WITH_VIEW = {
  members: { select: { user: { select: { id: true, displayName: true, email: true } } }, orderBy: { user: { displayName: 'asc' } } },
  grants: {
    select: {
      app: { select: { clientId: true, name: true } },
      roles: { select: { role: { select: { key: true, sortOrder: true } } } },
    },
  },
} as const;

type GroupRow = {
  id: string;
  name: string;
  description: string;
  members: { user: { id: string; displayName: string; email: string } }[];
  grants: { app: { clientId: string; name: string }; roles: { role: { key: string; sortOrder: number } }[] }[];
};

const viewOf = (group: GroupRow): GroupView => ({
  id: group.id,
  name: group.name,
  description: group.description,
  members: group.members.map(({ user }) => ({ userId: user.id, displayName: user.displayName, email: user.email })),
  grants: group.grants.map((grant) => ({
    clientId: grant.app.clientId,
    name: grant.app.name,
    roles: grant.roles
      .map((entry) => entry.role)
      .sort((a, b) => b.sortOrder - a.sortOrder)
      .map((role) => role.key),
  })),
});

export interface GroupsDeps {
  db: Db;
  audit: AuditWriter;
  /**
   * Called with everybody whose access just changed. Group membership and group grants change
   * what people may do in an app, so the apps hear about it the same way a direct grant does.
   */
  onAccessChanged?: (change: { userIds: string[]; clientIds: string[]; reason: string }) => Promise<void>;
}

export function createGroups({ db, audit, onAccessChanged }: GroupsDeps): Groups {
  const load = (id: string) => db.group.findUnique({ where: { id }, include: WITH_VIEW });

  const loadOrThrow = async (id: string): Promise<GroupRow> => {
    const group = await load(id);
    if (!group) throw new GroupError('not_found', 'That group no longer exists.');
    return group;
  };

  /** Everyone in the group, and every app it touches — the blast radius of a change. */
  const reach = async (id: string): Promise<{ userIds: string[]; clientIds: string[] }> => {
    const group = await load(id);
    return {
      userIds: (group?.members ?? []).map((member) => member.user.id),
      clientIds: (group?.grants ?? []).map((grant) => grant.app.clientId),
    };
  };

  const checkName = (name: string): string => {
    const trimmed = name.trim();
    if (!NAME.test(trimmed)) {
      throw new GroupError('invalid', 'Group names are 1–64 characters: letters, numbers, spaces, dot, dash or underscore.');
    }
    return trimmed;
  };

  return {
    async list() {
      const groups = await db.group.findMany({
        orderBy: { name: 'asc' },
        select: { id: true, name: true, description: true, _count: { select: { members: true, grants: true } } },
      });
      return groups.map((group) => ({
        id: group.id,
        name: group.name,
        description: group.description,
        memberCount: group._count.members,
        appCount: group._count.grants,
      }));
    },

    async get(id) {
      const group = await load(id);
      return group ? viewOf(group) : undefined;
    },

    async create({ name, description = '', actorUserId, ip }) {
      const wanted = checkName(name);
      if (await db.group.findUnique({ where: { name: wanted } })) {
        throw new GroupError('name_taken', `There is already a group called "${wanted}".`);
      }
      const created = await db.group.create({ data: { name: wanted, description } });
      await audit.write({
        event: AUDIT_EVENTS.groupCreated,
        actorUserId,
        targetType: 'group',
        targetId: created.id,
        ip,
        detail: { name: wanted },
      });
      return viewOf(await loadOrThrow(created.id));
    },

    async rename({ id, name, description, actorUserId, ip }) {
      const group = await loadOrThrow(id);
      const wanted = checkName(name);
      const clash = await db.group.findUnique({ where: { name: wanted } });
      if (clash && clash.id !== id) throw new GroupError('name_taken', `There is already a group called "${wanted}".`);

      await db.group.update({ where: { id }, data: { name: wanted, ...(description === undefined ? {} : { description }) } });
      await audit.write({
        event: AUDIT_EVENTS.groupUpdated,
        actorUserId,
        targetType: 'group',
        targetId: id,
        ip,
        detail: { from: group.name, to: wanted },
      });
      return viewOf(await loadOrThrow(id));
    },

    async remove({ id, actorUserId, ip }) {
      const group = await load(id);
      if (!group) return false;
      // Deleting a group takes its access with it, so the apps hear about it first.
      const affected = await reach(id);

      await db.group.delete({ where: { id } });
      await audit.write({
        event: AUDIT_EVENTS.groupRemoved,
        actorUserId,
        targetType: 'group',
        targetId: id,
        ip,
        detail: { name: group.name, members: affected.userIds.length },
      });
      await onAccessChanged?.({ ...affected, reason: 'group_removed' });
      return true;
    },

    async setMembers({ id, userIds, actorUserId, ip }) {
      const group = await loadOrThrow(id);
      const people = await db.user.findMany({ where: { id: { in: userIds } }, select: { id: true } });
      if (people.length !== new Set(userIds).size) throw new GroupError('no_such_user', 'One of those people does not have an account.');

      const before = group.members.map((member) => member.user.id);
      await db.$transaction(async (tx) => {
        await tx.groupMember.deleteMany({ where: { groupId: id } });
        await tx.groupMember.createMany({ data: people.map((person) => ({ groupId: id, userId: person.id })) });
      });

      await audit.write({
        event: AUDIT_EVENTS.groupMembersChanged,
        actorUserId,
        targetType: 'group',
        targetId: id,
        ip,
        detail: { added: userIds.filter((user) => !before.includes(user)).length, removed: before.filter((user) => !userIds.includes(user)).length },
      });
      // Everybody who was in it *or* is now: both sets had their access changed.
      await onAccessChanged?.({
        userIds: [...new Set([...before, ...userIds])],
        clientIds: group.grants.map((grant) => grant.app.clientId),
        reason: 'group_members_changed',
      });
      return viewOf(await loadOrThrow(id));
    },

    async setGrant({ id, clientId, roles, actorUserId, ip }) {
      await loadOrThrow(id);
      const app = await db.app.findUnique({ where: { clientId }, include: { roles: true } });
      if (!app) throw new GroupError('no_such_app', `No app is registered with the client id "${clientId}".`);

      const known = new Map(app.roles.map((role) => [role.key, role.id]));
      const unknown = roles.filter((key) => !known.has(key));
      if (unknown.length > 0) throw new GroupError('unknown_roles', `${app.name} has no role called "${unknown.join('", "')}".`, unknown);

      await db.$transaction(async (tx) => {
        const grant = await tx.groupGrant.upsert({
          where: { groupId_appId: { groupId: id, appId: app.id } },
          create: { groupId: id, appId: app.id },
          update: {},
        });
        await tx.groupGrantRole.deleteMany({ where: { groupGrantId: grant.id } });
        await tx.groupGrantRole.createMany({ data: roles.map((key) => ({ groupGrantId: grant.id, roleId: known.get(key) ?? '' })) });
      });

      await audit.write({
        event: AUDIT_EVENTS.groupGrantChanged,
        actorUserId,
        targetType: 'group',
        targetId: id,
        ip,
        detail: { clientId, roles },
      });
      const affected = await reach(id);
      await onAccessChanged?.({ userIds: affected.userIds, clientIds: [clientId], reason: 'group_grant_changed' });
      return viewOf(await loadOrThrow(id));
    },

    async revokeGrant({ id, clientId, actorUserId, ip }) {
      const app = await db.app.findUnique({ where: { clientId }, select: { id: true } });
      if (!app) throw new GroupError('no_such_app', `No app is registered with the client id "${clientId}".`);

      const affected = await reach(id);
      const { count } = await db.groupGrant.deleteMany({ where: { groupId: id, appId: app.id } });
      if (count === 0) return false;

      await audit.write({
        event: AUDIT_EVENTS.groupGrantRevoked,
        actorUserId,
        targetType: 'group',
        targetId: id,
        ip,
        detail: { clientId },
      });
      await onAccessChanged?.({ userIds: affected.userIds, clientIds: [clientId], reason: 'group_grant_revoked' });
      return true;
    },

    async membersOf(id) {
      const members = await db.groupMember.findMany({ where: { groupId: id }, select: { userId: true } });
      return members.map((member) => member.userId);
    },
  };
}
