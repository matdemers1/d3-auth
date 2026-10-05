import { createHash, randomBytes } from 'node:crypto';
import { AUDIT_EVENTS } from '../audit/events.js';
import type { AuditWriter } from '../audit/writer.js';
import type { Db } from '../db.js';
import type { MailAdapter } from '../mail/adapter.js';
import { inviteMail, reEnrolMail, type TemplateContext } from '../mail/templates.js';
import type { Prisma } from '../generated/prisma/client.js';
import { checkPassword, USERNAME_PATTERN, USERNAME_RULE } from '../security/policy.js';
import type { SecretHasher } from '../security/hash.js';

// Invites (REQ-065, REQ-078, REQ-040, REQ-108). There is no public signup, so this is how anyone
// after the owner gets an account.
//
// Two rules shape the code. The token is only ever stored as a hash, and the raw value exists in
// one email and one API response — so an invite cannot be stolen from the database. And a mail
// failure never loses the invite: it is created first, the send is reported separately, and the
// console shows a link to copy when the send did not work.

export const INVITE_TTL_HOURS = 72;
export const REENROL_TTL_HOURS = 2;

const hashToken = (token: string): string => createHash('sha256').update(token).digest('hex');

/**
 * What a new person arrives with (AUTH-T-9.8): the groups they join and the apps they are given,
 * applied in the transaction that creates their account — never before it exists, and never to an
 * account an invite merely resets.
 */
export interface InitialAccess {
  groupIds: string[];
  grants: { clientId: string; roles: string[] }[];
}

export interface CreateInviteInput {
  email: string;
  /** Validated by the caller against the groups and apps that exist (the admin route does). */
  initialAccess?: InitialAccess;
  invitedByUserId: string;
  ip?: string | undefined;
  userAgent?: string | undefined;
}

export interface InviteCreated {
  id: string;
  email: string;
  url: string;
  expiresAt: Date;
  mail: { delivered: boolean; error?: string };
}

export type AcceptResult =
  | { ok: true; userId: string }
  | { ok: false; error: 'invalid_or_expired' | 'taken' | 'invalid'; problems?: string[] };

export interface Invites {
  create(input: CreateInviteInput): Promise<InviteCreated>;
  /** The re-enrol link an admin reset sends (REQ-039); same mechanism, shorter life. */
  createReEnrol(input: { userId: string; email: string; actorUserId: string }): Promise<InviteCreated>;
  describe(token: string): Promise<{ valid: boolean; email?: string }>;
  accept(input: { token: string; username: string; displayName: string; password: string; ip?: string | undefined; userAgent?: string | undefined }): Promise<AcceptResult>;
}

export interface InvitesDeps {
  db: Db;
  mail: MailAdapter;
  hasher: SecretHasher;
  audit: AuditWriter;
  template: TemplateContext;
}

export function createInvites({ db, mail, hasher, audit, template }: InvitesDeps): Invites {
  const inviteUrl = (token: string): string => `${template.issuer}/login/invite/${token}`;

  async function mint(input: {
    email: string;
    invitedById: string | null;
    hours: number;
    kind: 'invite' | 'reenrol';
    initialAccess?: InitialAccess;
  }): Promise<{ id: string; token: string; expiresAt: Date }> {
    const token = randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + input.hours * 60 * 60 * 1000);
    const invite = await db.invite.create({
      data: {
        email: input.email,
        invitedById: input.invitedById,
        tokenHash: hashToken(token),
        initialGrants: (input.initialAccess ?? []) as unknown as Prisma.InputJsonValue,
        expiresAt,
      },
    });
    return { id: invite.id, token, expiresAt };
  }

  return {
    async create(input) {
      const email = input.email.trim().toLowerCase();
      const existing = await db.user.findUnique({ where: { email } });
      if (existing) {
        // Not an error worth hiding from an admin: they are looking at their own list of people.
        throw Object.assign(new Error('That email already has an account.'), { code: 'already_a_user' });
      }

      const { id, token, expiresAt } = await mint({
        email,
        invitedById: input.invitedByUserId,
        hours: INVITE_TTL_HOURS,
        kind: 'invite',
        ...(input.initialAccess ? { initialAccess: input.initialAccess } : {}),
      });
      const url = inviteUrl(token);
      const rendered = inviteMail(template, { url, expiresInHours: INVITE_TTL_HOURS });
      const sent = await mail.send({ to: email, ...rendered });

      await audit.write({
        event: AUDIT_EVENTS.inviteCreated,
        actorUserId: input.invitedByUserId,
        targetType: 'user',
        ip: input.ip,
        userAgent: input.userAgent,
        detail: {
          email,
          delivered: sent.delivered,
          driver: sent.driver,
          ...(input.initialAccess ? { groupIds: input.initialAccess.groupIds, grants: input.initialAccess.grants } : {}),
        },
      });

      return { id, email, url, expiresAt, mail: { delivered: sent.delivered, ...(sent.error ? { error: sent.error } : {}) } };
    },

    async createReEnrol(input) {
      const email = input.email.trim().toLowerCase();
      const { id, token, expiresAt } = await mint({ email, invitedById: input.actorUserId, hours: REENROL_TTL_HOURS, kind: 'reenrol' });
      const url = inviteUrl(token);
      const rendered = reEnrolMail(template, { url, expiresInHours: REENROL_TTL_HOURS });
      const sent = await mail.send({ to: email, ...rendered });
      return { id, email, url, expiresAt, mail: { delivered: sent.delivered, ...(sent.error ? { error: sent.error } : {}) } };
    },

    async describe(token) {
      const invite = await db.invite.findUnique({ where: { tokenHash: hashToken(token) } });
      if (!invite || invite.acceptedAt || invite.expiresAt <= new Date()) return { valid: false };
      return { valid: true, email: invite.email };
    },

    async accept(input) {
      const tokenHash = hashToken(input.token);
      const invite = await db.invite.findUnique({ where: { tokenHash } });
      if (!invite || invite.acceptedAt || invite.expiresAt <= new Date()) return { ok: false, error: 'invalid_or_expired' };

      const username = input.username.trim();
      const displayName = input.displayName.trim();
      const problems: string[] = [];
      if (!USERNAME_PATTERN.test(username)) problems.push(USERNAME_RULE);
      if (displayName.length < 1) problems.push('Enter the name people will see.');
      problems.push(...checkPassword(input.password, { email: invite.email, username, displayName }).problems);
      if (problems.length > 0) return { ok: false, error: 'invalid', problems };

      const argon2idHash = await hasher.hash(input.password);

      try {
        const user = await db.$transaction(async (tx) => {
          const claimed = await tx.invite.updateMany({
            where: { id: invite.id, acceptedAt: null },
            data: { acceptedAt: new Date() },
          });
          // Two taps on the same link: only the first one gets to create the account.
          if (claimed.count === 0) throw Object.assign(new Error('already accepted'), { code: 'invalid_or_expired' });

          const existing = await tx.user.findUnique({ where: { email: invite.email } });
          if (existing) {
            // A reset: the account stays, with the same `sub`, and gets a fresh password.
            await tx.passwordCredential.deleteMany({ where: { userId: existing.id } });
            await tx.passwordCredential.create({ data: { userId: existing.id, argon2idHash } });
            return tx.user.update({
              where: { id: existing.id },
              data: { displayName, status: 'active', emailVerified: true },
            });
          }

          const created = await tx.user.create({
            data: { email: invite.email, username, displayName, kind: 'guest', status: 'active', emailVerified: true },
          });
          await tx.passwordCredential.create({ data: { userId: created.id, argon2idHash } });

          // The access the admin chose, in this same transaction (AUTH-T-9.8): the person exists with
          // it or not at all. A group or app removed since the invite was sent is simply skipped —
          // it no longer exists to be given — and a role removed since, likewise.
          const access = readInitialAccess(invite.initialGrants);
          const audited = (event: string, targetType: string, targetId: string, detail: Record<string, unknown>) =>
            tx.auditEvent.create({
              data: {
                event,
                actorUserId: invite.invitedById,
                targetType,
                targetId,
                ip: input.ip ?? null,
                userAgent: input.userAgent ?? null,
                detail: { ...detail, via: 'invite', userId: created.id },
              },
            });
          for (const groupId of access.groupIds) {
            const group = await tx.group.findUnique({ where: { id: groupId }, select: { id: true } });
            if (!group) continue;
            await tx.groupMember.create({ data: { groupId, userId: created.id } });
            await audited(AUDIT_EVENTS.groupMembersChanged, 'group', groupId, { added: [created.id] });
          }
          for (const wanted of access.grants) {
            const app = await tx.app.findUnique({ where: { clientId: wanted.clientId }, include: { roles: true } });
            if (!app) continue;
            const grant = await tx.grant.create({ data: { userId: created.id, appId: app.id, grantedById: invite.invitedById } });
            const roles = app.roles.filter((role) => wanted.roles.includes(role.key));
            if (roles.length > 0) await tx.grantRole.createMany({ data: roles.map((role) => ({ grantId: grant.id, roleId: role.id })) });
            await audited(AUDIT_EVENTS.grantCreated, 'app', app.id, { clientId: app.clientId, roles: roles.map((role) => role.key) });
          }
          return created;
        });

        await audit.write({
          event: AUDIT_EVENTS.inviteAccepted,
          actorUserId: user.id,
          targetType: 'user',
          targetId: user.id,
          ip: input.ip,
          userAgent: input.userAgent,
          // The mailbox was proven by opening the link, which is what email_verified means (REQ-040).
          detail: { email: user.email, username: user.username, emailVerified: true },
        });
        return { ok: true, userId: user.id };
      } catch (err) {
        const code = (err as { code?: string }).code;
        if (code === 'invalid_or_expired') return { ok: false, error: 'invalid_or_expired' };
        if (err instanceof Error && err.message.includes('Unique constraint')) return { ok: false, error: 'taken' };
        throw err;
      }
    },
  };
}

/** The invite's stored access, tolerating the empty list invites carried before AUTH-T-9.8. */
function readInitialAccess(raw: unknown): InitialAccess {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return { groupIds: [], grants: [] };
  const value = raw as { groupIds?: unknown; grants?: unknown };
  const groupIds = Array.isArray(value.groupIds) ? value.groupIds.filter((id): id is string => typeof id === 'string') : [];
  const grants = Array.isArray(value.grants)
    ? value.grants.flatMap((g: unknown) => {
        const grant = g as { clientId?: unknown; roles?: unknown };
        return typeof grant.clientId === 'string'
          ? [{ clientId: grant.clientId, roles: Array.isArray(grant.roles) ? grant.roles.filter((r): r is string => typeof r === 'string') : [] }]
          : [];
      })
    : [];
  return { groupIds, grants };
}
