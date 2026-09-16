import { AUDIT_EVENTS } from '../audit/events.js';
import type { AuditWriter } from '../audit/writer.js';
import type { Db } from '../db.js';

// Granting and revoking access (REQ-049, REQ-056).
//
// A grant is deliberate: somebody with the console gave this person access to this app with these
// roles, and the audit row says who. Changing or revoking one has to reach the app as well as the
// table — a revoked person whose app session keeps working is the thing this is supposed to stop
// — so every write here calls `onChanged`, which T-3.5 wires to back-channel logout.

export interface GrantView {
  userId: string;
  displayName: string;
  email: string;
  roles: string[];
  grantedAt: Date;
  grantedBy: string | null;
  lastSignIn: Date | null;
}

export interface AppAccess {
  clientId: string;
  name: string;
  roles: string[];
  grantedAt: Date;
}

export class GrantError extends Error {
  constructor(
    readonly code: 'no_such_app' | 'no_such_user' | 'unknown_roles',
    message: string,
    readonly detail?: unknown,
  ) {
    super(message);
    this.name = 'GrantError';
  }
}

export interface Grants {
  /** Everyone who can sign in to this app, for the Access tab (REQ-066). */
  forApp(clientId: string): Promise<GrantView[]>;
  /** Everything this person can sign in to, for their detail page and their launcher (REQ-079). */
  forUser(userId: string): Promise<AppAccess[]>;
  /** Creates or replaces the grant. An empty role list is allowed; no grant at all is not. */
  set(input: { userId: string; clientId: string; roles: string[]; actorUserId: string; ip?: string | undefined }): Promise<GrantView>;
  revoke(input: { userId: string; clientId: string; actorUserId: string; ip?: string | undefined }): Promise<boolean>;
}

export interface GrantsDeps {
  db: Db;
  audit: AuditWriter;
  /**
   * Called after any change to somebody's access, before the answer goes back. T-3.5 delivers a
   * back-channel logout here; until then the change is recorded and the app finds out on its next
   * token renewal.
   */
  onChanged?: (change: { userId: string; clientId: string; reason: 'granted' | 'changed' | 'revoked' }) => Promise<void>;
}

export function createGrants({ db, audit, onChanged }: GrantsDeps): Grants {
  const appOf = async (clientId: string) => {
    const app = await db.app.findUnique({ where: { clientId }, include: { roles: true } });
    if (!app) throw new GrantError('no_such_app', `No app is registered with the client id "${clientId}".`);
    return app;
  };

  const view = (
    row: {
      user: { id: string; displayName: string; email: string; lastLoginAt: Date | null };
      roles: { role: { key: string; sortOrder: number } }[];
      createdAt: Date;
      grantedBy: { displayName: string } | null;
    },
    /** Last sign-in *to this app*, which is a more useful answer than "signed in somewhere". */
    lastSignIn?: Date | null,
  ): GrantView => ({
    userId: row.user.id,
    displayName: row.user.displayName,
    email: row.user.email,
    roles: row.roles
      .map((entry) => entry.role)
      .sort((a, b) => b.sortOrder - a.sortOrder)
      .map((role) => role.key),
    grantedAt: row.createdAt,
    grantedBy: row.grantedBy?.displayName ?? null,
    lastSignIn: lastSignIn === undefined ? row.user.lastLoginAt : lastSignIn,
  });

  const WITH_VIEW = {
    user: { select: { id: true, displayName: true, email: true, lastLoginAt: true } },
    grantedBy: { select: { displayName: true } },
    roles: { select: { role: { select: { key: true, sortOrder: true } } } },
  } as const;

  return {
    async forApp(clientId) {
      const app = await appOf(clientId);
      const [grants, visits] = await Promise.all([
        db.grant.findMany({ where: { appId: app.id }, include: WITH_VIEW, orderBy: { createdAt: 'asc' } }),
        db.appVisit.findMany({ where: { appId: app.id }, select: { userId: true, lastSignInAt: true } }),
      ]);
      const seen = new Map(visits.map((visit) => [visit.userId, visit.lastSignInAt]));
      return grants.map((grant) => view(grant, seen.get(grant.userId) ?? null));
    },

    async forUser(userId) {
      const grants = await db.grant.findMany({
        where: { userId, app: { enabled: true } },
        include: { app: { select: { clientId: true, name: true } }, roles: { select: { role: { select: { key: true, sortOrder: true } } } } },
        orderBy: { app: { name: 'asc' } },
      });
      return grants.map((grant) => ({
        clientId: grant.app.clientId,
        name: grant.app.name,
        roles: grant.roles
          .map((entry) => entry.role)
          .sort((a, b) => b.sortOrder - a.sortOrder)
          .map((role) => role.key),
        grantedAt: grant.createdAt,
      }));
    },

    async set({ userId, clientId, roles, actorUserId, ip }) {
      const app = await appOf(clientId);
      const user = await db.user.findUnique({ where: { id: userId }, select: { id: true } });
      if (!user) throw new GrantError('no_such_user', 'That person does not have an account.');

      // Roles come from the app's manifest, so a role it has never declared is a mistake worth
      // refusing rather than silently dropping (REQ-047).
      const known = new Map(app.roles.map((role) => [role.key, role.id]));
      const unknown = roles.filter((key) => !known.has(key));
      if (unknown.length > 0) {
        throw new GrantError('unknown_roles', `${app.name} has no role called "${unknown.join('", "')}".`, unknown);
      }

      const existing = await db.grant.findUnique({ where: { userId_appId: { userId, appId: app.id } } });
      await db.$transaction(async (tx) => {
        const grant =
          existing ??
          (await tx.grant.create({ data: { userId, appId: app.id, grantedById: actorUserId } }));
        await tx.grantRole.deleteMany({ where: { grantId: grant.id } });
        await tx.grantRole.createMany({ data: roles.map((key) => ({ grantId: grant.id, roleId: known.get(key) ?? '' })) });
      });

      await audit.write({
        event: existing ? AUDIT_EVENTS.grantChanged : AUDIT_EVENTS.grantCreated,
        actorUserId,
        targetType: 'grant',
        targetId: userId,
        ip,
        detail: { clientId, roles },
      });
      await onChanged?.({ userId, clientId, reason: existing ? 'changed' : 'granted' });

      const saved = await db.grant.findUniqueOrThrow({ where: { userId_appId: { userId, appId: app.id } }, include: WITH_VIEW });
      return view(saved);
    },

    async revoke({ userId, clientId, actorUserId, ip }) {
      const app = await appOf(clientId);
      const { count } = await db.grant.deleteMany({ where: { userId, appId: app.id } });
      if (count === 0) return false;

      await audit.write({
        event: AUDIT_EVENTS.grantRevoked,
        actorUserId,
        targetType: 'grant',
        targetId: userId,
        ip,
        detail: { clientId },
      });
      await onChanged?.({ userId, clientId, reason: 'revoked' });
      return true;
    },
  };
}
