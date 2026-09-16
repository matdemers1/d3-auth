import express, { Router, type NextFunction, type Request, type RequestHandler, type Response } from 'express';
import { AUDIT_EVENTS } from '../audit/events.js';
import { clientIp, type AuditWriter } from '../audit/writer.js';
import { consoleUserOf, type ConsoleAuth } from '../console/auth.js';
import type { Db } from '../db.js';
import { mustHoldFactor, verifiedFactorCount } from '../security/factors.js';
import type { SessionControl } from '../security/sessions.js';
import type { TrustedDevices } from '../security/trusted-device.js';
import { GrantError, type Grants } from '../authz/grants.js';
import { AppError, type Apps } from './apps.js';
import type { Invites } from './invites.js';
import { parseManifest, type Manifest } from './manifest.js';

// The console's API for the people side of the house (C-1, C-3). Phase 3 adds apps, grants and
// groups here; this is the part Phase 2 needs to put a real person on the system.

export const ADMIN_API = '/api/admin';

export interface AdminDeps {
  db: Db;
  apps: Apps;
  grants: Grants;
  /** Used in copy the console shows to people, e.g. "Ask Matthew" (REQ-087). */
  operatorDisplayName: string;
  auth: ConsoleAuth;
  invites: Invites;
  sessions: SessionControl;
  trustedDevices: TrustedDevices;
  audit: AuditWriter;
}

export function adminRouter({ db, apps, grants, operatorDisplayName, auth, invites, sessions, trustedDevices, audit }: AdminDeps): Router {
  const router = Router();
  const asJson = express.json({ limit: '8kb' });
  const body: RequestHandler = (req, res, next) => {
    asJson(req, res, (err: unknown) => {
      if (err) next(err);
      else next();
    });
  };

  // Who am I, and what may I see? The console asks this before rendering anything.
  router.get('/api/me', (req, res, next) => {
    void (async () => {
      try {
        const found = await auth.current(req);
        if (!found) {
          res.status(401).json({ error: 'sign_in_required' });
          return;
        }
        const { user } = found;
        res.set('Cache-Control', 'no-store').json({
          id: user.id,
          email: user.email,
          username: user.username,
          displayName: user.displayName,
          kind: user.kind,
          status: user.status,
          operatorDisplayName,
        });
      } catch (err) {
        next(err);
      }
    })();
  });

  router.get(`${ADMIN_API}/people`, auth.requireAdmin, (_req, res, next) => {
    void (async () => {
      try {
        const [people, pending] = await Promise.all([
          db.user.findMany({
            orderBy: { createdAt: 'asc' },
            select: { id: true, email: true, username: true, displayName: true, kind: true, status: true, lastLoginAt: true, createdAt: true },
          }),
          db.invite.findMany({
            where: { acceptedAt: null, expiresAt: { gt: new Date() } },
            orderBy: { createdAt: 'desc' },
            select: { id: true, email: true, createdAt: true, expiresAt: true },
          }),
        ]);
        res.set('Cache-Control', 'no-store').json({ people, pendingInvites: pending });
      } catch (err) {
        next(err);
      }
    })();
  });

  // Making somebody an admin (REQ-035). The factor rule is enforced here, at grant time, because
  // this is the moment an account gains the power that makes a second factor non-negotiable —
  // checking it later, at sign-in, would already be too late.
  /** One person, everything an admin needs to decide about them (C-2, REQ-064). */
  router.get<{ id: string }>(`${ADMIN_API}/people/:id`, auth.requireAdmin, (req, res, next) => {
    void (async () => {
      try {
        const person = await db.user.findUnique({
          where: { id: req.params.id },
          select: {
            id: true,
            email: true,
            username: true,
            displayName: true,
            kind: true,
            status: true,
            emailVerified: true,
            lastLoginAt: true,
            createdAt: true,
            webauthnCredentials: { select: { label: true, createdAt: true, lastUsedAt: true } },
            totpCredentials: { where: { confirmedAt: { not: null } }, select: { label: true, confirmedAt: true } },
          },
        });
        if (!person) {
          res.status(404).json({ error: 'not_found' });
          return;
        }

        const [sessions, devices, access] = await Promise.all([
          db.session.findMany({
            where: { userId: person.id, revokedAt: null, expiresAt: { gt: new Date() } },
            orderBy: { lastSeenAt: 'desc' },
            select: { id: true, ip: true, userAgent: true, lastSeenAt: true },
          }),
          db.trustedDevice.count({ where: { userId: person.id, revokedAt: null, expiresAt: { gt: new Date() } } }),
          grants.forUser(person.id),
        ]);

        const { webauthnCredentials, totpCredentials, ...profile } = person;
        res.set('Cache-Control', 'no-store').json({
          ...profile,
          // Enough to answer "can this person prove it is them?" without exposing a credential.
          factors: {
            passkeys: webauthnCredentials.length,
            authenticatorApps: totpCredentials.length,
            trustedDevices: devices,
          },
          sessions,
          access,
        });
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post<{ id: string }>(`${ADMIN_API}/people/:id/kind`, auth.requireOwner, body, (req, res, next) => {
    void (async () => {
      try {
        const { user: actor } = consoleUserOf(res);
        const input = req.body as { kind?: unknown };
        const kind = input.kind;
        if (kind !== 'admin' && kind !== 'guest') {
          res.status(400).json({ error: 'invalid_kind', message: 'A person can be an admin or a guest.' });
          return;
        }
        const target = await db.user.findUnique({ where: { id: req.params.id }, select: { id: true, kind: true } });
        if (!target) {
          res.status(404).json({ error: 'not_found' });
          return;
        }
        if (target.kind === 'owner') {
          res.status(409).json({ error: 'owner_unchanged', message: 'The owner cannot be demoted here.' });
          return;
        }
        if (mustHoldFactor(kind) && (await verifiedFactorCount(db, target.id)) === 0) {
          res.status(409).json({
            error: 'factor_required',
            message: 'Ask them to add a passkey or an authenticator app first. Admins must be able to prove it is them.',
          });
          return;
        }

        await db.user.update({ where: { id: target.id }, data: { kind } });
        await audit.write({
          event: AUDIT_EVENTS.personKindChanged,
          actorUserId: actor.id,
          targetType: 'user',
          targetId: target.id,
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
          detail: { from: target.kind, to: kind },
        });
        res.json({ kind });
      } catch (err) {
        next(err);
      }
    })();
  });

  /** Common shape for the two actions that act on somebody else's account. */
  const target = async (
    id: string,
    res: Response,
  ): Promise<{ id: string; email: string; kind: string; status: string } | undefined> => {
    const { user: actor } = consoleUserOf(res);
    const found = await db.user.findUnique({ where: { id }, select: { id: true, email: true, kind: true, status: true } });
    if (!found) {
      res.status(404).json({ error: 'not_found' });
      return undefined;
    }
    if (found.id === actor.id) {
      res.status(409).json({ error: 'not_yourself', message: 'Somebody else has to do this to your account.' });
      return undefined;
    }
    if (found.kind === 'owner') {
      res.status(409).json({ error: 'owner_protected', message: 'The owner cannot be suspended or reset from here.' });
      return undefined;
    }
    return found;
  };

  // Suspending somebody (REQ-038). A suspension that left their sessions alive would only stop
  // the *next* sign-in, so the sessions go with it.
  router.post<{ id: string }>(`${ADMIN_API}/people/:id/suspend`, auth.requireAdmin, (req, res, next) => {
    void (async () => {
      try {
        const { user: actor } = consoleUserOf(res);
        const person = await target(req.params.id, res);
        if (!person) return;

        await db.user.update({ where: { id: person.id }, data: { status: 'suspended' } });
        const ended = await sessions.revokeAll(person.id);
        const devices = await trustedDevices.revokeAll(person.id);
        await audit.write({
          event: AUDIT_EVENTS.personSuspended,
          actorUserId: actor.id,
          targetType: 'user',
          targetId: person.id,
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
          detail: { sessionsEnded: ended, devicesForgotten: devices },
        });
        res.json({ status: 'suspended', sessionsEnded: ended });
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post<{ id: string }>(`${ADMIN_API}/people/:id/reactivate`, auth.requireAdmin, (req, res, next) => {
    void (async () => {
      try {
        const { user: actor } = consoleUserOf(res);
        const person = await target(req.params.id, res);
        if (!person) return;

        await db.user.update({ where: { id: person.id }, data: { status: 'active' } });
        await audit.write({
          event: AUDIT_EVENTS.personReactivated,
          actorUserId: actor.id,
          targetType: 'user',
          targetId: person.id,
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
        });
        res.json({ status: 'active' });
      } catch (err) {
        next(err);
      }
    })();
  });

  // Reset (REQ-039). Everything that could let the old holder back in goes at once, and the
  // account keeps its id — so its `sub`, its grants and its history survive the reset.
  router.post<{ id: string }>(`${ADMIN_API}/people/:id/reset`, auth.requireAdmin, (req, res, next) => {
    void (async () => {
      try {
        const { user: actor } = consoleUserOf(res);
        const person = await target(req.params.id, res);
        if (!person) return;

        await db.$transaction(async (tx) => {
          await tx.passwordCredential.deleteMany({ where: { userId: person.id } });
          await tx.webauthnCredential.deleteMany({ where: { userId: person.id } });
          await tx.totpCredential.deleteMany({ where: { userId: person.id } });
        });
        const ended = await sessions.revokeAll(person.id);
        const devices = await trustedDevices.revokeAll(person.id);

        const link = await invites.createReEnrol({ userId: person.id, email: person.email, actorUserId: actor.id });
        await audit.write({
          event: AUDIT_EVENTS.personReset,
          actorUserId: actor.id,
          targetType: 'user',
          targetId: person.id,
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
          detail: { sessionsEnded: ended, devicesForgotten: devices, mailDelivered: link.mail.delivered },
        });
        // The link comes back either way: that is the fallback when mail is down (REQ-108).
        res.json({ url: link.url, expiresAt: link.expiresAt, mail: link.mail, sessionsEnded: ended });
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post(`${ADMIN_API}/invites`, auth.requireAdmin, body, (req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        const input = req.body as { email?: unknown };
        const email = typeof input.email === 'string' ? input.email.trim().toLowerCase() : '';
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
          res.status(400).json({ error: 'invalid_email', message: 'Enter an email address to invite.' });
          return;
        }

        const created = await invites.create({
          email,
          invitedByUserId: user.id,
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
        });
        // The link comes back whether or not the mail went: that is the fallback (REQ-108).
        res.status(201).json(created);
      } catch (err) {
        if ((err as { code?: string }).code === 'already_a_user') {
          res.status(409).json({ error: 'already_a_user', message: 'That email already has an account.' });
          return;
        }
        next(err);
      }
    })();
  });

  router.post<{ id: string }>(`${ADMIN_API}/invites/:id/revoke`, auth.requireAdmin, (req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        const inviteId = req.params.id;
        const { count } = await db.invite.updateMany({
          where: { id: inviteId, acceptedAt: null },
          data: { expiresAt: new Date() },
        });
        if (count === 0) {
          res.status(404).json({ error: 'not_found' });
          return;
        }
        await audit.write({
          event: AUDIT_EVENTS.inviteRevoked,
          actorUserId: user.id,
          targetType: 'user',
          targetId: inviteId,
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
        });
        res.json({ revoked: true });
      } catch (err) {
        next(err);
      }
    })();
  });

  // Apps (C-4, C-5, C-6). Owner-only: registering an app decides who can ask for tokens at all,
  // which is a different kind of power from managing the people who already have accounts.
  const withManifest =
    (act: (manifest: Manifest, req: Request, res: Response) => Promise<void>): RequestHandler =>
    (req, res, next) => {
      void (async () => {
        try {
          const input = req.body as { manifest?: unknown };
          // The manifest may be pasted as JSON text or sent as an object; both arrive here.
          const raw: unknown = typeof input.manifest === 'string' ? JSON.parse(input.manifest) : (input.manifest ?? req.body);
          const parsed = parseManifest(raw);
          if (!parsed.ok) {
            res.status(400).json({ error: 'invalid_manifest', problems: parsed.problems });
            return;
          }
          await act(parsed.manifest, req, res);
        } catch (err) {
          if (err instanceof SyntaxError) {
            res.status(400).json({ error: 'invalid_manifest', problems: [{ field: 'manifest', message: 'That is not valid JSON.' }] });
            return;
          }
          if (err instanceof AppError) {
            res.status(err.code === 'already_exists' || err.code === 'roles_in_use' ? 409 : 404).json({
              error: err.code,
              message: err.message,
              ...(err.detail ? { detail: err.detail } : {}),
            });
            return;
          }
          next(err);
        }
      })();
    };

  router.get(`${ADMIN_API}/apps`, auth.requireOwner, (_req, res, next) => {
    void (async () => {
      try {
        res.set('Cache-Control', 'no-store').json({ apps: await apps.list() });
      } catch (err) {
        next(err);
      }
    })();
  });

  router.get<{ clientId: string }>(`${ADMIN_API}/apps/:clientId`, auth.requireOwner, (req, res, next) => {
    void (async () => {
      try {
        const app = await apps.get(req.params.clientId);
        if (!app) {
          res.status(404).json({ error: 'not_found' });
          return;
        }
        res.set('Cache-Control', 'no-store').json(app);
      } catch (err) {
        next(err);
      }
    })();
  });

  // What this manifest would do, before anybody commits to it (REQ-048, REQ-067).
  router.post(
    `${ADMIN_API}/apps/preview`,
    auth.requireOwner,
    body,
    withManifest(async (manifest, _req, res) => {
      res.json({ diff: await apps.preview(manifest) });
    }),
  );

  router.post(
    `${ADMIN_API}/apps`,
    auth.requireOwner,
    body,
    withManifest(async (manifest, req, res) => {
      const { user } = consoleUserOf(res);
      const created = await apps.register({
        manifest,
        actorUserId: user.id,
        ip: clientIp(req),
        userAgent: req.get('user-agent'),
      });
      // The secret is in this response and nowhere else, ever again.
      res.status(201).json(created);
    }),
  );

  router.post<{ clientId: string }>(
    `${ADMIN_API}/apps/:clientId/manifest`,
    auth.requireOwner,
    body,
    withManifest(async (manifest, req, res) => {
      const { user } = consoleUserOf(res);
      const input = req.body as { confirmRoleRemoval?: unknown };
      if (manifest.client_id !== req.params.clientId) {
        res.status(400).json({
          error: 'client_id_mismatch',
          message: 'The manifest is for a different app. A client id cannot be changed by re-registering.',
        });
        return;
      }
      res.json(
        await apps.update({
          manifest,
          actorUserId: user.id,
          confirmRoleRemoval: input.confirmRoleRemoval === true,
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
        }),
      );
    }),
  );

  /** The three actions that do not take a manifest. */
  const appAction =
    (act: (clientId: string, req: Request, res: Response, actorUserId: string) => Promise<unknown>): RequestHandler =>
    (req, res, next) => {
      void (async () => {
        try {
          const { user } = consoleUserOf(res);
          res.json(await act((req.params as { clientId: string }).clientId, req, res, user.id));
        } catch (err) {
          if (err instanceof AppError) {
            res.status(err.code === 'not_found' ? 404 : 409).json({ error: err.code, message: err.message });
            return;
          }
          next(err);
        }
      })();
    };

  router.post<{ clientId: string }>(
    `${ADMIN_API}/apps/:clientId/secret`,
    auth.requireOwner,
    appAction((clientId, req, _res, actorUserId) => apps.rotateSecret({ clientId, actorUserId, ip: clientIp(req) })),
  );

  router.post<{ clientId: string }>(
    `${ADMIN_API}/apps/:clientId/enabled`,
    auth.requireOwner,
    body,
    appAction((clientId, req, _res, actorUserId) =>
      apps.setEnabled({ clientId, enabled: (req.body as { enabled?: unknown }).enabled !== false, actorUserId, ip: clientIp(req) }),
    ),
  );

  router.post<{ clientId: string }>(
    `${ADMIN_API}/apps/:clientId/remove`,
    auth.requireOwner,
    appAction((clientId, req, _res, actorUserId) => apps.remove({ clientId, actorUserId, ip: clientIp(req) })),
  );

  // Grants (REQ-049). Admins hand out access; apps themselves are owner-only above.
  const onGrantError = (err: unknown, res: Response, next: NextFunction): void => {
    if (err instanceof GrantError) {
      res.status(err.code === 'unknown_roles' ? 400 : 404).json({ error: err.code, message: err.message, ...(err.detail ? { detail: err.detail } : {}) });
      return;
    }
    next(err);
  };

  /** Who can sign in to this app, and as what — the Access tab (REQ-066). */
  router.get<{ clientId: string }>(`${ADMIN_API}/apps/:clientId/access`, auth.requireAdmin, (req, res, next) => {
    void (async () => {
      try {
        res.set('Cache-Control', 'no-store').json({ access: await grants.forApp(req.params.clientId) });
      } catch (err) {
        onGrantError(err, res, next);
      }
    })();
  });

  /** Everything one person can reach, for their detail page (REQ-064). */
  router.get<{ id: string }>(`${ADMIN_API}/people/:id/access`, auth.requireAdmin, (req, res, next) => {
    void (async () => {
      try {
        res.set('Cache-Control', 'no-store').json({ access: await grants.forUser(req.params.id) });
      } catch (err) {
        onGrantError(err, res, next);
      }
    })();
  });

  router.post<{ id: string }>(`${ADMIN_API}/people/:id/access`, auth.requireAdmin, body, (req, res, next) => {
    void (async () => {
      try {
        const { user: actor } = consoleUserOf(res);
        const input = req.body as { clientId?: unknown; roles?: unknown };
        const clientId = typeof input.clientId === 'string' ? input.clientId : '';
        const roles = Array.isArray(input.roles) ? input.roles.filter((role): role is string => typeof role === 'string') : [];
        if (!clientId) {
          res.status(400).json({ error: 'invalid', message: 'Say which app this is for.' });
          return;
        }
        res.json(await grants.set({ userId: req.params.id, clientId, roles, actorUserId: actor.id, ip: clientIp(req) }));
      } catch (err) {
        onGrantError(err, res, next);
      }
    })();
  });

  router.post<{ id: string }>(`${ADMIN_API}/people/:id/access/revoke`, auth.requireAdmin, body, (req, res, next) => {
    void (async () => {
      try {
        const { user: actor } = consoleUserOf(res);
        const clientId = (req.body as { clientId?: unknown }).clientId;
        if (typeof clientId !== 'string') {
          res.status(400).json({ error: 'invalid', message: 'Say which app this is for.' });
          return;
        }
        const revoked = await grants.revoke({ userId: req.params.id, clientId, actorUserId: actor.id, ip: clientIp(req) });
        if (!revoked) {
          res.status(404).json({ error: 'not_found', message: 'They did not have access to that app.' });
          return;
        }
        res.json({ revoked: true });
      } catch (err) {
        onGrantError(err, res, next);
      }
    })();
  });

  return router;
}
