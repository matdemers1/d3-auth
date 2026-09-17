import express, { Router, type NextFunction, type Request, type RequestHandler, type Response } from 'express';
import { AUDIT_EVENTS } from '../audit/events.js';
import { clientIp, type AuditWriter } from '../audit/writer.js';
import { consoleUserOf, type ConsoleAuth } from '../console/auth.js';
import type { Db } from '../db.js';
import type { ReadinessProbe } from '../health.js';
import { mustHoldFactor, verifiedFactorCount } from '../security/factors.js';
import type { SessionControl } from '../security/sessions.js';
import type { TrustedDevices } from '../security/trusted-device.js';
import { GrantError, type Grants } from '../authz/grants.js';
import { AppError, type Apps } from './apps.js';
import { knownEvents, searchAudit, toCsv, type AuditFilter } from './audit-query.js';
import { overview } from './overview.js';
import { alertSettingsSchema, lifetimeSettingsSchema, mailSettingsSchema, type Settings } from './settings.js';
import { exportState, importState, stateSchema } from './state.js';
import { GroupError, type Groups } from './groups.js';
import type { MailAdapter } from '../mail/adapter.js';
import type { Invites } from './invites.js';
import { parseManifest, type Manifest } from './manifest.js';
import { buildFromPreset, connectionFor, describePreset, findPreset, PRESETS } from './presets/index.js';

// The console's API for the people side of the house (C-1, C-3). Phase 3 adds apps, grants and
// groups here; this is the part Phase 2 needs to put a real person on the system.

export const ADMIN_API = '/api/admin';

export interface AdminDeps {
  db: Db;
  /** The issuer apps are told to use, for their connection sheets. */
  issuer: string;
  apps: Apps;
  grants: Grants;
  groups: Groups;
  settings: Settings;
  mail: MailAdapter;
  /** Used in copy the console shows to people, e.g. "Ask Matthew" (REQ-087). */
  operatorDisplayName: string;
  auth: ConsoleAuth;
  invites: Invites;
  sessions: SessionControl;
  trustedDevices: TrustedDevices;
  audit: AuditWriter;
  /** The same probe /readyz answers with, so the home tiles cannot disagree with it. */
  readiness: ReadinessProbe;
  /** Whether nightly offsite backups are set up, so the home page can say when they are not. */
  backupsConfigured?: boolean;
}

export function adminRouter({
  db,
  issuer,
  apps,
  grants,
  groups,
  settings,
  mail,
  operatorDisplayName,
  auth,
  invites,
  sessions,
  trustedDevices,
  audit,
  readiness,
  backupsConfigured = false,
}: AdminDeps): Router {
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
    auth.requireFreshOwner,
    body,
    withManifest(async (manifest, req, res) => {
      const { user } = consoleUserOf(res);
      const created = await apps.register({
        manifest,
        actorUserId: user.id,
        ip: clientIp(req),
        userAgent: req.get('user-agent'),
      });
      // The secret is in this response and nowhere else, ever again — here and in the sheet.
      res.status(201).json({ ...created, connection: connectionFor(issuer, created.app, created.secret) });
    }),
  );

  // Presets (REQ-143): an app D3 Auth already knows how to connect. The list is served from the
  // registry, so the console cannot offer a preset the server does not have.
  router.get(`${ADMIN_API}/app-presets`, auth.requireOwner, (_req, res) => {
    res.set('Cache-Control', 'no-store').json({ presets: PRESETS.map((preset) => describePreset(preset)) });
  });

  router.post<{ key: string }>(`${ADMIN_API}/app-presets/:key/preview`, auth.requireOwner, body, (req, res, next) => {
    void (async () => {
      try {
        const preset = findPreset(req.params.key);
        if (!preset) {
          res.status(404).json({ error: 'preset_not_found', message: 'There is no preset by that name.' });
          return;
        }
        const built = buildFromPreset(preset, (req.body as { inputs?: unknown } | undefined)?.inputs);
        if (!built.ok) {
          res.status(400).json({ error: 'invalid_inputs', problems: built.problems });
          return;
        }
        res.json({ inputs: built.inputs, manifest: built.manifest, diff: await apps.preview(built.manifest) });
      } catch (err) {
        next(err);
      }
    })();
  });

  // Registering from a preset is registering a manifest: same parse, same register, same step-up.
  // The only difference is that the answers are remembered, so the paste sheet can be shown again.
  router.post(`${ADMIN_API}/apps/from-preset`, auth.requireFreshOwner, body, (req, res, next) => {
    void (async () => {
      try {
        const input = (req.body ?? {}) as { preset?: unknown; inputs?: unknown };
        const preset = typeof input.preset === 'string' ? findPreset(input.preset) : undefined;
        if (!preset) {
          res.status(404).json({ error: 'preset_not_found', message: 'There is no preset by that name.' });
          return;
        }
        const built = buildFromPreset(preset, input.inputs);
        if (!built.ok) {
          res.status(400).json({ error: 'invalid_inputs', problems: built.problems });
          return;
        }
        const { user } = consoleUserOf(res);
        const created = await apps.register({
          manifest: built.manifest,
          actorUserId: user.id,
          preset: { key: preset.key, inputs: built.inputs },
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
        });
        res.status(201).set('Cache-Control', 'no-store').json({ ...created, connection: connectionFor(issuer, created.app, created.secret) });
      } catch (err) {
        if (err instanceof AppError) {
          res.status(err.code === 'already_exists' ? 409 : 404).json({ error: err.code, message: err.message });
          return;
        }
        next(err);
      }
    })();
  });

  // What the app needs, at any time (REQ-142). Built from the row and the provider's own protocol
  // choices; the stored secret is a hash and is never part of it.
  router.get<{ clientId: string }>(`${ADMIN_API}/apps/:clientId/connection`, auth.requireOwner, (req, res, next) => {
    void (async () => {
      try {
        const app = await apps.get(req.params.clientId);
        if (!app) {
          res.status(404).json({ error: 'not_found' });
          return;
        }
        res.set('Cache-Control', 'no-store').json(connectionFor(issuer, app));
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post<{ clientId: string }>(
    `${ADMIN_API}/apps/:clientId/manifest`,
    auth.requireFreshOwner,
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
    auth.requireFreshOwner,
    appAction(async (clientId, req, _res, actorUserId) => {
      const { secret } = await apps.rotateSecret({ clientId, actorUserId, ip: clientIp(req) });
      const app = await apps.get(clientId);
      // Shown once: in this answer, and in the sheet with it.
      return { secret, ...(app ? { connection: connectionFor(issuer, app, secret) } : {}) };
    }),
  );

  router.post<{ clientId: string }>(
    `${ADMIN_API}/apps/:clientId/enabled`,
    auth.requireFreshOwner,
    body,
    appAction((clientId, req, _res, actorUserId) =>
      apps.setEnabled({ clientId, enabled: (req.body as { enabled?: unknown }).enabled !== false, actorUserId, ip: clientIp(req) }),
    ),
  );

  router.post<{ clientId: string }>(
    `${ADMIN_API}/apps/:clientId/remove`,
    auth.requireFreshOwner,
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

  // Groups (C-7, REQ-068). Admin-level: a group hands out access, and access is an admin's job.
  const onGroupError = (err: unknown, res: Response, next: NextFunction): void => {
    if (err instanceof GroupError) {
      const status = err.code === 'not_found' ? 404 : err.code === 'name_taken' ? 409 : 400;
      res.status(status).json({ error: err.code, message: err.message, ...(err.detail ? { detail: err.detail } : {}) });
      return;
    }
    next(err);
  };

  const groupRoute =
    (act: (req: Request & { params: { id: string } }, res: Response, actorUserId: string) => Promise<unknown>): RequestHandler =>
    (req, res, next) => {
      void (async () => {
        try {
          const { user } = consoleUserOf(res);
          const answer = await act(req as Request & { params: { id: string } }, res, user.id);
          if (answer !== undefined) res.set('Cache-Control', 'no-store').json(answer);
        } catch (err) {
          onGroupError(err, res, next);
        }
      })();
    };

  router.get(`${ADMIN_API}/groups`, auth.requireAdmin, groupRoute(async () => ({ groups: await groups.list() })));

  router.get<{ id: string }>(
    `${ADMIN_API}/groups/:id`,
    auth.requireAdmin,
    groupRoute(async (req, res) => {
      const group = await groups.get(req.params.id);
      if (!group) {
        res.status(404).json({ error: 'not_found' });
        return undefined;
      }
      return group;
    }),
  );

  router.post(
    `${ADMIN_API}/groups`,
    auth.requireAdmin,
    body,
    groupRoute((req, _res, actorUserId) => {
      const input = req.body as { name?: unknown; description?: unknown };
      return groups.create({
        name: typeof input.name === 'string' ? input.name : '',
        description: typeof input.description === 'string' ? input.description : '',
        actorUserId,
        ip: clientIp(req),
      });
    }),
  );

  router.post<{ id: string }>(
    `${ADMIN_API}/groups/:id`,
    auth.requireAdmin,
    body,
    groupRoute((req, _res, actorUserId) => {
      const input = req.body as { name?: unknown; description?: unknown };
      return groups.rename({
        id: req.params.id,
        name: typeof input.name === 'string' ? input.name : '',
        ...(typeof input.description === 'string' ? { description: input.description } : {}),
        actorUserId,
        ip: clientIp(req),
      });
    }),
  );

  router.post<{ id: string }>(
    `${ADMIN_API}/groups/:id/members`,
    auth.requireAdmin,
    body,
    groupRoute((req, _res, actorUserId) => {
      const input = req.body as { userIds?: unknown };
      const userIds = Array.isArray(input.userIds) ? input.userIds.filter((id): id is string => typeof id === 'string') : [];
      return groups.setMembers({ id: req.params.id, userIds, actorUserId, ip: clientIp(req) });
    }),
  );

  router.post<{ id: string }>(
    `${ADMIN_API}/groups/:id/access`,
    auth.requireAdmin,
    body,
    groupRoute((req, _res, actorUserId) => {
      const input = req.body as { clientId?: unknown; roles?: unknown };
      const roles = Array.isArray(input.roles) ? input.roles.filter((role): role is string => typeof role === 'string') : [];
      return groups.setGrant({
        id: req.params.id,
        clientId: typeof input.clientId === 'string' ? input.clientId : '',
        roles,
        actorUserId,
        ip: clientIp(req),
      });
    }),
  );

  router.post<{ id: string }>(
    `${ADMIN_API}/groups/:id/access/revoke`,
    auth.requireAdmin,
    body,
    groupRoute(async (req, res, actorUserId) => {
      const clientId = (req.body as { clientId?: unknown }).clientId;
      const revoked = await groups.revokeGrant({
        id: req.params.id,
        clientId: typeof clientId === 'string' ? clientId : '',
        actorUserId,
        ip: clientIp(req),
      });
      if (!revoked) {
        res.status(404).json({ error: 'not_found', message: 'That group did not have access to that app.' });
        return undefined;
      }
      return { revoked: true };
    }),
  );

  router.post<{ id: string }>(
    `${ADMIN_API}/groups/:id/remove`,
    auth.requireAdmin,
    groupRoute(async (req, res, actorUserId) => {
      const removed = await groups.remove({ id: req.params.id, actorUserId, ip: clientIp(req) });
      if (!removed) {
        res.status(404).json({ error: 'not_found' });
        return undefined;
      }
      return { removed: true };
    }),
  );

  // The audit trail (C-8, REQ-069). Admin-level reading; the table itself refuses writes.
  const filterFrom = (req: Request): AuditFilter => {
    const query = req.query as Record<string, string | undefined>;
    const date = (value: string | undefined): Date | undefined => {
      if (!value) return undefined;
      const parsed = new Date(value);
      return Number.isNaN(parsed.getTime()) ? undefined : parsed;
    };
    return {
      actorUserId: query.actor,
      targetId: query.target,
      event: query.event,
      from: date(query.from),
      to: date(query.to),
      limit: query.limit ? Number(query.limit) : undefined,
      cursor: query.cursor,
    };
  };

  // The console's front page (REQ-073). Admins see it; it is the first thing after signing in.
  router.get(`${ADMIN_API}/overview`, auth.requireAdmin, (_req, res, next) => {
    void (async () => {
      try {
        res.set('Cache-Control', 'no-store').json(await overview(db, readiness, { backupsConfigured }));
      } catch (err) {
        next(err);
      }
    })();
  });

  router.get(`${ADMIN_API}/audit`, auth.requireAdmin, (req, res, next) => {
    void (async () => {
      try {
        const page = await searchAudit(db, filterFrom(req));
        res.set('Cache-Control', 'no-store').json(page);
      } catch (err) {
        next(err);
      }
    })();
  });

  router.get(`${ADMIN_API}/audit/events`, auth.requireAdmin, (_req, res, next) => {
    void (async () => {
      try {
        res.set('Cache-Control', 'no-store').json({ events: await knownEvents(db) });
      } catch (err) {
        next(err);
      }
    })();
  });

  /** The same search, as a file. Same filters, so what you see is what you get. */
  router.get(`${ADMIN_API}/audit/export`, auth.requireAdmin, (req, res, next) => {
    void (async () => {
      try {
        const filter = { ...filterFrom(req), limit: 200 };
        const page = await searchAudit(db, filter);
        const stamp = new Date().toISOString().slice(0, 10);
        if ((req.query as { format?: string }).format === 'json') {
          res.set('Content-Disposition', `attachment; filename="audit-${stamp}.json"`).json(page.events);
          return;
        }
        res
          .type('text/csv')
          .set('Content-Disposition', `attachment; filename="audit-${stamp}.csv"`)
          .send(toCsv(page));
      } catch (err) {
        next(err);
      }
    })();
  });

  // Settings (C-10, REQ-071). Owner-only: these decide how the system reaches people and how
  // long it trusts them.
  router.get(`${ADMIN_API}/settings`, auth.requireOwner, (_req, res, next) => {
    void (async () => {
      try {
        res.set('Cache-Control', 'no-store').json(await settings.view());
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post(`${ADMIN_API}/settings/mail`, auth.requireFreshOwner, body, (req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        const input = req.body as { settings?: unknown; secret?: unknown };
        const parsed = mailSettingsSchema.safeParse(input.settings);
        if (!parsed.success) {
          res.status(400).json({ error: 'invalid', problems: parsed.error.issues.map((issue) => issue.message) });
          return;
        }
        await settings.setMail({
          settings: parsed.data,
          // Absent leaves the stored secret alone; empty clears it.
          ...(typeof input.secret === 'string' ? { secret: input.secret } : {}),
          actorUserId: user.id,
          ip: clientIp(req),
        });
        res.json(await settings.view());
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post(`${ADMIN_API}/settings/alerts`, auth.requireOwner, body, (req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        const parsed = alertSettingsSchema.safeParse((req.body as { settings?: unknown }).settings);
        if (!parsed.success) {
          res.status(400).json({ error: 'invalid', problems: parsed.error.issues.map((issue) => issue.message) });
          return;
        }
        await settings.setAlerts({ settings: parsed.data, actorUserId: user.id, ip: clientIp(req) });
        res.json(await settings.view());
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post(`${ADMIN_API}/settings/lifetimes`, auth.requireOwner, body, (req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        const parsed = lifetimeSettingsSchema.safeParse((req.body as { settings?: unknown }).settings);
        if (!parsed.success) {
          res.status(400).json({ error: 'invalid', problems: parsed.error.issues.map((issue) => issue.message) });
          return;
        }
        await settings.setLifetimes({ settings: parsed.data, actorUserId: user.id, ip: clientIp(req) });
        res.json(await settings.view());
      } catch (err) {
        next(err);
      }
    })();
  });

  /**
   * Send one real message with the configuration as it stands (REQ-109).
   *
   * The driver's own error comes back word for word. A paraphrase would be worse than useless
   * here: "could not send" tells an operator nothing, while "relay answered 401" tells them
   * exactly which thing to fix.
   */
  router.post(`${ADMIN_API}/settings/mail/test`, auth.requireOwner, body, (req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        const to = (req.body as { to?: unknown }).to;
        const recipient = typeof to === 'string' && to.includes('@') ? to : user.email;

        const result = await mail.send({
          to: recipient,
          subject: `Test message from ${operatorDisplayName}`,
          text: `This is a test message sent from the ${operatorDisplayName} console. If it arrived, mail works.`,
        });
        await audit.write({
          event: AUDIT_EVENTS.mailTested,
          actorUserId: user.id,
          targetType: 'user',
          targetId: user.id,
          ip: clientIp(req),
          detail: { to: recipient, delivered: result.delivered, driver: result.driver },
        });
        res.status(result.delivered ? 200 : 502).json(result);
      } catch (err) {
        next(err);
      }
    })();
  });

  // Export and import (REQ-072). Owner-only, and the import is behind a fresh proof: a file can
  // hand somebody access to everything, so it is treated like rotating a secret.
  router.get(`${ADMIN_API}/state/export`, auth.requireOwner, (req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        const state = await exportState(db);
        await audit.write({
          event: AUDIT_EVENTS.stateExported,
          actorUserId: user.id,
          targetType: 'app',
          ip: clientIp(req),
          detail: { apps: state.apps.length, people: state.people.length, groups: state.groups.length },
        });
        const stamp = new Date().toISOString().slice(0, 10);
        res
          .set('Cache-Control', 'no-store')
          .set('Content-Disposition', `attachment; filename="d3auth-state-${stamp}.json"`)
          .json(state);
      } catch (err) {
        next(err);
      }
    })();
  });

  const importRoute =
    (dryRun: boolean): RequestHandler =>
    (req, res, next) => {
      void (async () => {
        try {
          const { user } = consoleUserOf(res);
          const parsed = stateSchema.safeParse((req.body as { state?: unknown }).state);
          if (!parsed.success) {
            res.status(400).json({
              error: 'invalid',
              problems: parsed.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`),
            });
            return;
          }
          const result = await importState(db, parsed.data, { dryRun, actorUserId: user.id, audit });
          res.json(result);
        } catch (err) {
          next(err);
        }
      })();
    };

  // A state file is the one body here that is legitimately large; 8kb would refuse a real one.
  const stateBody = express.json({ limit: '2mb' });

  /** What it would do. Nothing is written; the console shows this before offering to apply it. */
  router.post(`${ADMIN_API}/state/import/preview`, auth.requireOwner, stateBody, importRoute(true));
  router.post(`${ADMIN_API}/state/import`, auth.requireFreshOwner, stateBody, importRoute(false));

  return router;
}
