import express, { Router, type RequestHandler } from 'express';
import { AUDIT_EVENTS } from '../audit/events.js';
import { clientIp, type AuditWriter } from '../audit/writer.js';
import { consoleUserOf, type ConsoleAuth } from '../console/auth.js';
import type { Db } from '../db.js';
import { mustHoldFactor, verifiedFactorCount } from '../security/factors.js';
import type { Invites } from './invites.js';

// The console's API for the people side of the house (C-1, C-3). Phase 3 adds apps, grants and
// groups here; this is the part Phase 2 needs to put a real person on the system.

export const ADMIN_API = '/api/admin';

export interface AdminDeps {
  db: Db;
  auth: ConsoleAuth;
  invites: Invites;
  audit: AuditWriter;
}

export function adminRouter({ db, auth, invites, audit }: AdminDeps): Router {
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

  return router;
}
