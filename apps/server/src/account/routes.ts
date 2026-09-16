import express, { Router, type RequestHandler } from 'express';
import type { RegistrationResponseJSON } from '@simplewebauthn/server';
import { AUDIT_EVENTS } from '../audit/events.js';
import { clientIp, type AuditWriter } from '../audit/writer.js';
import { consoleUserOf, isAdmin, type ConsoleAuth } from '../console/auth.js';
import type { Db } from '../db.js';
import type { Totp } from '../security/totp.js';
import type { WebAuthn } from '../security/webauthn.js';

// The account area's API (A-4 for now: factors). Profile, password and sessions follow in T-2.7.
//
// The rule that shapes this file: an owner or admin may not end up with no way to prove it is
// them (REQ-035, REQ-042). Removing a factor therefore counts what would be left.

export const ACCOUNT_API = '/api/account';

export interface AccountDeps {
  db: Db;
  auth: ConsoleAuth;
  totp: Totp;
  webauthn: WebAuthn;
  audit: AuditWriter;
}

export function accountRouter({ db, auth, totp, webauthn, audit }: AccountDeps): Router {
  const router = Router();
  const asJson = express.json({ limit: '16kb' });
  const body: RequestHandler = (req, res, next) => {
    asJson(req, res, (err: unknown) => {
      if (err) next(err);
      else next();
    });
  };

  /** How many verified factors the person would have left after removing one. */
  const factorCount = async (userId: string): Promise<number> => {
    const [passkeys, codes] = await Promise.all([
      db.webauthnCredential.count({ where: { userId } }),
      db.totpCredential.count({ where: { userId, confirmedAt: { not: null } } }),
    ]);
    return passkeys + codes;
  };

  router.get(`${ACCOUNT_API}/factors`, auth.requireUser, (_req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        const [passkeys, codes] = await Promise.all([webauthn.list(user.id), totp.list(user.id)]);
        res.set('Cache-Control', 'no-store').json({
          passkeys,
          totp: codes.filter((code) => code.confirmedAt !== null),
          // The console explains *why* removal is refused before the person tries.
          factorRequired: isAdmin(user),
        });
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post(`${ACCOUNT_API}/passkeys/begin`, auth.requireUser, (_req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        const options = await webauthn.beginRegistration({
          userId: user.id,
          accountName: user.email,
          displayName: user.displayName,
        });
        res.set('Cache-Control', 'no-store').json(options);
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post(`${ACCOUNT_API}/passkeys/finish`, auth.requireUser, body, (req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        const input = req.body as { response?: RegistrationResponseJSON; label?: string };
        if (!input.response) {
          res.status(400).json({ error: 'missing_response' });
          return;
        }
        const result = await webauthn.finishRegistration({
          userId: user.id,
          response: input.response,
          ...(input.label ? { label: input.label } : {}),
        });
        if (!result.ok) {
          res.status(400).json({ error: 'not_verified', message: 'That passkey could not be verified. Try again.' });
          return;
        }
        await audit.write({
          event: AUDIT_EVENTS.factorAdded,
          actorUserId: user.id,
          targetType: 'user',
          targetId: user.id,
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
          detail: { factor: 'passkey' },
        });
        res.json({ ok: true });
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post<{ id: string }>(`${ACCOUNT_API}/passkeys/:id/remove`, auth.requireUser, (req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        if (isAdmin(user) && (await factorCount(user.id)) <= 1) {
          res.status(409).json({
            error: 'last_factor',
            message: 'Admins keep at least one passkey or authenticator app. Add another before removing this one.',
          });
          return;
        }
        const removed = await webauthn.remove({ userId: user.id, credentialId: req.params.id });
        if (!removed) {
          res.status(404).json({ error: 'not_found' });
          return;
        }
        await audit.write({
          event: AUDIT_EVENTS.factorRemoved,
          actorUserId: user.id,
          targetType: 'user',
          targetId: user.id,
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
          detail: { factor: 'passkey' },
        });
        res.json({ removed: true });
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post(`${ACCOUNT_API}/totp/begin`, auth.requireUser, body, (req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        const input = req.body as { label?: string };
        const enrolment = await totp.begin({
          userId: user.id,
          accountName: user.email,
          ...(input.label ? { label: input.label } : {}),
        });
        // The secret is shown once, here, and never logged.
        res.set('Cache-Control', 'no-store').json(enrolment);
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post(`${ACCOUNT_API}/totp/confirm`, auth.requireUser, body, (req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        const input = req.body as { credentialId?: string; code?: string };
        const confirmed = await totp.confirm({
          userId: user.id,
          credentialId: input.credentialId ?? '',
          code: input.code ?? '',
        });
        if (!confirmed) {
          res.status(400).json({ error: 'wrong_code', message: 'That code did not match. Check the time on your phone and try the next one.' });
          return;
        }
        await audit.write({
          event: AUDIT_EVENTS.factorAdded,
          actorUserId: user.id,
          targetType: 'user',
          targetId: user.id,
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
          detail: { factor: 'totp' },
        });
        res.json({ ok: true });
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post<{ id: string }>(`${ACCOUNT_API}/totp/:id/remove`, auth.requireUser, (req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        if (isAdmin(user) && (await factorCount(user.id)) <= 1) {
          res.status(409).json({
            error: 'last_factor',
            message: 'Admins keep at least one passkey or authenticator app. Add another before removing this one.',
          });
          return;
        }
        const removed = await totp.remove({ userId: user.id, credentialId: req.params.id });
        if (!removed) {
          res.status(404).json({ error: 'not_found' });
          return;
        }
        await audit.write({
          event: AUDIT_EVENTS.factorRemoved,
          actorUserId: user.id,
          targetType: 'user',
          targetId: user.id,
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
          detail: { factor: 'totp' },
        });
        res.json({ removed: true });
      } catch (err) {
        next(err);
      }
    })();
  });

  return router;
}
