import { createHash } from 'node:crypto';
import express, { Router, type RequestHandler } from 'express';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { AUDIT_EVENTS } from '../audit/events.js';
import { clientIp, type AuditWriter } from '../audit/writer.js';
import { consoleUserOf, isAdmin, type ConsoleAuth } from '../console/auth.js';
import type { Grants } from '../authz/grants.js';
import type { Db } from '../db.js';
import { readCookie } from '../security/cookies.js';
import { verifiedFactorCount } from '../security/factors.js';
import type { SessionControl } from '../security/sessions.js';
import type { TrustedDevices } from '../security/trusted-device.js';
import type { SecretHasher } from '../security/hash.js';
import type { PasswordVerifier } from '../security/password.js';
import { checkPassword, USERNAME_PATTERN, USERNAME_RULE } from '../security/policy.js';
import type { Throttle } from '../security/throttle.js';
import type { Totp } from '../security/totp.js';
import type { WebAuthn } from '../security/webauthn.js';

// The account area's API: profile (A-2), password (A-3), factors (A-4), sessions and devices
// (A-5).
//
// Two rules shape this file. An owner or admin may not end up with no way to prove it is them
// (REQ-035, REQ-042), so removing a factor counts what would be left. And changing a password is
// not a password-only act: anyone holding a factor has to use it here too (REQ-081), because a
// borrowed session with a known password would otherwise be enough to take the account.

export const ACCOUNT_API = '/api/account';

/**
 * The step-up challenge is keyed by the session, but the session id is the cookie value itself —
 * so it is hashed first. Otherwise a row in the payload table would carry a live session token.
 */
const stepUpKey = (sessionId: string): string => `stepup:${createHash('sha256').update(sessionId).digest('hex')}`;

export interface AccountDeps {
  db: Db;
  grants: Grants;
  sessions: SessionControl;
  auth: ConsoleAuth;
  hasher: SecretHasher;
  passwords: PasswordVerifier;
  throttle: Throttle;
  totp: Totp;
  webauthn: WebAuthn;
  trustedDevices: TrustedDevices;
  deviceCookieName: string;
  audit: AuditWriter;
}

export function accountRouter({
  db,
  grants,
  sessions,
  auth,
  hasher,
  passwords,
  throttle,
  totp,
  webauthn,
  trustedDevices,
  deviceCookieName,
  audit,
}: AccountDeps): Router {
  const router = Router();
  const asJson = express.json({ limit: '16kb' });
  const body: RequestHandler = (req, res, next) => {
    asJson(req, res, (err: unknown) => {
      if (err) next(err);
      else next();
    });
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
        if (isAdmin(user) && (await verifiedFactorCount(db, user.id)) <= 1) {
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
        if (isAdmin(user) && (await verifiedFactorCount(db, user.id)) <= 1) {
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

  // A-1: the launcher (REQ-079). Everything this person can sign in to, which is the one screen
  // that answers "what is this account even for?".
  router.get(`${ACCOUNT_API}/apps`, auth.requireUser, (_req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        res.set('Cache-Control', 'no-store').json({ apps: await grants.forUser(user.id) });
      } catch (err) {
        next(err);
      }
    })();
  });

  // Trusted devices (REQ-036): the list is what makes "don't ask again" reversible.
  router.get(`${ACCOUNT_API}/devices`, auth.requireUser, (req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        const devices = await trustedDevices.list({ userId: user.id, token: readCookie(req, deviceCookieName) });
        res.set('Cache-Control', 'no-store').json({ devices });
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post<{ id: string }>(`${ACCOUNT_API}/devices/:id/revoke`, auth.requireUser, (req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        const revoked = await trustedDevices.revoke({ userId: user.id, id: req.params.id });
        if (!revoked) {
          res.status(404).json({ error: 'not_found' });
          return;
        }
        await audit.write({
          event: AUDIT_EVENTS.deviceRevoked,
          actorUserId: user.id,
          targetType: 'user',
          targetId: user.id,
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
        });
        res.json({ revoked: true });
      } catch (err) {
        next(err);
      }
    })();
  });

  // A-2: the parts of the profile a person owns. The email is not one of them — it is the
  // identifier an admin invited, and changing it is an admin's job (REQ-080).
  router.get(`${ACCOUNT_API}/profile`, auth.requireUser, (_req, res) => {
    const { user } = consoleUserOf(res);
    res.set('Cache-Control', 'no-store').json({
      email: user.email,
      username: user.username,
      displayName: user.displayName,
      kind: user.kind,
      status: user.status,
    });
  });

  router.post(`${ACCOUNT_API}/profile`, auth.requireUser, body, (req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        const input = req.body as { displayName?: unknown; username?: unknown };
        const displayName = typeof input.displayName === 'string' ? input.displayName.trim() : '';
        const username = typeof input.username === 'string' ? input.username.trim() : '';

        const problems: string[] = [];
        if (displayName.length < 1) problems.push('Enter the name people will see.');
        if (!USERNAME_PATTERN.test(username)) problems.push(USERNAME_RULE);
        if (problems.length > 0) {
          res.status(400).json({ error: 'invalid', problems });
          return;
        }

        const taken = await db.user.findFirst({ where: { username, id: { not: user.id } }, select: { id: true } });
        if (taken) {
          res.status(409).json({ error: 'taken', message: 'Somebody already has that username.' });
          return;
        }

        const updated = await db.user.update({ where: { id: user.id }, data: { displayName, username } });
        await audit.write({
          event: AUDIT_EVENTS.profileUpdated,
          actorUserId: user.id,
          targetType: 'user',
          targetId: user.id,
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
          detail: { displayName: updated.displayName, username: updated.username },
        });
        res.json({ displayName: updated.displayName, username: updated.username });
      } catch (err) {
        next(err);
      }
    })();
  });

  // The passkey half of the step-up below. The challenge is keyed to the session, so an assertion
  // obtained in one browser cannot be replayed from another.
  router.post(`${ACCOUNT_API}/step-up/passkey/begin`, auth.requireUser, (_req, res, next) => {
    void (async () => {
      try {
        const { user, sessionId } = consoleUserOf(res);
        const options = await webauthn.beginAuthentication({ userId: user.id, sessionKey: stepUpKey(sessionId) });
        res.set('Cache-Control', 'no-store').json(options);
      } catch (err) {
        next(err);
      }
    })();
  });

  /** Did they just prove it is them with something other than the password? */
  const steppedUp = async (input: {
    userId: string;
    sessionId: string;
    code?: unknown;
    passkey?: unknown;
  }): Promise<boolean> => {
    if (typeof input.code === 'string' && input.code.trim() !== '') {
      return totp.verify({ userId: input.userId, code: input.code });
    }
    if (input.passkey && typeof input.passkey === 'object') {
      const result = await webauthn.finishAuthentication({
        sessionKey: stepUpKey(input.sessionId),
        response: input.passkey as AuthenticationResponseJSON,
      });
      return result.ok && result.userId === input.userId;
    }
    return false;
  };

  // A-3: change your password (REQ-081).
  router.post(`${ACCOUNT_API}/password`, auth.requireUser, body, (req, res, next) => {
    void (async () => {
      try {
        const { user, sessionId, sessionUid } = consoleUserOf(res);
        const input = req.body as { currentPassword?: unknown; newPassword?: unknown; code?: unknown; passkey?: unknown };
        const currentPassword = typeof input.currentPassword === 'string' ? input.currentPassword : '';
        const newPassword = typeof input.newPassword === 'string' ? input.newPassword : '';
        const ip = clientIp(req);
        const keys = { account: user.email, ip };

        // Guessing the current password is guessing a password: the same throttle applies.
        const decision = await throttle.check(keys);
        if (!decision.allowed) {
          res.set('Retry-After', String(decision.retryAfterSeconds)).status(429).json({
            error: 'throttled',
            retryAfterSeconds: decision.retryAfterSeconds,
          });
          return;
        }

        const credential = await db.passwordCredential.findFirst({ where: { userId: user.id }, orderBy: { setAt: 'desc' } });
        if (!(await passwords.verify(credential?.argon2idHash, currentPassword))) {
          await throttle.recordFailure(keys);
          res.status(401).json({ error: 'wrong_password', message: 'That is not your current password.' });
          return;
        }
        await throttle.clear(keys);

        const policy = checkPassword(newPassword, { email: user.email, username: user.username, displayName: user.displayName });
        if (!policy.ok) {
          res.status(400).json({ error: 'invalid', problems: policy.problems });
          return;
        }

        // Holding a factor means using it here. Without this, a session left open on a shared
        // machine plus a known password is enough to take the account outright.
        if ((await verifiedFactorCount(db, user.id)) > 0 && !(await steppedUp({ userId: user.id, sessionId, ...input }))) {
          res.status(401).json({
            error: 'step_up_required',
            message: 'Confirm it is you with your passkey or a code from your authenticator app.',
          });
          return;
        }

        const argon2idHash = await hasher.hash(newPassword);
        await db.$transaction(async (tx) => {
          await tx.passwordCredential.deleteMany({ where: { userId: user.id } });
          await tx.passwordCredential.create({ data: { userId: user.id, argon2idHash } });
        });

        // Every other session belonged to the old password. This one stays: signing the person
        // out of the screen they are standing on helps nobody.
        const revoked = await sessions.revokeAll(user.id, sessionUid);
        await audit.write({
          event: AUDIT_EVENTS.passwordChanged,
          actorUserId: user.id,
          targetType: 'user',
          targetId: user.id,
          ip,
          userAgent: req.get('user-agent'),
          detail: { otherSessionsRevoked: revoked },
        });
        res.json({ ok: true, otherSessionsRevoked: revoked });
      } catch (err) {
        next(err);
      }
    })();
  });

  // A-5: where you are signed in (REQ-083).
  router.get(`${ACCOUNT_API}/sessions`, auth.requireUser, (_req, res, next) => {
    void (async () => {
      try {
        const { user, sessionUid } = consoleUserOf(res);
        const rows = await db.session.findMany({
          where: { userId: user.id, revokedAt: null, expiresAt: { gt: new Date() } },
          orderBy: { lastSeenAt: 'desc' },
          select: { id: true, ip: true, userAgent: true, createdAt: true, lastSeenAt: true, oidcSessionUid: true },
        });
        res.set('Cache-Control', 'no-store').json({
          sessions: rows.map(({ oidcSessionUid, ...row }) => ({
            ...row,
            current: oidcSessionUid !== null && oidcSessionUid === sessionUid,
          })),
        });
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post<{ id: string }>(`${ACCOUNT_API}/sessions/:id/revoke`, auth.requireUser, (req, res, next) => {
    void (async () => {
      try {
        const { user } = consoleUserOf(res);
        const row = await db.session.findFirst({ where: { id: req.params.id, userId: user.id, revokedAt: null } });
        if (!row) {
          res.status(404).json({ error: 'not_found' });
          return;
        }
        await sessions.end(row.oidcSessionUid);
        await db.session.update({ where: { id: row.id }, data: { revokedAt: new Date() } });
        await audit.write({
          event: AUDIT_EVENTS.sessionRevoked,
          actorUserId: user.id,
          targetType: 'session',
          targetId: row.id,
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
        });
        res.json({ revoked: true });
      } catch (err) {
        next(err);
      }
    })();
  });

  router.post(`${ACCOUNT_API}/sessions/revoke-others`, auth.requireUser, (req, res, next) => {
    void (async () => {
      try {
        const { user, sessionUid } = consoleUserOf(res);
        const revoked = await sessions.revokeAll(user.id, sessionUid);
        await audit.write({
          event: AUDIT_EVENTS.sessionRevoked,
          actorUserId: user.id,
          targetType: 'session',
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
          detail: { count: revoked, scope: 'others' },
        });
        res.json({ revoked });
      } catch (err) {
        next(err);
      }
    })();
  });

  return router;
}
