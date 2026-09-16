import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { AdapterFactory } from 'oidc-provider';
import type { Db } from '../db.js';
import { readCookie } from '../security/cookies.js';
import { mustHoldFactor } from '../security/factors.js';
import type { UserModel as User } from '../generated/prisma/models.js';
import { COOKIE_NAMES, cookieNamesFor } from '../oidc/provider.js';

// Who is asking, for the console and account APIs.
//
// The console is first-party and shares an origin with the provider, so it rides the SSO session
// rather than holding a token of its own: the session cookie names a server-side session, which
// names a user. The cookie value is an unguessable identifier that only exists in our own store,
// so a forged one simply is not found.
//
// Every API here also demands a same-origin fetch (Sec-Fetch-Site), which is what stops another
// site from driving these endpoints with the browser's cookie.

export interface ConsoleUser {
  user: User;
  sessionId: string;
  /** The provider's session uid, which is what our own session rows are keyed by. */
  sessionUid: string | undefined;
  /** When this session signed in. */
  authTime?: Date | undefined;
}

export const isAdmin = (user: User): boolean => mustHoldFactor(user.kind);

/** The user a guard has already established. Only valid inside a guarded handler. */
export const consoleUserOf = (res: Response): ConsoleUser => {
  const found = res.locals.consoleUser as ConsoleUser | undefined;
  if (!found) throw new Error('consoleUserOf called outside a guarded route');
  return found;
};

export interface ConsoleAuth {
  /** The signed-in user, or undefined. Never throws. */
  current(req: Request): Promise<ConsoleUser | undefined>;
  requireUser: RequestHandler;
  requireAdmin: RequestHandler;
  requireOwner: RequestHandler;
  /** Owner, and proved it within the step-up window (REQ-037). */
  requireFreshOwner: RequestHandler;
}

/** Five minutes: long enough to finish what you started, short enough to matter. */
export const STEP_UP_WINDOW_MS = 5 * 60 * 1000;

export function createConsoleAuth(db: Db, adapterFactory: AdapterFactory, secureCookies: boolean): ConsoleAuth {
  const sessions = adapterFactory('Session');
  const names = cookieNamesFor(secureCookies);

  const current = async (req: Request): Promise<ConsoleUser | undefined> => {
    const sessionId = readCookie(req, names.session) ?? readCookie(req, COOKIE_NAMES.session);
    if (!sessionId) return undefined;
    const payload = (await sessions.find(sessionId)) as { accountId?: string; uid?: string; loginTs?: number } | undefined;
    const accountId = payload?.accountId;
    if (!accountId) return undefined;
    const user = await db.user.findUnique({ where: { id: accountId } });
    // A suspended account keeps its session row but loses the console (REQ-041).
    if (!user || user.status !== 'active') return undefined;
    return {
      user,
      sessionId,
      sessionUid: payload.uid,
      // When they last proved who they were, which is what owner-only actions check (REQ-037).
      authTime: typeof payload.loginTs === 'number' ? new Date(payload.loginTs * 1000) : undefined,
    };
  };

  /** A cross-site fetch never gets to act on the session, whatever the cookie says. */
  const sameOrigin = (req: Request): boolean => {
    const site = req.get('sec-fetch-site');
    return site === undefined || site === 'same-origin' || site === 'none';
  };

  const guard =
    (allow: (user: User) => boolean): RequestHandler =>
    (req: Request, res: Response, next: NextFunction) => {
      void (async () => {
        if (!sameOrigin(req)) {
          res.status(403).json({ error: 'cross_site' });
          return;
        }
        const found = await current(req);
        if (!found) {
          res.status(401).json({ error: 'sign_in_required' });
          return;
        }
        if (!allow(found.user)) {
          res.status(403).json({ error: 'not_allowed' });
          return;
        }
        res.locals.consoleUser = found;
        next();
      })();
    };

  /**
   * Owner-only actions need proof that the person at the keyboard is still the owner (REQ-037).
   *
   * A session left open on a desk is the threat here: everything behind this guard changes what
   * the whole system trusts — which apps exist, which keys sign, what the settings are — and a
   * borrowed session should not be enough. Signing in counts as proof for five minutes; after
   * that they re-prove it, with a password and a factor if they have one.
   */
  const requireFreshOwner: RequestHandler = (req, res, next) => {
    void (async () => {
      const found = await current(req);
      if (!found) {
        res.status(401).json({ error: 'sign_in_required' });
        return;
      }
      if (!sameOrigin(req)) {
        res.status(403).json({ error: 'cross_site' });
        return;
      }
      if (found.user.kind !== 'owner') {
        res.status(403).json({ error: 'not_allowed' });
        return;
      }

      const row = found.sessionUid
        ? await db.session.findUnique({ where: { oidcSessionUid: found.sessionUid }, select: { steppedUpAt: true } })
        : null;
      const proved = [row?.steppedUpAt, found.authTime].filter((at): at is Date => at instanceof Date);
      const freshest = proved.sort((a, b) => b.getTime() - a.getTime())[0];
      if (!freshest || Date.now() - freshest.getTime() > STEP_UP_WINDOW_MS) {
        res.status(401).json({
          error: 'step_up_required',
          message: 'Confirm it is you before changing something this important.',
        });
        return;
      }

      res.locals.consoleUser = found;
      next();
    })();
  };

  return {
    current,
    requireUser: guard(() => true),
    requireAdmin: guard(isAdmin),
    requireOwner: guard((user) => user.kind === 'owner'),
    requireFreshOwner,
  };
}
