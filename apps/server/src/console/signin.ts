import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { Router, type Request, type Response } from 'express';
import { readCookie } from '../security/cookies.js';
import { ROUTES } from '../oidc/provider.js';
import { isAdmin, type ConsoleAuth } from './auth.js';
import { CONSOLE_CLIENT_ID, SIGNIN_CALLBACK_PATH, SIGNIN_PATH } from './console-client.js';

// Signing in to the console directly (ADR-005).
//
//   GET /signin?next=/admin/people   → an authorization request for the console's own client
//   GET /signin/callback             → back where they were going
//
// The code that comes back is never redeemed. Its PKCE verifier is thrown away the moment the
// challenge is computed, so nobody — this server included — can exchange it; what the flow is for
// is the SSO session the provider sets along the way, which is what the console runs on.
//
// `next` is only ever a path on this origin under /admin or /account. Anything else lands on the
// default, so the sign-in link cannot be turned into a redirect to somewhere else.

const STATE_COOKIE_SECURE = '__Host-d3auth_signin';
const STATE_COOKIE_PLAIN = 'd3auth_signin';
const STATE_MAX_AGE_MS = 10 * 60 * 1000;

/** A same-origin path under the console or account surfaces, or undefined. */
export function safeNext(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length > 512) return undefined;
  if (!/^\/(admin|account)(?:[/?#]|$)/.test(value)) return undefined;
  // Backslashes and control characters are how "a path" becomes "another host" in some browsers.
  for (const char of value) {
    if (char === '\\' || char.charCodeAt(0) < 0x20 || char.charCodeAt(0) === 0x7f) return undefined;
  }
  return value;
}

const sameString = (a: string, b: string): boolean => {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
};

export function signinRouter(deps: { issuer: string; auth: ConsoleAuth; secureCookies: boolean }): Router {
  const router = Router();
  const origin = new URL(deps.issuer).origin;
  const cookieName = deps.secureCookies ? STATE_COOKIE_SECURE : STATE_COOKIE_PLAIN;

  const landing = async (req: Request, next: string | undefined): Promise<string> => {
    if (next) return next;
    const found = await deps.auth.current(req);
    return found && isAdmin(found.user) ? '/admin' : '/account';
  };

  const clearState = (res: Response): void => {
    res.clearCookie(cookieName, { httpOnly: true, sameSite: 'lax', secure: deps.secureCookies, path: '/' });
  };

  // The bare origin and the bare /login have nothing to show on their own; both mean "sign in".
  router.get(['/', '/login'], (_req, res) => {
    res.redirect(302, SIGNIN_PATH);
  });

  router.get(SIGNIN_PATH, (req, res, nextHandler) => {
    void (async () => {
      try {
        const next = safeNext(req.query.next);
        res.set('Cache-Control', 'no-store');

        // Already signed in: nothing to ask.
        if (await deps.auth.current(req)) {
          res.redirect(303, await landing(req, next));
          return;
        }

        const state = randomBytes(24).toString('base64url');
        const challenge = createHash('sha256').update(randomBytes(32).toString('base64url')).digest('base64url');
        res.cookie(cookieName, `${state}.${Buffer.from(next ?? '').toString('base64url')}`, {
          httpOnly: true,
          sameSite: 'lax',
          secure: deps.secureCookies,
          path: '/',
          maxAge: STATE_MAX_AGE_MS,
        });

        const authorize = new URL(`${origin}${ROUTES.authorization}`);
        authorize.search = new URLSearchParams({
          client_id: CONSOLE_CLIENT_ID,
          response_type: 'code',
          scope: 'openid',
          redirect_uri: `${origin}${SIGNIN_CALLBACK_PATH}`,
          state,
          code_challenge: challenge,
          code_challenge_method: 'S256',
        }).toString();
        res.redirect(303, authorize.toString());
      } catch (err) {
        nextHandler(err);
      }
    })();
  });

  router.get(SIGNIN_CALLBACK_PATH, (req, res, nextHandler) => {
    void (async () => {
      try {
        res.set('Cache-Control', 'no-store');
        const stored = readCookie(req, cookieName) ?? '';
        const [expected = '', encodedNext = ''] = stored.split('.');
        clearState(res);

        const state = typeof req.query.state === 'string' ? req.query.state : '';
        // A callback this browser did not start (or started too long ago) proves nothing. Start again
        // rather than show an error: the sign-in form is what they were after.
        if (!expected || !state || !sameString(expected, state)) {
          res.redirect(303, SIGNIN_PATH);
          return;
        }
        if (typeof req.query.error === 'string') {
          res.redirect(303, '/login/error');
          return;
        }

        const next = safeNext(Buffer.from(encodedNext, 'base64url').toString('utf8'));
        res.redirect(303, await landing(req, next));
      } catch (err) {
        nextHandler(err);
      }
    })();
  });

  return router;
}
