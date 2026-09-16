import express, { Router, type Request, type RequestHandler, type Response } from 'express';
import type Provider from 'oidc-provider';
import type { AdapterFactory } from 'oidc-provider';
import { AUDIT_EVENTS } from '../audit/events.js';
import { effectiveAccess } from '../authz/effective-roles.js';
import { clientIp, type AuditWriter } from '../audit/writer.js';
import type { Db } from '../db.js';
import type { Logger } from '../log.js';
import { readCookie } from '../security/cookies.js';
import { csrfMatches, csrfToken } from '../security/csrf.js';
import type { PasswordVerifier } from '../security/password.js';
import type { SessionControl } from '../security/sessions.js';
import type { Throttle } from '../security/throttle.js';
import { TRUSTED_DEVICE_DAYS, type TrustedDevices } from '../security/trusted-device.js';
import type { Totp } from '../security/totp.js';
import type { WebAuthn } from '../security/webauthn.js';
import type { Recovery } from '../setup/recovery.js';
import { renderContinueAsPage, renderLoginPage, renderRecoveryPage } from './fallback.js';
import { createFlowStore, type FlowStore, type LoginFlow } from './flow-store.js';
import { advance, isComplete, start, type Identity, type LoginState } from './machine.js';

// The interaction API the sign-in screens call (T-1.5, T-1.6). The console renders the screens;
// every decision is made here. The state machine is the only thing that can reach `complete`,
// and only `complete` calls the provider's interactionResult.

export const INTERACTION_API = '/api/interaction';
/** Must match `ROUTES.authorization` in the provider. */
const ROUTE_AUTHORIZATION = '/oidc/auth';
/** Where the provider sends a browser that needs to sign in. */
export const loginPath = (uid: string): string => `/login/${uid}`;

const FLOW_TTL_SECONDS = 60 * 60;
/** Said for a wrong password, an unknown email, and a suspended account alike (REQ-086). */
const GENERIC_CREDENTIALS_ERROR = 'That email and password do not match.';

export interface InteractionDeps {
  provider: Provider;
  adapterFactory: AdapterFactory;
  db: Db;
  passwords: PasswordVerifier;
  throttle: Throttle;
  audit: AuditWriter;
  logger: Logger;
  totp: Totp;
  webauthn: WebAuthn;
  trustedDevices: TrustedDevices;
  recovery: Recovery;
  sessions: SessionControl;
  /** Cookie name for the trusted-device token; `__Host-` prefixed on an https issuer. */
  deviceCookieName: string;
  /** False only for a local http issuer, where a Secure cookie would never be sent back. */
  secureCookies: boolean;
  operatorDisplayName: string;
  /** Our own issuer, for rebuilding an authorization request from its parameters. */
  issuer: string;
  /** Where the console build lives; the sign-in form is rendered into its shell. */
  consoleDist: string;
}

type Step = 'identify' | 'password' | 'factor' | 'trust' | 'done';

const stepFor = (state: LoginState): Step => {
  switch (state.name) {
    case 'awaiting_identifier':
      return 'identify';
    case 'awaiting_password':
      return 'password';
    case 'awaiting_factor':
      return 'factor';
    case 'awaiting_trusted_device':
      return 'trust';
    default:
      return 'done';
  }
};

/** What the second-factor screen offers, so it can lead with the passkey when there is one. */
const factorsOf = (state: LoginState): string[] =>
  state.name === 'awaiting_factor' ? [...state.identity.factors] : [];

export function interactionRouter(deps: InteractionDeps): Router {
  const { provider, db, passwords, throttle, audit, logger } = deps;
  const flows: FlowStore = createFlowStore(deps.adapterFactory);
  // Both shapes are accepted: the console posts JSON, and the same endpoints take an ordinary
  // form post so sign-in still works with JavaScript off (and for simple automated browsers).
  const asJson = express.json({ limit: '4kb' });
  const asForm = express.urlencoded({ extended: false, limit: '4kb' });
  const body: RequestHandler = (req, res, next) => {
    asJson(req, res, (err: unknown) => {
      if (err) next(err);
      else asForm(req, res, next);
    });
  };

  const wantsJson = (req: Request): boolean =>
    req.is('application/json') !== false || (req.get('accept') ?? '').includes('application/json');

  /** JSON for the console, a 303 back to the screen for a plain form post. */
  const reply = (req: Request, res: Response, uid: string, status: number, payload: Record<string, unknown>): void => {
    if (wantsJson(req)) {
      res.status(status).json(payload);
      return;
    }
    const redirectTo = typeof payload.redirectTo === 'string' ? payload.redirectTo : undefined;
    if (redirectTo) {
      res.redirect(303, redirectTo);
      return;
    }
    const query = new URLSearchParams();
    if (typeof payload.step === 'string') query.set('step', payload.step);
    if (typeof payload.error === 'string') query.set('error', payload.error);
    if (typeof payload.retryAfterSeconds === 'number') query.set('retryAfter', String(payload.retryAfterSeconds));
    res.redirect(303, `${loginPath(uid)}?${query.toString()}`);
  };

  const respondNoStore = (res: Response): void => {
    res.set('Cache-Control', 'no-store');
  };

  /** Loads the interaction and its flow, minting the flow on first sight. */
  async function context(req: Request, res: Response): Promise<{ uid: string; flow: LoginFlow; clientName: string; clientId: string } | undefined> {
    const details = await provider.interactionDetails(req, res);
    const existing = await flows.load(details.uid);
    const flow: LoginFlow = existing ?? { state: start(), csrf: csrfToken() };
    if (!existing) await flows.save(details.uid, flow, FLOW_TTL_SECONDS);
    const client = await provider.Client.find(String(details.params.client_id));
    const clientId = String(details.params.client_id);
    return { uid: details.uid, flow, clientName: client?.clientName ?? clientId, clientId };
  }

  /**
   * The person said "don't ask on this browser again". The cookie is written before the redirect
   * so it survives the hop back to the app, and never for an account that cannot sign in.
   */
  async function rememberDevice(req: Request, res: Response, accountId: string): Promise<void> {
    const issued = await deps.trustedDevices.issue({ userId: accountId, userAgent: req.get('user-agent') });
    if (!issued) return;
    res.cookie(deps.deviceCookieName, issued.token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: deps.secureCookies,
      path: '/',
      expires: issued.expiresAt,
    });
    await audit.write({
      event: AUDIT_EVENTS.deviceTrusted,
      actorUserId: accountId,
      targetType: 'user',
      targetId: accountId,
      ip: clientIp(req),
      userAgent: req.get('user-agent'),
      detail: { days: TRUSTED_DEVICE_DAYS },
    });
  }

  /**
   * Deny by default (REQ-051). An account with no grant for this client cannot sign in to it,
   * and finds that out before any interstitial — there is nothing to consent to, and nothing to
   * tell an attacker apart from a person who simply has not been given access.
   *
   * Returns the redirect back to the app when access is refused, or undefined to carry on.
   */
  async function denyWithoutGrant(req: Request, res: Response, uid: string, accountId: string, clientId: string): Promise<string | undefined> {
    const access = await effectiveAccess(db, { userId: accountId, clientId });
    if (access.hasGrant) return undefined;

    const redirectTo = await provider.interactionResult(req, res, {
      error: 'access_denied',
      error_description: 'You do not have access to this app.',
    });
    await flows.clear(uid);
    await audit.write({
      event: AUDIT_EVENTS.accessDenied,
      actorUserId: accountId,
      targetType: 'app',
      ip: clientIp(req),
      userAgent: req.get('user-agent'),
      detail: { clientId },
    });
    return redirectTo;
  }

  /** True when this person has never completed a sign-in to this app before (REQ-059). */
  async function firstTimeHere(accountId: string, clientId: string): Promise<boolean> {
    const grant = await db.grant.findFirst({
      where: { userId: accountId, app: { clientId } },
      select: { firstSignInAt: true },
    });
    return (grant?.firstSignInAt ?? null) === null;
  }

  async function finish(
    req: Request,
    res: Response,
    uid: string,
    accountId: string,
    amr: readonly string[],
    clientId: string,
    trustDevice = false,
  ): Promise<void> {
    const denied = await denyWithoutGrant(req, res, uid, accountId, clientId);
    if (denied) {
      reply(req, res, uid, 200, { step: 'done', redirectTo: denied });
      return;
    }
    if (trustDevice) await rememberDevice(req, res, accountId);
    const redirectTo = await provider.interactionResult(
      req,
      res,
      { login: { accountId, amr: [...amr] } },
      { mergeWithLastSubmission: false },
    );
    await flows.clear(uid);
    const now = new Date();
    await db.user.update({ where: { id: accountId }, data: { lastLoginAt: now } });
    // Per app, so the Access tab can say when somebody last used this one. `firstSignInAt` is
    // deliberately not set here: it is what decides whether the continue-as interstitial is still
    // due, and that screen comes *after* this point in the flow (REQ-059).
    await db.grant.updateMany({ where: { userId: accountId, app: { clientId } }, data: { lastSignInAt: now } });
    if (amr.includes('recovery')) {
      // One window, one sign-in. What is left is an account with no second factor, which the
      // account area nags about until they enrol one.
      await deps.recovery.spend(accountId);
      await audit.write({
        event: AUDIT_EVENTS.recoveryUsed,
        actorUserId: accountId,
        targetType: 'user',
        targetId: accountId,
        ip: clientIp(req),
        userAgent: req.get('user-agent'),
      });
    }
    await audit.write({
      event: AUDIT_EVENTS.loginSuccess,
      actorUserId: accountId,
      targetType: 'user',
      targetId: accountId,
      ip: clientIp(req),
      userAgent: req.get('user-agent'),
      detail: { amr },
    });
    reply(req, res, uid, 200, { step: 'done', redirectTo });
  }

  const router = Router();

  /**
   * D3 Auth shows no scope-consent screen (REQ-060): what a registered app may see is decided by
   * the grant an admin gave the person, not by a dialog nobody reads. The scopes are recorded and
   * the interaction continues — unless there is no grant, in which case nothing is recorded and
   * the answer is access_denied (REQ-051).
   */
  async function grantAndFinish(req: Request, res: Response, details: Awaited<ReturnType<Provider['interactionDetails']>>): Promise<string> {
    const accountId = details.session?.accountId ?? '';
    const clientId = String(details.params.client_id);

    // Already signed in, asking for a second app: the grant decides, before any screen.
    const denied = await denyWithoutGrant(req, res, details.uid, accountId, clientId);
    if (denied) return denied;

    const grant = details.grantId
      ? ((await provider.Grant.find(details.grantId)) ?? new provider.Grant({ accountId, clientId }))
      : new provider.Grant({ accountId, clientId });
    const missing = details.prompt.details as { missingOIDCScope?: string[]; missingOIDCClaims?: string[] };
    if (missing.missingOIDCScope) grant.addOIDCScope(missing.missingOIDCScope.join(' '));
    if (missing.missingOIDCClaims) grant.addOIDCClaims(missing.missingOIDCClaims);
    const grantId = await grant.save();
    return provider.interactionResult(req, res, { consent: { grantId } }, { mergeWithLastSubmission: true });
  }

  // The page the provider sends the browser to. A consent prompt is resolved here and redirected
  // straight back, so no screen flashes. Otherwise the console shell is served with a working
  // sign-in form already in the HTML; React takes over when it loads.
  router.get('/login/:uid', (req, res, next) => {
    void (async () => {
      try {
        const details = await provider.interactionDetails(req, res);
        if (details.prompt.name === 'consent') {
          const accountId = details.session?.accountId ?? '';
          const clientId = String(details.params.client_id);

          // Deny first, so somebody without access never sees the app's name on a screen.
          const denied = await denyWithoutGrant(req, res, details.uid, accountId, clientId);
          if (denied) {
            res.redirect(303, denied);
            return;
          }

          // First time in this app: say which account is about to be used, and offer a way out
          // (REQ-059). Every later sign-in resolves silently — there is no consent to give
          // (REQ-060), only an identity worth confirming once.
          if (await firstTimeHere(accountId, clientId)) {
            const person = await db.user.findUnique({ where: { id: accountId }, select: { username: true, displayName: true } });
            const client = await provider.Client.find(clientId);
            res.set('Cache-Control', 'no-store').type('html').send(
              renderContinueAsPage(deps.consoleDist, {
                uid: details.uid,
                csrf: (await flows.load(details.uid))?.csrf ?? csrfToken(),
                clientName: client?.clientName ?? clientId,
                username: person?.username ?? '',
                displayName: person?.displayName ?? '',
                operatorDisplayName: deps.operatorDisplayName,
              }),
            );
            return;
          }

          res.redirect(303, await grantAndFinish(req, res, details));
          return;
        }
        const ctx = await context(req, res);
        if (!ctx) {
          next();
          return;
        }
        res.set('Cache-Control', 'no-store').type('html').send(
          renderLoginPage(deps.consoleDist, {
            uid: ctx.uid,
            flow: ctx.flow,
            clientName: ctx.clientName,
            operatorDisplayName: deps.operatorDisplayName,
          }),
        );
      } catch {
        // No interaction for this uid (expired, or someone else's): let the console render its
        // own error screen.
        next();
      }
    })();
  });

  /**
   * Break-glass (REQ-122). Opening the link clears the factors and arms the account; it does not
   * sign anybody in on its own — the password is still required. ADR-003 says why.
   */
  router.get<{ token: string }>('/login/recover/:token', (req, res, next) => {
    void (async () => {
      try {
        respondNoStore(res);
        const claimed = await deps.recovery.claim(req.params.token);
        res
          .status(claimed.ok ? 200 : 410)
          .type('html')
          .send(renderRecoveryPage(deps.consoleDist, claimed, deps.operatorDisplayName));
      } catch (err) {
        next(err);
      }
    })();
  });

  // What the sign-in screen needs to render itself.
  router.get(`${INTERACTION_API}/:uid`, async (req, res, next) => {
    try {
      respondNoStore(res);
      const ctx = await context(req, res);
      if (!ctx) return;

      // Already signed in and standing on the continue-as interstitial (REQ-059): the screen
      // needs a different answer from "type your email".
      const details = await provider.interactionDetails(req, res);
      if (details.prompt.name === 'consent') {
        const person = await db.user.findUnique({
          where: { id: details.session?.accountId ?? '' },
          select: { username: true, displayName: true },
        });
        res.json({
          step: 'continue',
          csrf: ctx.flow.csrf,
          clientName: ctx.clientName,
          operatorDisplayName: deps.operatorDisplayName,
          username: person?.username ?? person?.displayName ?? '',
        });
        return;
      }

      res.json({
        step: stepFor(ctx.flow.state),
        csrf: ctx.flow.csrf,
        clientName: ctx.clientName,
        operatorDisplayName: deps.operatorDisplayName,
        factors: factorsOf(ctx.flow.state),
        ...(ctx.flow.attemptedEmail ? { email: ctx.flow.attemptedEmail } : {}),
      });
    } catch (err) {
      next(err);
    }
  });

  // Email step. Always answers "now enter your password", whether or not the account exists.
  router.post(`${INTERACTION_API}/:uid/identify`, body, async (req, res, next) => {
    try {
      respondNoStore(res);
      const ctx = await context(req, res);
      if (!ctx) return;
      const input = req.body as { email?: unknown; csrf?: unknown };
      if (!csrfMatches(ctx.flow.csrf, input.csrf)) {
        reply(req, res, ctx.uid, 403, { error: 'csrf' });
        return;
      }
      const email = typeof input.email === 'string' ? input.email.trim().toLowerCase() : '';
      if (!email.includes('@')) {
        reply(req, res, ctx.uid, 400, { error: 'invalid_email', message: 'Enter the email address you were invited with.' });
        return;
      }

      const user = await db.user.findUnique({
        where: { email },
        include: {
          passwordCredentials: { orderBy: { setAt: 'desc' }, take: 1 },
          totpCredentials: { where: { confirmedAt: { not: null } }, select: { id: true } },
          webauthnCredentials: { select: { credentialId: true } },
        },
      });
      // A trusted-device cookie only means something once we know whose account this is: it is
      // checked against *this* user, so somebody else's cookie skips nothing.
      const deviceTrusted =
        user && user.status === 'active'
          ? await deps.trustedDevices.verify({ userId: user.id, token: readCookie(req, deps.deviceCookieName) })
          : false;
      const recovering = user && user.status === 'active' ? await deps.recovery.armed(user.id) : false;

      const identity: Identity | undefined =
        user && user.status === 'active'
          ? {
              accountId: user.id,
              factors: [
                ...(user.totpCredentials.length > 0 ? (['totp'] as const) : []),
                ...(user.webauthnCredentials.length > 0 ? (['passkey'] as const) : []),
              ],
              deviceTrusted,
              recovering,
            }
          : undefined;

      // An unknown or suspended account still advances to the password screen: the difference is
      // only visible after a full Argon2id verify that always fails.
      const state = identity
        ? advance(ctx.flow.state, { type: 'identified', identity })
        : { name: 'awaiting_password' as const, identity: { accountId: '', factors: [], deviceTrusted: false } };

      await flows.save(ctx.uid, { ...ctx.flow, state, attemptedEmail: email }, FLOW_TTL_SECONDS);
      reply(req, res, ctx.uid, 200, { step: 'password', csrf: ctx.flow.csrf, email });
    } catch (err) {
      next(err);
    }
  });

  // Password step: throttle first, then one Argon2id verify, then the machine.
  router.post(`${INTERACTION_API}/:uid/password`, body, async (req, res, next) => {
    try {
      respondNoStore(res);
      const ctx = await context(req, res);
      if (!ctx) return;
      const input = req.body as { password?: unknown; csrf?: unknown };
      if (!csrfMatches(ctx.flow.csrf, input.csrf)) {
        reply(req, res, ctx.uid, 403, { error: 'csrf' });
        return;
      }
      if (ctx.flow.state.name !== 'awaiting_password') {
        reply(req, res, ctx.uid, 409, { error: 'wrong_step', step: stepFor(ctx.flow.state) });
        return;
      }

      const email = ctx.flow.attemptedEmail ?? '';
      const ip = clientIp(req);
      const keys = { account: email, ip };

      const decision = await throttle.check(keys);
      if (!decision.allowed) {
        res.set('Retry-After', String(decision.retryAfterSeconds));
        await audit.write({
          event: AUDIT_EVENTS.loginThrottled,
          ip,
          userAgent: req.get('user-agent'),
          detail: { email, scope: decision.scope, retryAfterSeconds: decision.retryAfterSeconds },
        });
        reply(req, res, ctx.uid, 429, { error: 'throttled', retryAfterSeconds: decision.retryAfterSeconds });
        return;
      }

      const accountId = ctx.flow.state.identity.accountId;
      const credential = accountId
        ? await db.passwordCredential.findFirst({ where: { userId: accountId }, orderBy: { setAt: 'desc' } })
        : null;
      const password = typeof input.password === 'string' ? input.password : '';
      // Always verify, even with no account: the decoy hash is what makes the timing uniform
      // (REQ-026), so this must not short-circuit.
      const verified = await passwords.verify(credential?.argon2idHash, password);
      const ok = accountId !== '' && verified;

      if (!ok) {
        await throttle.recordFailure(keys);
        await audit.write({
          event: AUDIT_EVENTS.loginFailure,
          ...(accountId ? { actorUserId: accountId, targetType: 'user' as const, targetId: accountId } : {}),
          ip,
          userAgent: req.get('user-agent'),
          detail: { email, reason: accountId ? 'bad_password' : 'unknown_account' },
        });
        reply(req, res, ctx.uid, 401, { error: 'invalid_credentials', message: GENERIC_CREDENTIALS_ERROR });
        return;
      }

      await throttle.clear(keys);
      const state = advance(ctx.flow.state, { type: 'password_verified' });
      if (!isComplete(state)) {
        await flows.save(ctx.uid, { ...ctx.flow, state }, FLOW_TTL_SECONDS);
        // The factors travel with the step: without them the screen cannot know to offer the
        // passkey, and would ask for a code the person may not have.
        reply(req, res, ctx.uid, 200, { step: stepFor(state), csrf: ctx.flow.csrf, factors: factorsOf(state) });
        return;
      }
      await finish(req, res, ctx.uid, state.accountId, state.amr, ctx.clientId);
    } catch (err) {
      next(err);
    }
  });

  // Second factor: a code from an authenticator app (REQ-033).
  router.post(`${INTERACTION_API}/:uid/totp`, body, async (req, res, next) => {
    try {
      respondNoStore(res);
      const ctx = await context(req, res);
      if (!ctx) return;
      const input = req.body as { code?: unknown; csrf?: unknown };
      if (!csrfMatches(ctx.flow.csrf, input.csrf)) {
        reply(req, res, ctx.uid, 403, { error: 'csrf' });
        return;
      }
      if (ctx.flow.state.name !== 'awaiting_factor') {
        reply(req, res, ctx.uid, 409, { error: 'wrong_step', step: stepFor(ctx.flow.state) });
        return;
      }

      const ip = clientIp(req);
      const keys = { account: ctx.flow.attemptedEmail ?? '', ip };
      const decision = await throttle.check(keys);
      if (!decision.allowed) {
        res.set('Retry-After', String(decision.retryAfterSeconds));
        reply(req, res, ctx.uid, 429, { error: 'throttled', retryAfterSeconds: decision.retryAfterSeconds });
        return;
      }

      const accountId = ctx.flow.state.identity.accountId;
      const verified = await deps.totp.verify({ userId: accountId, code: typeof input.code === 'string' ? input.code : '' });
      if (!verified) {
        await throttle.recordFailure(keys);
        await audit.write({
          event: AUDIT_EVENTS.loginFailure,
          actorUserId: accountId,
          targetType: 'user',
          targetId: accountId,
          ip,
          userAgent: req.get('user-agent'),
          detail: { reason: 'bad_totp' },
        });
        reply(req, res, ctx.uid, 401, { error: 'invalid_code', message: 'That code did not match. Try the next one.' });
        return;
      }

      await throttle.clear(keys);
      const state = advance(ctx.flow.state, { type: 'factor_verified', method: 'totp' });
      if (isComplete(state)) {
        await finish(req, res, ctx.uid, state.accountId, state.amr, ctx.clientId);
        return;
      }
      await flows.save(ctx.uid, { ...ctx.flow, state }, FLOW_TTL_SECONDS);
      reply(req, res, ctx.uid, 200, { step: stepFor(state), csrf: ctx.flow.csrf });
    } catch (err) {
      next(err);
    }
  });

  // Passkeys, both as a second factor and as a way in on their own (REQ-032, REQ-034).
  router.post(`${INTERACTION_API}/:uid/passkey/begin`, body, async (req, res, next) => {
    try {
      respondNoStore(res);
      const ctx = await context(req, res);
      if (!ctx) return;
      const known = ctx.flow.state.name === 'awaiting_factor' ? ctx.flow.state.identity.accountId : undefined;
      const options = await deps.webauthn.beginAuthentication({ sessionKey: ctx.uid, ...(known ? { userId: known } : {}) });
      res.json(options);
    } catch (err) {
      next(err);
    }
  });

  router.post(`${INTERACTION_API}/:uid/passkey/finish`, body, async (req, res, next) => {
    try {
      respondNoStore(res);
      const ctx = await context(req, res);
      if (!ctx) return;
      const input = req.body as { response?: unknown; csrf?: unknown };
      if (!csrfMatches(ctx.flow.csrf, input.csrf)) {
        reply(req, res, ctx.uid, 403, { error: 'csrf' });
        return;
      }

      const result = await deps.webauthn.finishAuthentication({
        sessionKey: ctx.uid,
        response: input.response as never,
      });
      if (!result.ok || !result.userId) {
        reply(req, res, ctx.uid, 401, { error: 'passkey_failed', message: 'That passkey was not accepted. Try again, or use your password.' });
        return;
      }

      const user = await db.user.findUnique({ where: { id: result.userId } });
      if (user?.status !== 'active') {
        reply(req, res, ctx.uid, 401, { error: 'passkey_failed', message: 'That passkey was not accepted.' });
        return;
      }

      const identity = { accountId: user.id, factors: [] as const, deviceTrusted: false };
      const state =
        ctx.flow.state.name === 'awaiting_factor'
          ? advance(ctx.flow.state, { type: 'factor_verified', method: 'passkey' })
          : advance(start(), { type: 'passkey_authenticated', identity });

      if (isComplete(state)) {
        await finish(req, res, ctx.uid, state.accountId, state.amr, ctx.clientId);
        return;
      }
      await flows.save(ctx.uid, { ...ctx.flow, state }, FLOW_TTL_SECONDS);
      reply(req, res, ctx.uid, 200, { step: stepFor(state), csrf: ctx.flow.csrf });
    } catch (err) {
      next(err);
    }
  });

  // "Don't ask again on this browser" (REQ-036). Either answer finishes the login; only "yes"
  // writes a cookie, and only for thirty days.
  router.post(`${INTERACTION_API}/:uid/trust`, body, async (req, res, next) => {
    try {
      respondNoStore(res);
      const ctx = await context(req, res);
      if (!ctx) return;
      const input = req.body as { trust?: unknown; csrf?: unknown };
      if (!csrfMatches(ctx.flow.csrf, input.csrf)) {
        reply(req, res, ctx.uid, 403, { error: 'csrf' });
        return;
      }
      if (ctx.flow.state.name !== 'awaiting_trusted_device') {
        reply(req, res, ctx.uid, 409, { error: 'wrong_step', step: stepFor(ctx.flow.state) });
        return;
      }
      // A form post sends the string "true"; the console sends a boolean. Anything else is "no".
      const trust = input.trust === true || input.trust === 'true';
      const state = advance(ctx.flow.state, { type: 'trusted_device_answered', trust });
      if (!isComplete(state)) throw new Error('the trusted-device answer must complete the login');
      await finish(req, res, ctx.uid, state.accountId, state.amr, ctx.clientId, state.trustDevice);
    } catch (err) {
      next(err);
    }
  });

  // The two answers to the continue-as interstitial (REQ-059).
  router.post(`${INTERACTION_API}/:uid/continue`, body, async (req, res, next) => {
    try {
      respondNoStore(res);
      const details = await provider.interactionDetails(req, res);
      const flow = await flows.load(details.uid);
      const input = req.body as { csrf?: unknown };
      // The flow is gone once the login completed, so a missing one means there is nothing to
      // check against and the interaction itself is the proof.
      if (flow && !csrfMatches(flow.csrf, input.csrf)) {
        reply(req, res, details.uid, 403, { error: 'csrf' });
        return;
      }

      const accountId = details.session?.accountId ?? '';
      const clientId = String(details.params.client_id);
      const denied = await denyWithoutGrant(req, res, details.uid, accountId, clientId);
      if (denied) {
        reply(req, res, details.uid, 200, { step: 'done', redirectTo: denied });
        return;
      }

      const now = new Date();
      await db.grant.updateMany({
        where: { userId: accountId, app: { clientId } },
        data: { firstSignInAt: now, lastSignInAt: now },
      });
      reply(req, res, details.uid, 200, { step: 'done', redirectTo: await grantAndFinish(req, res, details) });
    } catch (err) {
      next(err);
    }
  });

  /**
   * "Not you?" — end the session and start the app's authorization request again from the top.
   *
   * The interaction cannot simply be resumed: it is bound to the session that created it, and
   * the provider refuses the pair as a mismatch. So the request the app made is rebuilt from its
   * own parameters, which lands the person on the sign-in screen with the app none the wiser.
   */
  router.post(`${INTERACTION_API}/:uid/switch`, body, async (req, res, next) => {
    try {
      respondNoStore(res);
      const details = await provider.interactionDetails(req, res);
      const sessionUid = details.session?.uid;
      if (sessionUid) await deps.sessions.end(sessionUid);
      await db.session.updateMany({ where: { oidcSessionUid: sessionUid ?? '', revokedAt: null }, data: { revokedAt: new Date() } });
      await flows.clear(details.uid);

      const again = new URLSearchParams();
      for (const [key, value] of Object.entries(details.params)) {
        if (typeof value === 'string') again.set(key, value);
      }
      reply(req, res, details.uid, 200, { step: 'identify', redirectTo: `${deps.issuer}${ROUTE_AUTHORIZATION}?${again.toString()}` });
    } catch (err) {
      next(err);
    }
  });

  // "Not you?" and the browser back button: end the interaction without signing anybody in.
  router.post(`${INTERACTION_API}/:uid/abort`, body, async (req, res, next) => {
    try {
      respondNoStore(res);
      const ctx = await context(req, res);
      if (!ctx) return;
      const input = req.body as { csrf?: unknown };
      if (!csrfMatches(ctx.flow.csrf, input.csrf)) {
        reply(req, res, ctx.uid, 403, { error: 'csrf' });
        return;
      }
      const redirectTo = await provider.interactionResult(req, res, {
        error: 'access_denied',
        error_description: 'The person cancelled the sign-in.',
      });
      await flows.clear(ctx.uid);
      await audit.write({
        event: AUDIT_EVENTS.loginAborted,
        ip: clientIp(req),
        userAgent: req.get('user-agent'),
        detail: { email: ctx.flow.attemptedEmail },
      });
      reply(req, res, ctx.uid, 200, { step: 'done', redirectTo });
    } catch (err) {
      logger.debug({ err }, 'abort failed');
      next(err);
    }
  });

  return router;
}
