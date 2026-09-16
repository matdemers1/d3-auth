import express, { Router, type Request, type RequestHandler, type Response } from 'express';
import type Provider from 'oidc-provider';
import type { AdapterFactory } from 'oidc-provider';
import { AUDIT_EVENTS } from '../audit/events.js';
import { clientIp, type AuditWriter } from '../audit/writer.js';
import type { Db } from '../db.js';
import type { Logger } from '../log.js';
import { csrfMatches, csrfToken } from '../security/csrf.js';
import type { PasswordVerifier } from '../security/password.js';
import type { Throttle } from '../security/throttle.js';
import { renderLoginPage } from './fallback.js';
import { createFlowStore, type FlowStore, type LoginFlow } from './flow-store.js';
import { advance, isComplete, start, type Identity, type LoginState } from './machine.js';

// The interaction API the sign-in screens call (T-1.5, T-1.6). The console renders the screens;
// every decision is made here. The state machine is the only thing that can reach `complete`,
// and only `complete` calls the provider's interactionResult.

export const INTERACTION_API = '/api/interaction';
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
  operatorDisplayName: string;
  /** Where the console build lives; the sign-in form is rendered into its shell. */
  consoleDist: string;
}

type Step = 'identify' | 'password' | 'done';

const stepFor = (state: LoginState): Step => {
  switch (state.name) {
    case 'awaiting_identifier':
      return 'identify';
    case 'awaiting_password':
      return 'password';
    default:
      return 'done';
  }
};

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
  async function context(req: Request, res: Response): Promise<{ uid: string; flow: LoginFlow; clientName: string } | undefined> {
    const details = await provider.interactionDetails(req, res);
    const existing = await flows.load(details.uid);
    const flow: LoginFlow = existing ?? { state: start(), csrf: csrfToken() };
    if (!existing) await flows.save(details.uid, flow, FLOW_TTL_SECONDS);
    const client = await provider.Client.find(String(details.params.client_id));
    return { uid: details.uid, flow, clientName: client?.clientName ?? String(details.params.client_id) };
  }

  async function finish(req: Request, res: Response, uid: string, accountId: string, amr: readonly string[]): Promise<void> {
    const redirectTo = await provider.interactionResult(
      req,
      res,
      { login: { accountId, amr: [...amr] } },
      { mergeWithLastSubmission: false },
    );
    await flows.clear(uid);
    await db.user.update({ where: { id: accountId }, data: { lastLoginAt: new Date() } });
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
   * D3 Auth shows no scope-consent screen (REQ-060): a registered app's access is decided by the
   * grant an admin gave the person, which Phase 3 enforces here. For now the missing scopes and
   * claims are recorded and the interaction continues.
   */
  async function grantAndFinish(req: Request, res: Response, details: Awaited<ReturnType<Provider['interactionDetails']>>): Promise<string> {
    const accountId = details.session?.accountId ?? '';
    const clientId = String(details.params.client_id);
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

  // What the sign-in screen needs to render itself.
  router.get(`${INTERACTION_API}/:uid`, async (req, res, next) => {
    try {
      respondNoStore(res);
      const ctx = await context(req, res);
      if (!ctx) return;
      res.json({
        step: stepFor(ctx.flow.state),
        csrf: ctx.flow.csrf,
        clientName: ctx.clientName,
        operatorDisplayName: deps.operatorDisplayName,
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
      const identity: Identity | undefined =
        user && user.status === 'active'
          ? {
              accountId: user.id,
              factors: [
                ...(user.totpCredentials.length > 0 ? (['totp'] as const) : []),
                ...(user.webauthnCredentials.length > 0 ? (['passkey'] as const) : []),
              ],
              deviceTrusted: false,
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
        // Second factors arrive in Phase 2; until then nothing else can reach this branch.
        await flows.save(ctx.uid, { ...ctx.flow, state }, FLOW_TTL_SECONDS);
        reply(req, res, ctx.uid, 200, { step: stepFor(state), csrf: ctx.flow.csrf });
        return;
      }
      await finish(req, res, ctx.uid, state.accountId, state.amr);
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
