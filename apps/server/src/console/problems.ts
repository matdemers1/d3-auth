import { Router, type RequestHandler } from 'express';
import { bearerOf } from './bearer.js';

// problem+json for a native app (AUTH-T-9.6, the D3 App contract). The console reads
// `{ error, message }` and keeps doing so; a request carrying a Bearer token, or asking for
// application/problem+json, gets the same refusal
// as RFC 9457, typed from the contract's registry, so D3 Constellation reads every product's
// refusals one way. Converted here, once, rather than in every route — a route added later is
// covered without anybody remembering to.

const BASE = 'https://d3cloud.io/problems/';

/** Our refusal codes that the contract registers, and the status the registry gives them. */
const REGISTERED: Readonly<Record<string, { type: string; status?: number }>> = {
  step_up_required: { type: 'step_up_required', status: 403 },
  factor_required: { type: 'step_up_required', status: 403 },
  throttled: { type: 'throttled' },
  sign_in_required: { type: 'session_revoked', status: 401 },
  not_allowed: { type: 'forbidden_role', status: 403 },
  wrong_password: { type: 'invalid_credentials' },
  wrong_code: { type: 'invalid_code' },
  invalid_or_expired: { type: 'invite_invalid', status: 410 },
  last_factor: { type: 'last_factor' },
  owner_protected: { type: 'owner_protected' },
  not_yourself: { type: 'not_yourself' },
  taken: { type: 'taken' },
  already_a_user: { type: 'already_a_user' },
  already_exists: { type: 'already_exists' },
};

const TITLES: Readonly<Record<string, string>> = {
  step_up_required: 'Confirm it’s you',
  session_revoked: 'Sign in again',
  forbidden_role: 'You can’t do that here',
  throttled: 'Too many attempts',
};

export function problemsForBearer(): RequestHandler {
  return (req, res, next) => {
    // A Bearer token, or a client that asks for problems by name (content negotiation): the
    // console sends neither.
    const wantsProblems = bearerOf(req) !== null || (req.get('accept') ?? '').includes('application/problem+json');
    if (!req.path.startsWith('/api/') || !wantsProblems) {
      next();
      return;
    }
    const json = res.json.bind(res);
    res.json = (body: unknown) => {
      if (res.statusCode < 400 || body === null || typeof body !== 'object' || Array.isArray(body)) return json(body);
      const { error, message, retryAfterSeconds, ...rest } = body as Record<string, unknown>;
      const code = typeof error === 'string' ? error : 'about:blank';
      const known = REGISTERED[code];
      const status = known?.status ?? res.statusCode;
      const type = known ? `${BASE}${known.type}` : 'about:blank';
      const problem: Record<string, unknown> = {
        type,
        title: (known && TITLES[known.type]) ?? (typeof message === 'string' ? message : 'That didn’t work'),
        status,
        ...(typeof message === 'string' ? { detail: message } : {}),
        // The original code stays readable, registered or not.
        code,
        ...(typeof retryAfterSeconds === 'number' ? { retryAfter: retryAfterSeconds } : {}),
        ...rest,
      };
      res.status(status).type('application/problem+json');
      return res.send(JSON.stringify(problem));
    };
    next();
  };
}

/** As a router, for the service's router list: first, so it sees every API response. */
export function problemsRouter(): Router {
  return Router().use(problemsForBearer());
}
