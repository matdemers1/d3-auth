import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';

// Verifying a back-channel logout token (REQ-098, REQ-095).
//
// A logout token arrives unauthenticated, from anybody who can reach the endpoint, and asks the
// app to end somebody's session. So every check matters — and one of them is unusual enough to
// state plainly: a logout token must **not** carry a `nonce`. That is what stops an ID token
// from being replayed at the logout endpoint to sign somebody out at will.

export const LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

/** Asymmetric only. `alg=none` has no signature; HMAC means the verifier could have forged it. */
export const ALLOWED_ALGORITHMS = ['ES256', 'RS256'] as const;

/** Anything jose can verify against: a remote key set, or a local one in a test. */
export type KeyResolver = Parameters<typeof jwtVerify>[1];

export interface LogoutTokenOptions {
  issuer: string;
  clientId: string;
  /** Defaults to the issuer's `/oidc/jwks`; pass one to reuse a key set across calls. */
  jwks?: KeyResolver;
  /** How old a logout token may be. Two minutes, like the provider's own lifetime. */
  maxAgeSeconds?: number;
}

export interface VerifiedLogout {
  /** Which session to end. Absent when the provider signs out every session for `sub`. */
  sid?: string;
  sub: string;
  /** For idempotency: the same event delivered twice carries the same `jti`. */
  jti: string;
}

export class LogoutTokenError extends Error {
  constructor(readonly reason: string) {
    super(`logout token rejected: ${reason}`);
    this.name = 'LogoutTokenError';
  }
}

export const jwksFor = (issuer: string): KeyResolver =>
  createRemoteJWKSet(new URL(`${issuer.replace(/\/$/, '')}/oidc/jwks`));

/** Checks a logout token completely, or throws saying which rule it broke. */
export async function verifyLogoutToken(token: string, options: LogoutTokenOptions): Promise<VerifiedLogout> {
  const keys = options.jwks ?? jwksFor(options.issuer);
  const maxAge = options.maxAgeSeconds ?? 120;

  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, keys, {
      issuer: options.issuer,
      audience: options.clientId,
      algorithms: [...ALLOWED_ALGORITHMS],
      typ: 'logout+jwt',
    }));
  } catch (err) {
    throw new LogoutTokenError(err instanceof Error ? err.message : 'signature or claims');
  }

  // An ID token would carry a nonce. Accepting one here would let a token minted for sign-in be
  // replayed as a sign-out.
  if ('nonce' in payload) throw new LogoutTokenError('a logout token must not carry a nonce');

  const events = payload.events as Record<string, unknown> | undefined;
  if (!events || typeof events !== 'object' || !(LOGOUT_EVENT in events)) {
    throw new LogoutTokenError('not a back-channel logout event');
  }

  const issuedAt = typeof payload.iat === 'number' ? payload.iat : 0;
  if (!issuedAt || Math.floor(Date.now() / 1000) - issuedAt > maxAge) throw new LogoutTokenError('too old');

  const sub = typeof payload.sub === 'string' ? payload.sub : '';
  const sid = typeof payload.sid === 'string' ? payload.sid : undefined;
  if (!sub && !sid) throw new LogoutTokenError('names neither a subject nor a session');

  const jti = typeof payload.jti === 'string' ? payload.jti : '';
  if (!jti) throw new LogoutTokenError('has no jti, so it cannot be applied once');

  return { sub, jti, ...(sid ? { sid } : {}) };
}

export interface BackchannelHandlerOptions extends LogoutTokenOptions {
  /** End the session this token names. Called at most once per `jti`. */
  endSession: (logout: VerifiedLogout) => Promise<void> | void;
  /** Remembers which events have been applied. Swap in Redis or a table for more than one process. */
  seen?: { has(jti: string): boolean; add(jti: string): void };
}

/** Keeps the last few thousand `jti`s. Enough for one process; not a substitute for a store. */
export function inMemorySeen(limit = 5000): NonNullable<BackchannelHandlerOptions['seen']> {
  const seen = new Set<string>();
  return {
    has: (jti) => seen.has(jti),
    add: (jti) => {
      if (seen.size >= limit) seen.delete(seen.values().next().value ?? '');
      seen.add(jti);
    },
  };
}

/**
 * The handler an app mounts at its back-channel endpoint (REQ-099).
 *
 * Idempotent by `jti`, because delivery retries: the provider tries three times, and a second
 * arrival of the same event must not end a session the person has since started again.
 */
export function createBackchannelHandler(options: BackchannelHandlerOptions) {
  const seen = options.seen ?? inMemorySeen();

  return async function handle(logoutToken: string): Promise<{ ok: boolean; repeated?: boolean; reason?: string }> {
    let verified: VerifiedLogout;
    try {
      verified = await verifyLogoutToken(logoutToken, options);
    } catch (err) {
      return { ok: false, reason: err instanceof LogoutTokenError ? err.reason : 'invalid' };
    }

    if (seen.has(verified.jti)) return { ok: true, repeated: true };
    seen.add(verified.jti);
    await options.endSession(verified);
    return { ok: true };
  };
}
