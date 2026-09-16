import { randomUUID } from 'node:crypto';
import type Provider from 'oidc-provider';
import { AUDIT_EVENTS } from '../audit/events.js';
import type { AuditWriter } from '../audit/writer.js';
import type { Db } from '../db.js';
import type { Logger } from '../log.js';

// Telling apps that somebody has been signed out (REQ-011, REQ-012, REQ-056).
//
// Revoking access in the console is worth nothing if the app the person is using never hears
// about it: their session there keeps working until a token happens to expire. So every event
// that should end somebody's access — logout, suspension, reset, a grant changed or revoked —
// posts a signed logout token to the apps involved.
//
// Delivery is best-effort by nature: the app may be down, or wrong, or slow. Three attempts, then
// the app is marked *slow revoke* in the audit trail, which is the honest description — the
// person is still signed out here, and the app will find out when its tokens next need renewing.
//
// The token is built by the provider (so it is a proper, signed logout token) but posted by us.
// `oidc-provider` refuses outright to post to loopback and private addresses — the right default
// for the internet, and impossible to test against a local listener. The same rule is enforced
// here, with one escape hatch: an issuer on `localhost` or a `.test` domain, which is by
// definition not production (RFC 6761).

export const ATTEMPTS = 3;
const BACKOFF_MS = [0, 250, 1000];
const TIMEOUT_MS = 2500;

/** Loopback, link-local and the private ranges — the addresses an app should not be able to probe. */
const PRIVATE_HOST = /^(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|\[?::1\]?$)/i;

export interface LogoutTarget {
  clientId: string;
  /** The session identifier that app knows this person by, when there is one. */
  sid?: string | undefined;
}

export interface Backchannel {
  /** Tells one app that this person is signed out. Resolves once delivered or given up on. */
  notify(input: { userId: string; clientId: string; sid?: string | undefined; reason: string }): Promise<boolean>;
  /** Every app this session was used with, from the session itself. */
  notifySession(input: { sessionUid: string; reason: string }): Promise<void>;
}

/** The client metadata we need; the published types do not carry the back-channel fields. */
type LogoutCapableClient = { backchannelLogoutUri?: string; backchannelLogoutSessionRequired?: boolean };

export interface BackchannelDeps {
  provider: Provider;
  audit: AuditWriter;
  logger: Logger;
  /** True only on a development or test issuer, where the apps live on loopback. */
  allowPrivateEndpoints?: boolean;
}

export function createBackchannel({ provider, audit, logger, allowPrivateEndpoints = false }: BackchannelDeps): Backchannel {

  /** Builds the signed logout token with the provider, then delivers it ourselves. */
  async function post(client: LogoutCapableClient, sub: string, sid: string | undefined): Promise<void> {
    const token = new provider.IdToken({ sub }, { client: client as never });
    token.set('events', { 'http://schemas.openid.net/event/backchannel-logout': {} });
    token.set('jti', randomUUID());
    if (client.backchannelLogoutSessionRequired && sid) token.set('sid', sid);
    // `mask` keeps the payload to what a logout token may carry: this is not an ID token.
    (token as unknown as { mask: Record<string, null> }).mask = { sub: null };

    const response = await fetch(client.backchannelLogoutUri ?? '', {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ logout_token: await token.issue({ use: 'logout' }) }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (response.status !== 200 && response.status !== 204) {
      throw new Error(`expected 200 from ${client.backchannelLogoutUri ?? ''}, got ${String(response.status)}`);
    }
  }

  const notify: Backchannel['notify'] = async ({ userId, clientId, sid, reason }) => {
    const client = (await provider.Client.find(clientId)) as LogoutCapableClient | undefined;
    if (!client?.backchannelLogoutUri) {
      // Nothing to deliver to. The console calls this *slow revoke*: access ends when the app's
      // tokens do, and an operator deserves to know which apps behave that way.
      await audit.write({
        event: AUDIT_EVENTS.logoutSlowRevoke,
        actorUserId: userId,
        targetType: 'app',
        detail: { clientId, reason },
      });
      return false;
    }

    if (!allowPrivateEndpoints && PRIVATE_HOST.test(new URL(client.backchannelLogoutUri).hostname)) {
      // An app could otherwise be registered to point at something on our own network and used
      // to probe it. The owner registers apps, but the owner is not the only reader of this log.
      logger.warn({ clientId }, 'refusing a back-channel logout to a private address');
      await audit.write({
        event: AUDIT_EVENTS.logoutFailed,
        actorUserId: userId,
        targetType: 'app',
        detail: { clientId, reason, error: 'private_endpoint' },
      });
      return false;
    }

    for (let attempt = 0; attempt < ATTEMPTS; attempt += 1) {
      if (BACKOFF_MS[attempt]) await new Promise((resolve) => setTimeout(resolve, BACKOFF_MS[attempt]));
      try {
        await post(client, userId, sid);
        await audit.write({
          event: AUDIT_EVENTS.logoutDelivered,
          actorUserId: userId,
          targetType: 'app',
          detail: { clientId, reason, attempt: attempt + 1 },
        });
        return true;
      } catch (err) {
        const cause = err instanceof Error ? (err.cause ?? err) : err;
        logger.warn(
          { err: cause instanceof Error ? `${cause.name}: ${cause.message}` : String(cause), clientId, attempt: attempt + 1 },
          'back-channel logout attempt failed',
        );
      }
    }

    await audit.write({
      event: AUDIT_EVENTS.logoutFailed,
      actorUserId: userId,
      targetType: 'app',
      detail: { clientId, reason, attempts: ATTEMPTS },
    });
    return false;
  };

  return {
    notify,

    async notifySession({ sessionUid, reason }) {
      const session = await provider.Session.findByUid(sessionUid).catch(() => undefined);
      const accountId = session?.accountId;
      if (!session || !accountId) return;

      // The session knows every app it was used with, and the identifier each of them was given.
      const authorizations = (session.authorizations ?? {}) as Record<string, { sid?: string }>;
      const targets: LogoutTarget[] = Object.entries(authorizations).map(([clientId, entry]) => ({ clientId, sid: entry.sid }));
      if (targets.length === 0) return;

      await Promise.all(targets.map((target) => notify({ userId: accountId, reason, ...target })));
    },
  };
}

/** Every app this person could be signed in to right now, for the events that are not one session. */
export async function appsFor(db: Db, userId: string): Promise<string[]> {
  const grants = await db.grant.findMany({
    where: { userId, app: { enabled: true } },
    select: { app: { select: { clientId: true } } },
  });
  return grants.map((grant) => grant.app.clientId);
}
