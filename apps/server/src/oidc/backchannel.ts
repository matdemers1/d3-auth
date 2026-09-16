import { randomUUID } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
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
//
// The rule is checked against the addresses the hostname *resolves to*, not the hostname itself.
// A name is whatever its DNS says it is; `internal.example.com` can point at 10.0.0.5 as easily as
// `10.0.0.5` can be typed.

export const ATTEMPTS = 3;
const BACKOFF_MS = [0, 250, 1000];
const TIMEOUT_MS = 2500;

/** Loopback, link-local, private, shared and reserved ranges — the addresses an app must not probe. */
const PRIVATE = new BlockList();
for (const [network, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
] as const) PRIVATE.addSubnet(network, prefix, 'ipv4');
for (const [network, prefix] of [['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['2001:db8::', 32]] as const) {
  PRIVATE.addSubnet(network, prefix, 'ipv6');
}

const isPrivateAddress = (address: string): boolean => {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address)?.[1];
  if (mapped) return PRIVATE.check(mapped, 'ipv4');
  return PRIVATE.check(address, isIP(address) === 6 ? 'ipv6' : 'ipv4');
};

/** True when any address this URL's host resolves to is one we must not post to. Unresolvable counts. */
export async function isPrivateDestination(url: string): Promise<boolean> {
  const host = new URL(url).hostname.replace(/^\[|\]$/g, '');
  if (isIP(host)) return isPrivateAddress(host);
  try {
    const addresses = await lookup(host, { all: true, verbatim: true });
    return addresses.length === 0 || addresses.some((entry) => isPrivateAddress(entry.address));
  } catch {
    return true;
  }
}

export interface LogoutTarget {
  clientId: string;
  /** The session identifier that app knows this person by, when there is one. */
  sid?: string | undefined;
}

export interface Backchannel {
  /**
   * Delivers to an already-found client, with the retries and audit rows. The provider's own
   * sign-out path is routed here on test issuers, where its guard cannot work (see service.ts).
   */
  deliver(input: { client: LogoutCapableClient & { clientId: string }; userId: string; sid?: string | undefined; reason: string }): Promise<boolean>;
  /** Tells one app that this person is signed out. Resolves once delivered or given up on. */
  notify(input: { userId: string; clientId: string; sid?: string | undefined; reason: string }): Promise<boolean>;
  /** Every app this session was used with, from the session itself. */
  notifySession(input: { sessionUid: string; reason: string }): Promise<void>;
}

/** The client metadata we need; the published types do not carry the back-channel fields. */
export type LogoutCapableClient = { backchannelLogoutUri?: string; backchannelLogoutSessionRequired?: boolean };

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

  const deliver: Backchannel['deliver'] = async ({ client, userId, sid, reason }) => {
    const clientId = client.clientId;
    if (!allowPrivateEndpoints && (await isPrivateDestination(client.backchannelLogoutUri ?? ''))) {
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

  const notify: Backchannel['notify'] = async ({ userId, clientId, sid, reason }) => {
    const client = (await provider.Client.find(clientId)) as (LogoutCapableClient & { clientId: string }) | undefined;
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
    return deliver({ client, userId, sid, reason });
  };

  return {
    deliver,
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

/**
 * The other half of sign-out delivery: when a person signs out at the provider, the *provider*
 * sends the logout tokens (`end_session` calls `client.backchannelLogout`). That path is the
 * library's, with its own guard against private addresses — resolved per socket, stronger than
 * ours, and not something to replace on a real issuer. What it does not do is write the audit
 * rows REQ-110 asks for, so those are added from its events.
 *
 * On a test issuer the library's guard can never pass, because every app lives on a private
 * network. There, and only there, the provider's delivery is routed through ours, so a sign-out
 * in development or in the conformance suite reaches the app the way it will in production.
 */
export function installSignOutDelivery(provider: Provider, backchannel: Backchannel, audit: AuditWriter, testIssuer: boolean): void {
  if (testIssuer) {
    const prototype = (provider.Client as unknown as { prototype: { backchannelLogout: (sub: string, sid: string) => Promise<void> } }).prototype;
    prototype.backchannelLogout = async function (this: LogoutCapableClient & { clientId: string }, sub: string, sid: string) {
      const delivered = await backchannel.deliver({ client: this, userId: sub, sid, reason: 'signed_out' });
      if (!delivered) throw new Error(`back-channel logout to ${this.clientId} was not delivered`);
    };
    return;
  }

  type ClientLike = { clientId: string };
  provider.on('backchannel.success', (_ctx: unknown, client: ClientLike, accountId: string) => {
    void audit.write({ event: AUDIT_EVENTS.logoutDelivered, actorUserId: accountId, targetType: 'app', detail: { clientId: client.clientId, reason: 'signed_out' } });
  });
  provider.on('backchannel.error', (_ctx: unknown, err: Error, client: ClientLike, accountId: string) => {
    void audit.write({
      event: AUDIT_EVENTS.logoutFailed,
      actorUserId: accountId,
      targetType: 'app',
      detail: { clientId: client.clientId, reason: 'signed_out', error: err.message },
    });
  });
}
