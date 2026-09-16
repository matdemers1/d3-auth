import type Provider from 'oidc-provider';
import type { KoaContextWithOIDC } from 'oidc-provider';
import { AUDIT_EVENTS } from '../audit/events.js';
import type { AuditWriter } from '../audit/writer.js';
import type { Db } from '../db.js';
import type { Logger } from '../log.js';

// Our own session rows (REQ-030, REQ-045). The provider owns the SSO cookie; this mirrors it into
// the table behind the Sessions & devices screen, recording IP, user agent and last-seen.
//
// This runs as provider middleware rather than an event listener, so the row and its audit event
// are written *before* the response goes out. An event listener would be fire-and-forget: the
// sign-in would answer while the record of it was still in flight, which is not what
// "every auth event writes an audit row" means.
//
// The provider regenerates the session identifier when an interaction completes and again at
// logout (oidc-provider's resume and end_session both call resetIdentifier), so a fixated
// pre-login identifier cannot survive sign-in.

export const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;

export function recordSessions(provider: Provider, db: Db, audit: AuditWriter, logger: Logger): void {
  provider.use(async (raw, next) => {
    const ctx = raw as unknown as KoaContextWithOIDC;
    await next();

    // Unmatched provider routes (a 404) never get an `oidc` context, whatever the types say.
    const oidc = ctx.oidc as KoaContextWithOIDC['oidc'] | undefined;
    if (!oidc) return;

    const ip = ctx.get('cf-connecting-ip') || ctx.ip || null;
    const userAgent = ctx.get('user-agent') || null;

    try {
      const session = oidc.session;

      // Logout. The context still holds the session object at this point — the provider has
      // destroyed the stored one — so ask the store whether it survived rather than trusting it.
      if (oidc.route === 'end_session_confirm' && session?.uid) {
        const stored = await provider.Session.findByUid(session.uid).catch(() => undefined);
        if (!stored?.accountId) {
          const { count } = await db.session.updateMany({
            where: { oidcSessionUid: session.uid, revokedAt: null },
            data: { revokedAt: new Date() },
          });
          if (count > 0) {
            await audit.write({
              event: AUDIT_EVENTS.logout,
              actorUserId: session.accountId ?? null,
              targetType: 'session',
              ip,
              userAgent,
            });
          }
        }
        return;
      }

      if (session?.uid && session.accountId) {
        const now = new Date();
        const existing = await db.session.findUnique({ where: { oidcSessionUid: session.uid } });
        if (existing) {
          await db.session.update({ where: { id: existing.id }, data: { lastSeenAt: now } });
        } else {
          const created = await db.session.create({
            data: {
              userId: session.accountId,
              oidcSessionUid: session.uid,
              ip,
              userAgent,
              expiresAt: new Date(now.getTime() + SESSION_TTL_SECONDS * 1000),
            },
          });
          await audit.write({
            event: AUDIT_EVENTS.sessionStarted,
            actorUserId: session.accountId,
            targetType: 'session',
            targetId: created.id,
            ip,
            userAgent,
          });
        }
        return;
      }
    } catch (err) {
      // The protocol response has already been decided; losing the mirror row must not break
      // sign-in, but it is an error, not a shrug.
      logger.error({ err, route: oidc.route }, 'failed to record the session');
    }
  });
}
