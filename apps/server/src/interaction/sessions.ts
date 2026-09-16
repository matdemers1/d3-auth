import type Provider from 'oidc-provider';
import { AUDIT_EVENTS } from '../audit/events.js';
import type { AuditWriter } from '../audit/writer.js';
import type { Db } from '../db.js';
import type { Logger } from '../log.js';

// Our own session rows (REQ-030, REQ-045). The provider owns the SSO cookie; this mirrors it into
// the table behind the Sessions & devices screen, recording IP, user agent and last-seen.
//
// The provider regenerates the session identifier when an interaction completes and again at
// logout (oidc-provider's resume and end_session both call resetIdentifier), so a fixated
// pre-login identifier cannot survive sign-in.

export const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;

export function recordSessions(provider: Provider, db: Db, audit: AuditWriter, logger: Logger): void {
  provider.on('authorization.success', (ctx) => {
    const session = ctx.oidc.session;
    const accountId = session?.accountId;
    if (!session?.uid || !accountId) return;

    const ip = ctx.get('cf-connecting-ip') || ctx.ip;
    const userAgent = ctx.get('user-agent');
    const now = new Date();
    const expiresAt = new Date(now.getTime() + SESSION_TTL_SECONDS * 1000);

    void (async () => {
      try {
        const existing = await db.session.findUnique({ where: { oidcSessionUid: session.uid } });
        if (existing) {
          await db.session.update({ where: { id: existing.id }, data: { lastSeenAt: now } });
          return;
        }
        const created = await db.session.create({
          data: { userId: accountId, oidcSessionUid: session.uid, ip: ip || null, userAgent: userAgent || null, expiresAt },
        });
        await audit.write({
          event: AUDIT_EVENTS.sessionStarted,
          actorUserId: accountId,
          targetType: 'session',
          targetId: created.id,
          ip: ip || null,
          userAgent: userAgent || null,
        });
      } catch (err) {
        logger.error({ err }, 'failed to record session');
      }
    })();
  });

  provider.on('end_session.success', (ctx) => {
    const uid = ctx.oidc.session?.uid;
    const accountId = ctx.oidc.session?.accountId;
    if (!uid) return;
    void (async () => {
      try {
        const { count } = await db.session.updateMany({
          where: { oidcSessionUid: uid, revokedAt: null },
          data: { revokedAt: new Date() },
        });
        if (count > 0) {
          await audit.write({
            event: AUDIT_EVENTS.logout,
            actorUserId: accountId ?? null,
            targetType: 'session',
            ip: ctx.get('cf-connecting-ip') || ctx.ip,
            userAgent: ctx.get('user-agent'),
          });
        }
      } catch (err) {
        logger.error({ err }, 'failed to close session');
      }
    })();
  });
}
