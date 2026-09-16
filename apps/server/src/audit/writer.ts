import type { Request } from 'express';
import type { Db } from '../db.js';
import type { Prisma } from '../generated/prisma/client.js';
import type { Logger } from '../log.js';
import type { AuditEventName, AuditTargetType } from './events.js';

// Append-only audit writer (REQ-110). The row is the record of truth, so a failed write fails the
// action that caused it rather than being swallowed.

export interface AuditEntry {
  event: AuditEventName;
  actorUserId?: string | null | undefined;
  targetType?: AuditTargetType | undefined;
  targetId?: string | null | undefined;
  ip?: string | null | undefined;
  userAgent?: string | null | undefined;
  /** Never credentials: the log scrubber does not reach the database. */
  detail?: Record<string, unknown> | undefined;
}

export interface AuditWriter {
  write(entry: AuditEntry): Promise<void>;
}

/** The address to trust behind the tunnel (REQ-028): Cloudflare's, then Express's own view. */
export function clientIp(req: Request): string | undefined {
  const header = req.get('cf-connecting-ip')?.trim();
  if (header) return header;
  const ip = req.ip;
  // Express reports IPv4 over IPv6 as ::ffff:1.2.3.4; inet columns accept either, but the plain
  // form is what a person reading the audit log expects.
  return ip?.startsWith('::ffff:') ? ip.slice(7) : ip;
}

export function createAuditWriter(db: Db, logger: Logger): AuditWriter {
  return {
    async write(entry) {
      try {
        await db.auditEvent.create({
          data: {
            event: entry.event,
            actorUserId: entry.actorUserId ?? null,
            targetType: entry.targetType ?? null,
            targetId: entry.targetId ?? null,
            ip: entry.ip ?? null,
            userAgent: entry.userAgent ?? null,
            detail: (entry.detail ?? {}) as Prisma.InputJsonObject,
          },
        });
      } catch (err) {
        logger.error({ err, event: entry.event }, 'audit write failed');
        throw err;
      }
    },
  };
}
