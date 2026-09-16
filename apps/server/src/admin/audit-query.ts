import type { Db } from '../db.js';

// Reading the audit trail (REQ-069).
//
// The table is append-only and only grows, so everything here is a read with a cursor. Filters
// are the point: "what happened" is unanswerable at ten thousand rows, while "what did this
// person do to that app last Tuesday" is a question somebody actually has.
//
// Nothing here can write. That is not an oversight — the trigger on the table refuses updates
// and deletes, and this module has no reason to try.

export interface AuditFilter {
  /** Who did it. */
  actorUserId?: string | undefined;
  /** What it was done to. */
  targetId?: string | undefined;
  /** Exact event name, or a prefix like `grant.` for a family of them. */
  event?: string | undefined;
  from?: Date | undefined;
  to?: Date | undefined;
  limit?: number | undefined;
  /** The `id` of the last row of the previous page. */
  cursor?: string | undefined;
}

export interface AuditRow {
  id: string;
  at: Date;
  event: string;
  actor: { id: string; displayName: string; email: string } | null;
  targetType: string | null;
  targetId: string | null;
  ip: string | null;
  detail: unknown;
}

export interface AuditPage {
  events: AuditRow[];
  /** Pass back as `cursor` for the next page; absent when this is the end. */
  nextCursor?: string;
}

const MAX_LIMIT = 200;

/** Turns the filter into a where clause, ignoring anything blank. */
function whereOf(filter: AuditFilter): Record<string, unknown> {
  const where: Record<string, unknown> = {};
  if (filter.actorUserId) where.actorUserId = filter.actorUserId;
  if (filter.targetId) where.targetId = filter.targetId;
  if (filter.event) {
    // A trailing dot reads as a family: `grant.` means every grant event.
    where.event = filter.event.endsWith('.') ? { startsWith: filter.event } : filter.event;
  }
  if (filter.from || filter.to) {
    where.at = { ...(filter.from ? { gte: filter.from } : {}), ...(filter.to ? { lte: filter.to } : {}) };
  }
  if (filter.cursor) where.id = { lt: BigInt(filter.cursor) };
  return where;
}

export async function searchAudit(db: Db, filter: AuditFilter = {}): Promise<AuditPage> {
  const limit = Math.min(Math.max(filter.limit ?? 50, 1), MAX_LIMIT);
  const rows = await db.auditEvent.findMany({
    where: whereOf(filter),
    orderBy: { id: 'desc' },
    take: limit + 1,
  });

  const page = rows.slice(0, limit);
  const actors = await db.user.findMany({
    where: { id: { in: [...new Set(page.map((row) => row.actorUserId).filter((id): id is string => id !== null))] } },
    select: { id: true, displayName: true, email: true },
  });
  const byId = new Map(actors.map((actor) => [actor.id, actor]));

  return {
    events: page.map((row) => ({
      id: row.id.toString(),
      at: row.at,
      event: row.event,
      // A deleted account leaves its audit rows behind; the actor is then just an id.
      actor: row.actorUserId ? (byId.get(row.actorUserId) ?? { id: row.actorUserId, displayName: 'Deleted account', email: '' }) : null,
      targetType: row.targetType,
      targetId: row.targetId,
      ip: row.ip,
      detail: row.detail,
    })),
    ...(rows.length > limit && page.at(-1) ? { nextCursor: page[page.length - 1]?.id.toString() ?? '' } : {}),
  };
}

/** Every event name that has actually happened, so a filter can offer real choices. */
export async function knownEvents(db: Db): Promise<string[]> {
  const rows = await db.auditEvent.findMany({ distinct: ['event'], select: { event: true }, orderBy: { event: 'asc' } });
  return rows.map((row) => row.event);
}

const csvCell = (value: unknown): string => {
  const text =
    value === null || value === undefined
      ? ''
      : typeof value === 'object'
        ? JSON.stringify(value)
        : typeof value === 'string'
          ? value
          : JSON.stringify(value);
  // Quote everything: an event detail can contain commas, quotes and newlines.
  return `"${text.replace(/"/g, '""')}"`;
};

/** CSV of one page of results, for somebody who wants it in a spreadsheet (REQ-069). */
export function toCsv(page: AuditPage): string {
  const header = ['at', 'event', 'actor', 'actor_email', 'target_type', 'target_id', 'ip', 'detail'];
  const lines = page.events.map((row) =>
    [row.at.toISOString(), row.event, row.actor?.displayName ?? '', row.actor?.email ?? '', row.targetType, row.targetId, row.ip, row.detail]
      .map(csvCell)
      .join(','),
  );
  return [header.join(','), ...lines].join('\n');
}
