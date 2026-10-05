import { AUDIT_EVENTS } from '../audit/events.js';
import type { AuditWriter } from '../audit/writer.js';
import type { Db } from '../db.js';
import type { SessionControl } from '../security/sessions.js';
import type { TrustedDevices } from '../security/trusted-device.js';

// Deleting your own account (AUTH-T-10.3, AUTH-ADR-009): delete the person, revoke every grant and
// session.
//
// Asking suspends the account at once — every sign-in path refuses a suspended person — and ends
// everything it holds: provider sessions (each app told over back-channel logout), every token of
// every grant, trusted devices, push registrations and native step-ups. An admin reactivating it
// inside the grace period cancels, and the person's app access is still there to come back to.
//
// After the grace period the daily purge deletes the user row; credentials, sessions, app access,
// group memberships and identities go with it by cascade. The audit trail keeps the person's id,
// which is a `sub` no app will ever see again — the identity provider's history is not rewritten.

/** At least the contract's day; a week, so a regret on Monday can still be helped by an admin. */
export const DELETION_GRACE_MS = 7 * 24 * 60 * 60 * 1000;

export type DeletionRequest =
  | { readonly kind: 'scheduled'; readonly graceUntil: Date; readonly sessionsEnded: number }
  | { readonly kind: 'last_owner' }
  | { readonly kind: 'gone' };

export async function requestDeletion(
  deps: { db: Db; sessions: SessionControl; trustedDevices: TrustedDevices },
  userId: string,
  now = new Date(),
): Promise<DeletionRequest> {
  const { db } = deps;
  const graceUntil = new Date(now.getTime() + DELETION_GRACE_MS);
  const decided = await db.$transaction(async (tx) => {
    // Owners locked first, so two owners deleting themselves at once serialize and the second
    // finds itself the last.
    await tx.$queryRaw`SELECT id FROM "user" WHERE kind = 'owner' AND status = 'active' FOR UPDATE`;
    const user = await tx.user.findFirst({ where: { id: userId, status: 'active' } });
    if (user === null) return 'gone' as const;
    if (user.kind === 'owner') {
      const others = await tx.user.count({ where: { kind: 'owner', status: 'active', id: { not: userId } } });
      if (others === 0) return 'last_owner' as const;
    }
    await tx.user.update({ where: { id: userId }, data: { status: 'suspended', deleteAfter: graceUntil } });
    await tx.relayRegistration.deleteMany({ where: { userId } });
    await tx.nativeStepUp.deleteMany({ where: { userId } });
    return 'scheduled' as const;
  });
  if (decided !== 'scheduled') return { kind: decided };
  // Outside the transaction: ending a session tells the apps, which is network, not a row.
  const sessionsEnded = await deps.sessions.revokeAll(userId);
  await deps.trustedDevices.revokeAll(userId);
  return { kind: 'scheduled', graceUntil, sessionsEnded };
}

/**
 * Deletes every account whose grace period has passed; `now` is the test clock. Run daily. Each
 * account is its own delete and its own audit event, so one bad row cannot hold up the rest.
 */
export async function purgeDeletedAccounts(deps: { db: Db; audit: AuditWriter }, now = new Date()): Promise<number> {
  const due = await deps.db.user.findMany({
    where: { deleteAfter: { lte: now }, status: 'suspended' },
    select: { id: true },
  });
  let purged = 0;
  for (const { id } of due) {
    const { count } = await deps.db.user.deleteMany({ where: { id, deleteAfter: { lte: now }, status: 'suspended' } });
    if (count === 0) continue;
    purged += 1;
    await deps.audit.write({ event: AUDIT_EVENTS.personPurged, targetType: 'user', targetId: id });
  }
  return purged;
}
