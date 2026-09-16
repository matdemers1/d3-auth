import type Provider from 'oidc-provider';
import type { Db } from '../db.js';

// Ending sessions, in one place (REQ-038, REQ-039, REQ-083).
//
// Revoking has to reach the provider's own session store, not just our mirror table: a row
// marked revoked while the SSO cookie still works would be a lie told in the console's own UI.
//
// Back-channel logout notices to the apps a person is signed in to arrive with that feature in
// Phase 3 (T-3.6). Until then the session itself is gone here, which is what stops the next
// authorization request cold.

export interface SessionControl {
  /** Ends one provider session by its uid. Missing or already-gone is not an error. */
  end(uid: string | null): Promise<void>;
  /** Revokes every session for a user except `keepUid`. Returns how many were ended. */
  revokeAll(userId: string, keepUid?: string): Promise<number>;
}

export function createSessionControl(db: Db, provider: Provider): SessionControl {
  const end = async (uid: string | null): Promise<void> => {
    if (!uid) return;
    const session = await provider.Session.findByUid(uid).catch(() => undefined);
    await session?.destroy();
  };

  return {
    end,
    async revokeAll(userId, keepUid) {
      const rows = await db.session.findMany({
        where: { userId, revokedAt: null, ...(keepUid ? { oidcSessionUid: { not: keepUid } } : {}) },
        select: { id: true, oidcSessionUid: true },
      });
      for (const row of rows) await end(row.oidcSessionUid);
      const { count } = await db.session.updateMany({
        where: { id: { in: rows.map((row) => row.id) } },
        data: { revokedAt: new Date() },
      });
      return count;
    },
  };
}
