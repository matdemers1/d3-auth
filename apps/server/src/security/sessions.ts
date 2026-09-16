import type Provider from 'oidc-provider';
import type { Db } from '../db.js';
import type { Backchannel } from '../oidc/backchannel.js';
import { revokeAllTokens } from '../oidc/revoke-tokens.js';

// Ending sessions, in one place (REQ-038, REQ-039, REQ-083).
//
// Revoking has to reach the provider's own session store, not just our mirror table: a row
// marked revoked while the SSO cookie still works would be a lie told in the console's own UI.
//
// Ending a session here also tells the apps it was used with (REQ-011): a person signed out in
// the console whose app session keeps working has not really been signed out.

export interface SessionControl {
  /** Ends one provider session by its uid. Missing or already-gone is not an error. */
  end(uid: string | null): Promise<void>;
  /**
   * Revokes every session for a user except `keepUid`. Returns how many were ended.
   *
   * With nothing kept — a suspension, a reset — the person is being cut off, so every token they
   * were ever issued goes too. With a session kept, it is somebody tidying up their own devices,
   * and the apps they are using right now keep working.
   */
  revokeAll(userId: string, keepUid?: string): Promise<number>;
}

export function createSessionControl(db: Db, provider: Provider, backchannel?: Backchannel, reason = 'session_revoked'): SessionControl {
  const end = async (uid: string | null): Promise<void> => {
    if (!uid) return;
    // Tell the apps first: once the session is destroyed, the identifiers they know it by are
    // gone with it.
    await backchannel?.notifySession({ sessionUid: uid, reason });
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
      if (!keepUid) await revokeAllTokens(db, userId);
      return count;
    },
  };
}
