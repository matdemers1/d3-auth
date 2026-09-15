import type { Adapter, AdapterFactory, AdapterPayload } from 'oidc-provider';
import type { Db } from '../db.js';
import type { Prisma } from '../generated/prisma/client.js';

// oidc-provider storage over the oidc_payload table (REQ-001). One row per artifact, keyed by
// (kind, id) where kind is the provider's model name: AuthorizationCode, AccessToken,
// RefreshToken, Grant, Session, Interaction, ReplayDetection, and the rest.
//
// Expired rows are invisible to reads; a retention job deletes them later (Data Model: Retention).

type Row = { payload: Prisma.JsonValue; consumedAt: Date | null; expiresAt: Date | null };

const epochSeconds = (date: Date): number => Math.floor(date.getTime() / 1000);

function toPayload(row: Row | null, now: Date): AdapterPayload | undefined {
  if (!row) return undefined;
  if (row.expiresAt && row.expiresAt <= now) return undefined;
  const payload = row.payload as AdapterPayload;
  return row.consumedAt ? { ...payload, consumed: epochSeconds(row.consumedAt) } : payload;
}

export function createAdapterFactory(db: Db): AdapterFactory {
  return (kind: string): Adapter => ({
    async upsert(id, payload, expiresIn) {
      const data = {
        payload: payload as Prisma.InputJsonObject,
        grantId: payload.grantId ?? null,
        userCode: payload.userCode ?? null,
        uid: payload.uid ?? null,
        expiresAt: expiresIn ? new Date(Date.now() + expiresIn * 1000) : null,
      };
      await db.oidcPayload.upsert({
        where: { kind_id: { kind, id } },
        create: { kind, id, ...data },
        update: data,
      });
    },

    async find(id) {
      const row = await db.oidcPayload.findUnique({ where: { kind_id: { kind, id } } });
      return toPayload(row, new Date());
    },

    async findByUid(uid) {
      const row = await db.oidcPayload.findFirst({ where: { kind, uid } });
      return toPayload(row, new Date());
    },

    async findByUserCode(userCode) {
      const row = await db.oidcPayload.findFirst({ where: { kind, userCode } });
      return toPayload(row, new Date());
    },

    async consume(id) {
      await db.oidcPayload.updateMany({ where: { kind, id }, data: { consumedAt: new Date() } });
    },

    async destroy(id) {
      await db.oidcPayload.deleteMany({ where: { kind, id } });
    },

    // Grant revocation removes every artifact of the family, whatever its kind.
    async revokeByGrantId(grantId) {
      await db.oidcPayload.deleteMany({ where: { grantId } });
    },
  });
}
