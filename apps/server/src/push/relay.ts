import { createHmac, randomUUID } from 'node:crypto';
import type { AdapterFactory } from 'oidc-provider';
import type { Db } from '../db.js';
import type { Logger } from '../log.js';
import type { KekCrypto } from '../security/kek.js';
import { sealEnvelope } from './envelope.js';

// The relay adapter (AUTH-T-10.4, d3-app-contract spec/push.md): registrations, and sending. D3 Auth
// posts a sealed envelope to <relay>/v1/push/<registration>, signed with the registration's send key;
// the relay hands it to APNs. A registration lasts as long as the D3 Constellation grant that made
// it: a grant gone (signed out, access revoked) or a 410 from the relay forgets it. A push is best
// effort: nothing here may fail the request that caused it.

/** notification.v1 — what the device opens. */
export interface Notification {
  v: 1;
  category: string;
  title: string;
  body?: string;
  thread?: string;
  link?: string;
  sentAt: string;
}

const sendKeyContext = (id: string): string => `relay-send-key:${id}`;

/** base64url(HMAC-SHA256(sendKey, "<timestamp>.<body>")), as the relay checks it. */
export function signRelayRequest(sendKey: string, timestamp: string, body: string): string {
  return createHmac('sha256', sendKey).update(`${timestamp}.${body}`).digest('base64url');
}

export interface RelayDeps {
  db: Db;
  kek: KekCrypto;
  adapterFactory: AdapterFactory;
  logger: Logger;
}

export type PushResult = 'sent' | 'gone' | 'failed';

export interface Relay {
  register(input: { userId: string; grantId: string; devicePublicKey: Uint8Array; relayUrl: string; registration: string; sendKey: string; categories: string[] }): Promise<{ id: string }>;
  push(registrationId: string, notification: Notification, collapseId?: string): Promise<PushResult>;
  pushToUser(userId: string, notification: Notification, collapseId?: string): Promise<PushResult[]>;
}

export function createRelay({ db, kek, adapterFactory, logger }: RelayDeps): Relay {
  const grants = adapterFactory('Grant');

  const push: Relay['push'] = async (registrationId, notification, collapseId) => {
    try {
      const row = await db.relayRegistration.findUnique({ where: { id: registrationId } });
      if (!row) return 'gone';
      // Signed out or access revoked: the grant is gone, and so is what it registered.
      if (!(await grants.find(row.grantId))) {
        await db.relayRegistration.deleteMany({ where: { id: row.id } });
        return 'gone';
      }
      const sendKey = kek.decrypt(row.sendKeySealed, sendKeyContext(row.id)).toString('utf8');
      const body = JSON.stringify({
        ciphertext: sealEnvelope(row.devicePublicKey, Buffer.from(JSON.stringify(notification))),
        priority: 'high',
        ...(collapseId === undefined ? {} : { collapseId: collapseId.slice(0, 64) }),
      });
      const timestamp = String(Math.floor(Date.now() / 1000));
      const res = await fetch(`${row.relayUrl}/v1/push/${encodeURIComponent(row.registration)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-d3-relay-timestamp': timestamp, 'x-d3-relay-signature': signRelayRequest(sendKey, timestamp, body) },
        body,
        signal: AbortSignal.timeout(10_000),
      });
      if (res.status === 410) {
        await db.relayRegistration.deleteMany({ where: { id: row.id } });
        return 'gone';
      }
      if (!res.ok) {
        logger.warn({ status: res.status, registration: row.id }, 'relay refused a push');
        return 'failed';
      }
      return 'sent';
    } catch (err) {
      logger.warn({ err, registration: registrationId }, 'push failed');
      return 'failed';
    }
  };

  return {
    async register(input) {
      const id = randomUUID();
      await db.$transaction(async (tx) => {
        // Registering again replaces the grant's earlier registration, and whoever held the slot.
        await tx.relayRegistration.deleteMany({ where: { OR: [{ grantId: input.grantId }, { relayUrl: input.relayUrl, registration: input.registration }] } });
        await tx.relayRegistration.create({
          data: {
            id,
            userId: input.userId,
            grantId: input.grantId,
            devicePublicKey: new Uint8Array(input.devicePublicKey),
            relayUrl: input.relayUrl,
            registration: input.registration,
            sendKeySealed: kek.encrypt(Buffer.from(input.sendKey, 'utf8'), sendKeyContext(id)),
            categories: input.categories,
          },
        });
      });
      return { id };
    },
    push,
    async pushToUser(userId, notification, collapseId) {
      const rows = await db.relayRegistration.findMany({ where: { userId, categories: { has: notification.category } }, select: { id: true } });
      return Promise.all(rows.map((r) => push(r.id, notification, collapseId)));
    },
  };
}
