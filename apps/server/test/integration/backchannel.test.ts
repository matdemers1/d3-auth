import { once } from 'node:events';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { authorize, Browser, discover, grantAccess, markVisited, startHarness, USER, type Harness } from './oidc-harness.js';

// REQ-011, REQ-012, REQ-056.
//
// Revoking access is worth nothing if the app never hears about it. These tests stand a real
// listener in front of a real app registration and check what actually arrives: a signed logout
// token, once per event, and a *slow revoke* note when nobody is listening.

let h: Harness;
let userId: string;

const APP = { clientId: 'listening-app', secret: 'a-client-secret-for-the-backchannel-tests', callback: 'https://listening.d3auth.test/cb' };

/** A logout token is a JWT; the tests only need its claims, not its signature. */
const claimsOf = (jwt: string): Record<string, unknown> => {
  try {
    return JSON.parse(Buffer.from(jwt.split('.')[1] ?? '', 'base64url').toString('utf8')) as Record<string, unknown>;
  } catch {
    return {};
  }
};

/** Stands in for a relying party's back-channel endpoint. */
interface Listener {
  url: string;
  received: { token: string; claims: Record<string, unknown> }[];
  /** Makes the next attempts fail, so the retry behaviour can be seen. */
  failTimes: number;
  close(): Promise<void>;
}

async function listen(): Promise<Listener> {
  const state: Listener = { url: '', received: [], failTimes: 0, close: () => Promise.resolve() };
  const server: Server = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk: Buffer) => (body += chunk.toString()));
    req.on('end', () => {
      // Answer first, whatever arrives: a listener that throws before replying leaves the
      // provider's fetch hanging, and the failure looks like a delivery bug rather than a test one.
      if (state.failTimes > 0) {
        state.failTimes -= 1;
        res.writeHead(500).end();
        return;
      }
      res.writeHead(200).end();
      const token = new URLSearchParams(body).get('logout_token') ?? '';
      state.received.push({ token, claims: claimsOf(token) });
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;
  state.url = `http://127.0.0.1:${port}/backchannel`;
  state.close = () => new Promise<void>((resolve) => server.close(() => { resolve(); }));
  return state;
}

let listener: Listener;

beforeAll(async () => {
  h = await startHarness();
  userId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
  listener = await listen();

  const app = await h.service.db.app.upsert({
    where: { clientId: APP.clientId },
    create: {
      clientId: APP.clientId,
      name: 'Listening App',
      clientType: 'confidential_web',
      clientSecretHash: await h.hasher.hash(APP.secret),
      backchannelLogoutUri: listener.url,
      postLogoutRedirectUris: [],
    },
    update: { backchannelLogoutUri: listener.url, enabled: true },
  });
  await h.service.db.redirectUri.deleteMany({ where: { appId: app.id } });
  await h.service.db.redirectUri.create({ data: { appId: app.id, uri: APP.callback } });
  await h.service.db.role.deleteMany({ where: { appId: app.id } });
  await h.service.db.role.create({ data: { appId: app.id, key: 'member', displayName: 'Member', sortOrder: 1 } });
});

afterAll(async () => {
  await listener.close();
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  listener.received.length = 0;
  listener.failTimes = 0;
  await grantAccess(h, userId, APP.clientId, ['member']);
  await markVisited(h, userId, APP.clientId);
});

/** Signs in to the listening app and returns the session it created. */
async function signIn(): Promise<{ sid: string; sessionUid: string }> {
  const config = await discover(h, APP.clientId, client.ClientSecretBasic(APP.secret));
  const code = await authorize(h, config, { redirect_uri: APP.callback, scope: 'openid' }, new Browser(h.opFetch));
  const tokens = await client.authorizationCodeGrant(config, code.callback, {
    pkceCodeVerifier: code.verifier,
    expectedState: code.state,
    expectedNonce: code.nonce,
  });
  const sid = tokens.claims()?.sid;
  const row = await h.service.db.session.findFirstOrThrow({ where: { userId, revokedAt: null }, orderBy: { createdAt: 'desc' } });
  return { sid: typeof sid === 'string' ? sid : '', sessionUid: row.oidcSessionUid ?? '' };
}

describe('the logout token', () => {
  it('is signed, names the session, and says what happened (REQ-011)', async () => {
    const { sid } = await signIn();
    // An app that can be told gets a `sid` in its ID token, which is what it uses to find the
    // session this token is about.
    expect(sid).not.toBe('');

    await h.service.backchannel.notify({ userId, clientId: APP.clientId, sid, reason: 'test' });
    expect(listener.received).toHaveLength(1);

    const claims = listener.received[0]?.claims ?? {};
    expect(claims).toMatchObject({ sub: userId, aud: APP.clientId, sid });
    expect(claims.events).toMatchObject({ 'http://schemas.openid.net/event/backchannel-logout': {} });
    expect(claims.jti).toEqual(expect.any(String));
    // Short-lived by design: a logout token is a statement about now.
    expect(Number(claims.exp) - Number(claims.iat)).toBeLessThanOrEqual(120);
    // It is not an ID token and must never be mistaken for one.
    expect(claims.nonce).toBeUndefined();
  });

  it('arrives when a grant is revoked (REQ-056)', async () => {
    await signIn();
    await h.service.grants.revoke({ userId, clientId: APP.clientId, actorUserId: userId });
    expect(listener.received).toHaveLength(1);
    expect(listener.received[0]?.claims).toMatchObject({ sub: userId });
  });

  it('arrives when the roles on a grant change', async () => {
    await signIn();
    await h.service.grants.set({ userId, clientId: APP.clientId, roles: [], actorUserId: userId });
    expect(listener.received).toHaveLength(1);
  });

  it('arrives when the session is ended from the console', async () => {
    const { sessionUid } = await signIn();
    await h.service.sessions.end(sessionUid);
    expect(listener.received).toHaveLength(1);
    expect(listener.received[0]?.claims.sid).toBeTruthy();
  });
});

describe('when the app does not answer', () => {
  it('tries three times and then gives up (REQ-012)', async () => {
    const { sid } = await signIn();
    listener.failTimes = 2;

    const delivered = await h.service.backchannel.notify({ userId, clientId: APP.clientId, sid, reason: 'test' });
    expect(delivered).toBe(true);
    expect(listener.received).toHaveLength(1);

    listener.failTimes = 99;
    const gaveUp = await h.service.backchannel.notify({ userId, clientId: APP.clientId, sid, reason: 'test' });
    expect(gaveUp).toBe(false);

    const failure = await h.service.db.auditEvent.findFirstOrThrow({ where: { event: 'logout.failed' }, orderBy: { id: 'desc' } });
    expect(failure.detail).toMatchObject({ clientId: APP.clientId, attempts: 3 });
  });

  it('marks an app with no endpoint as slow revoke rather than pretending', async () => {
    await grantAccess(h, userId, 'web-app', ['member']);
    const delivered = await h.service.backchannel.notify({ userId, clientId: 'web-app', reason: 'test' });
    expect(delivered).toBe(false);

    const noted = await h.service.db.auditEvent.findFirstOrThrow({ where: { event: 'logout.slow_revoke' }, orderBy: { id: 'desc' } });
    expect(noted.detail).toMatchObject({ clientId: 'web-app' });
    expect(listener.received).toHaveLength(0);
  });
});
