import { once } from 'node:events';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createAuthClient, createBackchannelHandler, identityKey, SsoUnavailable } from '@d3cloud/auth-client';
import { createLocalJWKSet, type JSONWebKeySet } from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { Browser, grantAccess, ISSUER, RP_CALLBACK, startHarness, USER, WEB_CLIENT, type Harness } from './oidc-harness.js';

// The SDK against the real provider (REQ-088, REQ-094, REQ-097, REQ-098).
//
// The package's own tests check the rules in isolation; this one checks the thing that actually
// matters — that an app using the SDK can sign somebody in to *this* provider, see their roles,
// and be told when they are signed out.

let h: Harness;
let userId: string;

const clientFor = (overrides: Partial<Parameters<typeof createAuthClient>[0]> = {}) =>
  createAuthClient({
    issuer: ISSUER,
    clientId: WEB_CLIENT.clientId,
    clientSecret: WEB_CLIENT.secret,
    redirectUri: RP_CALLBACK,
    fetch: (input, init) => h.opFetch(input, init),
    ...overrides,
  });

/**
 * The provider's key set, fetched through the harness. A real app points the SDK at the issuer
 * and lets it fetch `/oidc/jwks` itself; here the issuer only exists behind `opFetch`.
 */
async function jwksThrough(harness: Harness) {
  const keys = (await (await harness.opFetch(`${ISSUER}/oidc/jwks`)).json()) as JSONWebKeySet;
  return createLocalJWKSet(keys);
}

/** Walks the browser through the provider's screens, the way a person would. */
async function signInThrough(url: string): Promise<URL> {
  const browser = new Browser(h.opFetch);
  const started = await browser.navigate(url);
  const finished = await browser.login(started.response);
  if (!finished.leftTo) throw new Error(`the sign-in did not come back: ${String(finished.status)}`);
  return finished.leftTo;
}

beforeAll(async () => {
  h = await startHarness();
  userId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
});

afterAll(async () => {
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  await grantAccess(h, userId, WEB_CLIENT.clientId, ['member']);
  await h.service.db.grant.updateMany({ where: { userId }, data: { firstSignInAt: new Date() } });
});

describe('an app using the SDK', () => {
  it('signs somebody in and knows who they are by (iss, sub)', async () => {
    const sdk = await clientFor();
    const start = await sdk.beginSignIn();
    const session = await sdk.completeSignIn(await signInThrough(start.url), start);

    expect(session.identity).toMatchObject({ iss: ISSUER, sub: userId, roles: ['member'] });
    expect(identityKey(session.identity)).toBe(`${ISSUER}#${userId}`);
    expect(session.accessToken).toEqual(expect.any(String));
  });

  it('sees the roles change on the next renewal, not the next sign-in (REQ-097)', async () => {
    const sdk = await clientFor();
    const start = await sdk.beginSignIn();
    const session = await sdk.completeSignIn(await signInThrough(start.url), start);
    expect(session.identity.roles).toEqual(['member']);

    await grantAccess(h, userId, WEB_CLIENT.clientId, ['admin']);
    expect(await sdk.rolesNow(session.accessToken, userId)).toEqual(['admin']);

    const renewed = await sdk.refresh(session.refreshToken ?? '');
    expect(renewed.identity.roles).toEqual(['admin']);
  });

  it('reports the provider as reachable, which is what the button asks', async () => {
    const sdk = await clientFor();
    expect(await sdk.healthy()).toBe(true);
  });

  it('says so plainly when the provider cannot be reached', async () => {
    await expect(
      createAuthClient({
        issuer: 'https://nowhere.d3auth.test',
        clientId: 'x',
        redirectUri: RP_CALLBACK,
        fetch: () => Promise.reject(new Error('connection refused')),
      }),
    ).rejects.toBeInstanceOf(SsoUnavailable);
  });

  it('refuses a callback whose state does not match the one it started with', async () => {
    const sdk = await clientFor();
    const start = await sdk.beginSignIn();
    const callback = await signInThrough(start.url);
    await expect(sdk.completeSignIn(callback, { ...start, state: 'not-the-state-we-sent' })).rejects.toThrow();
  });

  it('verifies a real logout token from this provider, and applies it once (REQ-098, REQ-099)', async () => {
    // A real listener, so the token under test is one the provider actually delivered.
    const delivered: string[] = [];
    const server = createServer((req, res) => {
      let body = '';
      req.on('data', (chunk: Buffer) => (body += chunk.toString()));
      req.on('end', () => {
        res.writeHead(200).end();
        delivered.push(new URLSearchParams(body).get('logout_token') ?? '');
      });
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const { port } = server.address() as AddressInfo;

    const app = await h.service.db.app.findUniqueOrThrow({ where: { clientId: WEB_CLIENT.clientId } });
    await h.service.db.app.update({ where: { id: app.id }, data: { backchannelLogoutUri: `http://127.0.0.1:${String(port)}/logout` } });

    try {
      expect(await h.service.backchannel.notify({ userId, clientId: WEB_CLIENT.clientId, sid: 'a-session', reason: 'test' })).toBe(true);
      expect(delivered).toHaveLength(1);

      const ended: string[] = [];
      const handle = createBackchannelHandler({
        issuer: ISSUER,
        clientId: WEB_CLIENT.clientId,
        jwks: await jwksThrough(h),
        endSession: (logout) => {
          ended.push(logout.sub);
        },
      });

      const token = delivered[0] ?? '';
      expect(await handle(token)).toEqual({ ok: true });
      // The provider retries; the same event must not end a session twice.
      expect(await handle(token)).toEqual({ ok: true, repeated: true });
      expect(ended).toEqual([userId]);
    } finally {
      await h.service.db.app.update({ where: { id: app.id }, data: { backchannelLogoutUri: null } });
      await new Promise<void>((resolve) => server.close(() => { resolve(); }));
    }
  });
});
