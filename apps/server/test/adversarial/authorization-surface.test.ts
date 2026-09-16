import { randomUUID } from 'node:crypto';
import type { Express } from 'express';
import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { authorize, ISSUER, startHarness, USER, webClientConfig, type Harness } from '../integration/oidc-harness.js';
import { consoleCaller, sessionCookie } from './support.js';

// Attack class: reaching an API you were not given (REQ-062, REQ-037, REQ-031).
//
// The functional tests check the routes somebody remembered to write a test for. An attacker
// checks the routes that exist. So this file does not list endpoints: it walks the running
// application's router, collects every `/api/admin` and `/api/account` route, and throws each
// one at the service four ways — with no session, as a guest, from another site, and from another
// origin by a browser too old to say where it came from. A route added next year without a guard
// fails here without anybody having to remember this file exists.

let h: Harness;
let config: client.Configuration;
let ownerId: string;

interface Route {
  method: 'GET' | 'POST';
  path: string;
}

/** Every route the app actually serves under the prefixes that must be guarded. */
function routesOf(app: Express): Route[] {
  const found: Route[] = [];
  const walk = (stack: unknown[]): void => {
    for (const layer of stack as { route?: { path: string; methods: Record<string, boolean> }; handle?: { stack?: unknown[] } }[]) {
      if (layer.route) {
        for (const method of Object.keys(layer.route.methods)) {
          const upper = method.toUpperCase();
          if (upper === 'GET' || upper === 'POST') found.push({ method: upper, path: layer.route.path });
        }
      } else if (layer.handle?.stack) {
        walk(layer.handle.stack);
      }
    }
  };
  walk((app as unknown as { router: { stack: unknown[] } }).router.stack);
  return found.filter((route) => /^\/api\/(admin|account)\//.test(route.path));
}

/** A concrete URL for a route pattern: every parameter becomes an id that exists nowhere. */
const concrete = (path: string): string => path.replace(/:[A-Za-z]+/g, randomUUID());

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  ownerId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
  await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
});

afterAll(async () => {
  await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
});

describe('the surface itself', () => {
  it('is found by walking the router, not by listing it', () => {
    const routes = routesOf(h.service.app);
    // If this drops to a handful, the walker broke and everything below proves nothing.
    expect(routes.length).toBeGreaterThan(40);
    expect(routes.some((route) => route.path === '/api/admin/state/import')).toBe(true);
    expect(routes.some((route) => route.path === '/api/account/password')).toBe(true);
  });
});

describe('with no session', () => {
  it('every guarded route refuses, and none of them does anything', async () => {
    const open: string[] = [];
    for (const route of routesOf(h.service.app)) {
      const answer = await h.opFetch(`${ISSUER}${concrete(route.path)}`, {
        method: route.method,
        headers: { accept: 'application/json', 'content-type': 'application/json', 'sec-fetch-site': 'same-origin' },
        ...(route.method === 'POST' ? { body: '{}' } : {}),
      });
      if (answer.status !== 401) open.push(`${route.method} ${route.path} → ${String(answer.status)}`);
    }
    expect(open).toEqual([]);
  });

  it('a forged session cookie is just an unknown cookie', async () => {
    const answer = await h.opFetch(`${ISSUER}/api/admin/people`, {
      headers: { accept: 'application/json', 'sec-fetch-site': 'same-origin', cookie: '__Host-d3auth_session=forged; __Host-d3auth_session.sig=forged' },
    });
    expect(answer.status).toBe(401);
  });
});

describe('as a guest', () => {
  it('every admin route refuses', async () => {
    await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'guest' } });
    try {
      const call = await consoleCaller(h, config);
      const open: string[] = [];
      for (const route of routesOf(h.service.app).filter((entry) => entry.path.startsWith('/api/admin/'))) {
        const answer = await call(concrete(route.path), route.method === 'POST' ? { body: {} } : {});
        if (answer.status !== 403) open.push(`${route.method} ${route.path} → ${String(answer.status)}`);
      }
      expect(open).toEqual([]);
    } finally {
      await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
    }
  });
});

describe('from somewhere else', () => {
  it('a cross-site request is refused on every route, whatever the cookie says', async () => {
    const call = await consoleCaller(h, config);
    const open: string[] = [];
    for (const route of routesOf(h.service.app)) {
      const answer = await call(concrete(route.path), {
        ...(route.method === 'POST' ? { body: {} } : {}),
        headers: { 'sec-fetch-site': 'cross-site' },
      });
      if (answer.status !== 403) open.push(`${route.method} ${route.path} → ${String(answer.status)}`);
    }
    expect(open).toEqual([]);
  });

  it('a browser that does not send Sec-Fetch-Site is judged by its Origin instead', async () => {
    const cookie = await sessionCookie(h, config);
    const victim = await h.service.db.user.upsert({
      where: { email: 'csrf-victim@example.com' },
      create: { email: 'csrf-victim@example.com', username: 'csrfvictim', displayName: 'CSRF Victim', status: 'active' },
      update: { status: 'active' },
    });

    // The request an old browser would make from evil.test: the owner's cookies, no fetch
    // metadata, and an Origin that is not ours. It must not suspend anybody.
    const forged = await h.opFetch(`${ISSUER}/api/admin/people/${victim.id}/suspend`, {
      method: 'POST',
      headers: {
        cookie,
        origin: 'https://evil.test',
        'content-type': 'text/plain',
      },
      body: '',
    });
    expect(forged.status).toBe(403);
    expect((await h.service.db.user.findUniqueOrThrow({ where: { id: victim.id } })).status).toBe('active');

    // Our own origin with no fetch metadata is still fine: that is a same-origin request from a
    // browser that simply predates the header.
    const ours = await h.opFetch(`${ISSUER}/api/admin/people`, {
      headers: { cookie, origin: ISSUER, accept: 'application/json' },
    });
    expect(ours.status).toBe(200);
    await h.service.db.user.deleteMany({ where: { id: victim.id } });
  });
});

describe('the first-run claim', () => {
  it('cannot be used to take an instance that already has an owner', async () => {
    const answer = await h.opFetch(`${ISSUER}/api/setup`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json', 'sec-fetch-site': 'same-origin' },
      body: JSON.stringify({ email: 'usurper@example.com', username: 'usurper', displayName: 'Usurper', password: 'a perfectly long passphrase' }),
    });
    expect(answer.status).toBeGreaterThanOrEqual(400);
    expect(await h.service.db.user.findUnique({ where: { email: 'usurper@example.com' } })).toBeNull();
    expect(await h.service.db.user.count({ where: { kind: 'owner' } })).toBe(1);
  });
});

describe('the token-bearing endpoints, from a web page on another origin', () => {
  it('refuse a cross-origin call even with a valid token', async () => {
    const flow = await authorize(h, config);
    const tokens = await client.authorizationCodeGrant(config, flow.callback, {
      pkceCodeVerifier: flow.verifier,
      expectedState: flow.state,
      expectedNonce: flow.nonce,
    });

    // Same token, no Origin: a server-side app. Works.
    const server = await h.opFetch(`${ISSUER}/oidc/me`, { headers: { authorization: `Bearer ${tokens.access_token}` } });
    expect(server.status).toBe(200);

    // Same token, from a page on evil.test: refused, and nothing tells the browser it may read the answer.
    const page = await h.opFetch(`${ISSUER}/oidc/me`, { headers: { authorization: `Bearer ${tokens.access_token}`, origin: 'https://evil.test' } });
    expect(page.status).toBeGreaterThanOrEqual(400);
    expect(page.headers.get('access-control-allow-origin')).toBeNull();
  });
});
