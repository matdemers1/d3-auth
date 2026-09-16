import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { authorize, Browser, grantAccess, ISSUER, startHarness, USER, webClientConfig, type Harness } from './oidc-harness.js';

// What the console screens read (REQ-062, REQ-064, REQ-066, REQ-079).
//
// The screens themselves are Playwright's job; these are the answers behind them, and the one
// rule they all share: an admin manages people, the owner manages apps, and a guest manages
// neither.

let h: Harness;
let config: client.Configuration;
let ownerId: string;
let personId: string;

type Call = (path: string, body?: unknown) => Promise<Response>;

async function consoleSession(credentials?: { email: string; password: string }): Promise<Call> {
  const { browser } = await authorize(h, config, {}, new Browser(h.opFetch), credentials);
  const cookie = [...browser.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  return (path, body) =>
    h.opFetch(`${ISSUER}${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: {
        cookie,
        accept: 'application/json',
        'sec-fetch-site': 'same-origin',
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
}

const PERSON = { email: 'console@example.com', username: 'consoleperson', displayName: 'Console Person', password: 'brambling quartz meadow' };

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  ownerId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
  await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });

  const person = await h.service.db.user.upsert({
    where: { email: PERSON.email },
    create: { email: PERSON.email, username: PERSON.username, displayName: PERSON.displayName, status: 'active' },
    update: { status: 'active', kind: 'guest' },
  });
  personId = person.id;
  await h.service.db.passwordCredential.deleteMany({ where: { userId: personId } });
  await h.service.db.passwordCredential.create({ data: { userId: personId, argon2idHash: await h.hasher.hash(PERSON.password) } });
});

afterAll(async () => {
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
});

describe('one person, for their page (REQ-064)', () => {
  it('answers with everything the screen shows, and no credential', async () => {
    await grantAccess(h, personId, 'web-app', ['member']);
    await h.service.totp.begin({ userId: personId, accountName: PERSON.email });

    const call = await consoleSession();
    const detail = (await (await call(`/api/admin/people/${personId}`)).json()) as Record<string, unknown>;

    expect(detail).toMatchObject({
      id: personId,
      email: PERSON.email,
      kind: 'guest',
      status: 'active',
      // An unconfirmed authenticator app is not a factor, so it is not counted as one.
      factors: { passkeys: 0, authenticatorApps: 0, trustedDevices: 0 },
    });
    expect(detail.access).toMatchObject([{ clientId: 'web-app', roles: ['member'] }]);

    // Nothing here is a secret: no hashes, no TOTP seeds, no session identifiers.
    const text = JSON.stringify(detail);
    expect(text).not.toMatch(/argon2|secret|hash/i);
  });

  it('counts a confirmed factor and a live session', async () => {
    const theirs = await consoleSession({ email: PERSON.email, password: PERSON.password });
    expect((await theirs('/api/me')).status).toBe(200);

    const call = await consoleSession();
    const detail = (await (await call(`/api/admin/people/${personId}`)).json()) as {
      sessions: unknown[];
      factors: { trustedDevices: number };
    };
    expect(detail.sessions.length).toBeGreaterThan(0);
  });

  it('is 404 for somebody who does not exist', async () => {
    const call = await consoleSession();
    expect((await call('/api/admin/people/01a0aa3c-0000-0000-0000-000000000000')).status).toBe(404);
  });
});

describe('the launcher (REQ-079)', () => {
  it('lists what this person can sign in to, and nothing else', async () => {
    await grantAccess(h, personId, 'web-app', ['member']);
    const theirs = await consoleSession({ email: PERSON.email, password: PERSON.password });

    const mine = (await (await theirs('/api/account/apps')).json()) as { apps: { clientId: string; roles: string[] }[] };
    expect(mine.apps).toMatchObject([{ clientId: 'web-app', roles: ['member'] }]);

    // The owner's own launcher is their own, not everybody's.
    const call = await consoleSession();
    const theirsToo = (await (await call('/api/account/apps')).json()) as { apps: { clientId: string }[] };
    expect(theirsToo.apps.map((app) => app.clientId)).not.toContain('native-app-that-nobody-granted');
  });

  it('is empty for somebody with no access at all', async () => {
    await h.service.db.grant.deleteMany({ where: { userId: personId } });
    await grantAccess(h, personId, 'web-app', []);
    const theirs = await consoleSession({ email: PERSON.email, password: PERSON.password });
    await h.service.db.grant.deleteMany({ where: { userId: personId } });

    const mine = (await (await theirs('/api/account/apps')).json()) as { apps: unknown[] };
    expect(mine.apps).toEqual([]);
  });
});

describe('who may see what (REQ-062)', () => {
  it('keeps a guest out of the console entirely', async () => {
    await grantAccess(h, personId, 'web-app', []);
    const theirs = await consoleSession({ email: PERSON.email, password: PERSON.password });

    expect((await theirs('/api/admin/people')).status).toBe(403);
    expect((await theirs('/api/admin/apps')).status).toBe(403);
    expect((await theirs(`/api/admin/people/${ownerId}`)).status).toBe(403);
    // Their own account is still theirs.
    expect((await theirs('/api/account/apps')).status).toBe(200);
  });

  it('lets an admin manage people but not apps', async () => {
    await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'admin' } });
    const call = await consoleSession();

    expect((await call('/api/admin/people')).status).toBe(200);
    expect((await call(`/api/admin/people/${personId}`)).status).toBe(200);
    expect((await call(`/api/admin/people/${personId}/access`, { clientId: 'web-app', roles: [] })).status).toBe(200);
    expect((await call('/api/admin/apps')).status).toBe(403);
  });
});
