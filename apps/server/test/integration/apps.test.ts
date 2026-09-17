import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { parseManifest, type Manifest } from '../../src/admin/manifest.js';
import { authorize, Browser, discover, grantAccess, ISSUER, startHarness, USER, webClientConfig, type Harness } from './oidc-harness.js';

// REQ-046, REQ-048, REQ-054, REQ-055, REQ-015.
//
// The claim this file exists to prove: an app registered through the API can be signed in to
// immediately, with no restart of the service every other app depends on — and a disabled app
// stops working at once, tokens included.

let h: Harness;
let config: client.Configuration;
let ownerId: string;

type Call = (path: string, body?: unknown) => Promise<Response>;

async function consoleSession(): Promise<Call> {
  const { browser } = await authorize(h, config, {}, new Browser(h.opFetch));
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

const manifestFor = (clientId: string): Manifest => {
  const result = parseManifest({
    client_id: clientId,
    name: 'A New App',
    client_type: 'confidential_web',
    redirect_uris: [`https://${clientId}.d3auth.test/cb`],
    post_logout_redirect_uris: [`https://${clientId}.d3auth.test/`],
    roles: [
      { key: 'admin', display: 'Administrator' },
      { key: 'member', display: 'Member', default: true },
    ],
  });
  if (!result.ok) throw new Error('fixture manifest is invalid');
  return result.manifest;
};

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  const owner = await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } });
  ownerId = owner.id;
  await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
});

afterAll(async () => {
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  await h.service.db.app.deleteMany({ where: { clientId: { startsWith: 'fresh-' } } });
});

describe('registering an app', () => {
  it('takes effect immediately: the new client can start an authorization request', async () => {
    const call = await consoleSession();
    const clientId = `fresh-${Date.now()}`;
    const manifest = manifestFor(clientId);

    const created = await call('/api/admin/apps', { manifest });
    expect(created.status).toBe(201);
    const body = (await created.json()) as { secret?: string; app: { roles: { key: string }[]; clientId: string } };
    // Shown exactly once, here (REQ-055).
    expect(body.secret).toEqual(expect.any(String));
    expect(body.app.roles.map((role) => role.key)).toEqual(['admin', 'member']);

    // No restart: the provider resolves the brand new client on the next request.
    const discovered = await discover(h, clientId, client.ClientSecretBasic(body.secret ?? ''));
    const url = client.buildAuthorizationUrl(discovered, {
      redirect_uri: `https://${clientId}.d3auth.test/cb`,
      scope: 'openid',
      code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
      code_challenge_method: 'S256',
      state: client.randomState(),
      nonce: client.randomNonce(),
    });
    const { response } = await new Browser(h.opFetch).navigate(url.toString());
    // The sign-in screen, not an "unknown client" error.
    expect(response.status).toBe(200);
    expect(new URL(response.url).pathname).toMatch(/^\/login\//);
  });

  it('stores only a hash of the secret, and the same secret never appears twice', async () => {
    const call = await consoleSession();
    const clientId = `fresh-${Date.now()}`;
    const first = (await (await call('/api/admin/apps', { manifest: manifestFor(clientId) })).json()) as { secret: string };

    const row = await h.service.db.app.findUniqueOrThrow({ where: { clientId } });
    expect(row.clientSecretHash).toMatch(/^\$argon2id\$/);
    expect(row.clientSecretHash).not.toContain(first.secret);

    // Rotation answers with a different secret, and the old one stops working.
    const rotated = (await (await call(`/api/admin/apps/${clientId}/secret`, {})).json()) as { secret: string };
    expect(rotated.secret).not.toBe(first.secret);

    const withOld = await discover(h, clientId, client.ClientSecretBasic(first.secret)).catch(() => undefined);
    expect(withOld).toBeDefined();
    const tokenWithOld = await h.opFetch(`${ISSUER}/oidc/token`, {
      method: 'POST',
      headers: {
        authorization: `Basic ${Buffer.from(`${clientId}:${first.secret}`).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: 'nonsense', redirect_uri: `https://${clientId}.d3auth.test/cb` }),
    });
    expect((await tokenWithOld.json()) as { error: string }).toMatchObject({ error: 'invalid_client' });
  });

  it('refuses a manifest that is not valid, per field', async () => {
    const call = await consoleSession();
    const answer = await call('/api/admin/apps', {
      manifest: { client_id: 'Nope Nope', name: '', client_type: 'confidential_web', redirect_uris: ['http://example.com/cb'] },
    });
    expect(answer.status).toBe(400);
    const body = (await answer.json()) as { error: string; problems: { field: string }[] };
    expect(body.error).toBe('invalid_manifest');
    expect(body.problems.map((problem) => problem.field)).toEqual(expect.arrayContaining(['client_id', 'name']));
  });

  it('refuses a client id that is already registered', async () => {
    const call = await consoleSession();
    const clientId = `fresh-${Date.now()}`;
    expect((await call('/api/admin/apps', { manifest: manifestFor(clientId) })).status).toBe(201);
    const again = await call('/api/admin/apps', { manifest: manifestFor(clientId) });
    expect(again.status).toBe(409);
    expect(await again.json()).toMatchObject({ error: 'already_exists' });
  });

  it('is owner-only', async () => {
    await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'admin' } });
    const call = await consoleSession();
    expect((await call('/api/admin/apps')).status).toBe(403);
    // An admin can still see people; apps are a different kind of power.
    expect((await call('/api/admin/people')).status).toBe(200);
    await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
  });
});

describe('re-registering a manifest', () => {
  it('previews the change without making it', async () => {
    const call = await consoleSession();
    const clientId = `fresh-${Date.now()}`;
    await call('/api/admin/apps', { manifest: manifestFor(clientId) });

    const renamed = { ...manifestFor(clientId), name: 'Renamed' };
    const preview = (await (await call('/api/admin/apps/preview', { manifest: renamed })).json()) as {
      diff: { changed: { field: string }[] };
    };
    expect(preview.diff.changed.map((change) => change.field)).toEqual(['name']);
    expect((await h.service.db.app.findUniqueOrThrow({ where: { clientId } })).name).toBe('A New App');
  });

  it('blocks removing a role somebody holds until it is confirmed (REQ-048)', async () => {
    const call = await consoleSession();
    const clientId = `fresh-${Date.now()}`;
    // No automatic owner grant (ADR-007): this test makes the grant itself.
    await call('/api/admin/apps', { manifest: manifestFor(clientId), grantMe: false });

    // Give somebody the role that is about to disappear.
    const app = await h.service.db.app.findUniqueOrThrow({ where: { clientId }, include: { roles: true } });
    const member = app.roles.find((role) => role.key === 'member');
    const grant = await h.service.db.grant.create({ data: { userId: ownerId, appId: app.id } });
    await h.service.db.grantRole.create({ data: { grantId: grant.id, roleId: member?.id ?? '' } });

    const withoutMember = { ...manifestFor(clientId), roles: [{ key: 'admin', display: 'Administrator', description: '', default: false }] };
    const blocked = await call(`/api/admin/apps/${clientId}/manifest`, { manifest: withoutMember });
    expect(blocked.status).toBe(409);
    expect(await blocked.json()).toMatchObject({ error: 'roles_in_use' });
    expect(await h.service.db.role.count({ where: { appId: app.id } })).toBe(2);

    const confirmed = await call(`/api/admin/apps/${clientId}/manifest`, { manifest: withoutMember, confirmRoleRemoval: true });
    expect(confirmed.status).toBe(200);
    expect(await h.service.db.role.count({ where: { appId: app.id } })).toBe(1);
    // The grant survives; the role it carried does not.
    expect(await h.service.db.grantRole.count({ where: { grantId: grant.id } })).toBe(0);
  });

  it('will not change a client id by the back door', async () => {
    const call = await consoleSession();
    const clientId = `fresh-${Date.now()}`;
    await call('/api/admin/apps', { manifest: manifestFor(clientId) });
    const answer = await call(`/api/admin/apps/${clientId}/manifest`, { manifest: manifestFor(`${clientId}-other`) });
    expect(answer.status).toBe(400);
    expect(await answer.json()).toMatchObject({ error: 'client_id_mismatch' });
  });
});

describe('disabling an app (REQ-054)', () => {
  it('stops new authorizations and takes its live tokens with it', async () => {
    const call = await consoleSession();
    const clientId = `fresh-${Date.now()}`;
    const created = (await (await call('/api/admin/apps', { manifest: manifestFor(clientId) })).json()) as { secret: string };

    // Sign in properly, so there is something to revoke.
    const appConfig = await discover(h, clientId, client.ClientSecretBasic(created.secret));
    // Deny-by-default applies to a brand new app too: somebody has to be given access first.
    await grantAccess(h, ownerId, clientId, ['member']);
    // Its own redirect URI, not the shared fixture's: this app has never heard of that one.
    const code = await authorize(h, appConfig, { redirect_uri: `https://${clientId}.d3auth.test/cb` }, new Browser(h.opFetch));
    const tokens = await client.authorizationCodeGrant(appConfig, code.callback, {
      pkceCodeVerifier: code.verifier,
      expectedState: code.state,
      expectedNonce: code.nonce,
    });
    expect(tokens.access_token).toBeTruthy();
    expect(await h.service.db.oidcPayload.count({ where: { kind: 'AccessToken' } })).toBeGreaterThan(0);

    const disabled = await call(`/api/admin/apps/${clientId}/enabled`, { enabled: false });
    expect(disabled.status).toBe(200);
    expect(await disabled.json()).toMatchObject({ tokensRevoked: expect.any(Number) as number });

    // The access token is gone, and so is the client.
    const introspected = await h.opFetch(`${ISSUER}/oidc/token/introspection`, {
      method: 'POST',
      headers: {
        authorization: `Basic ${Buffer.from(`${clientId}:${created.secret}`).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ token: tokens.access_token }),
    });
    expect(introspected.status).toBe(401);

    const { response } = await new Browser(h.opFetch).navigate(
      `${ISSUER}/oidc/auth?client_id=${clientId}&response_type=code&scope=openid&redirect_uri=${encodeURIComponent(`https://${clientId}.d3auth.test/cb`)}`,
    );
    expect(response.status).toBe(400);
  });
});
