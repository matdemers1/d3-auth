import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { immich } from '../../src/admin/presets/immich.js';
import { exportState, importState, stateSchema } from '../../src/admin/state.js';
import { AUDIT_EVENTS } from '../../src/audit/events.js';
import { STEP_UP_WINDOW_MS } from '../../src/console/auth.js';
import { authorize, Browser, discover, ISSUER, startHarness, USER, webClientConfig, type Harness } from './oidc-harness.js';

// REQ-142, REQ-143. Presets register through the same path as a pasted manifest, with the same
// step-up, and every app can show what it needs to be connected — without ever showing a secret
// that was not generated in that very response.

let h: Harness;
let config: client.Configuration;
let ownerId: string;

type Call = (path: string, body?: unknown) => Promise<Response>;

async function consoleSessionWithUid(): Promise<{ call: Call; sessionUid: string }> {
  const { browser } = await authorize(h, config, {}, new Browser(h.opFetch));
  const cookie = [...browser.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  const call: Call = (path, body) =>
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
  const row = await h.service.db.session.findFirstOrThrow({ where: { userId: ownerId }, orderBy: { createdAt: 'desc' } });
  return { call, sessionUid: row.oidcSessionUid ?? '' };
}

const consoleSession = async (): Promise<Call> => (await consoleSessionWithUid()).call;

interface SheetRow {
  id: string;
  label: string;
  value: string | string[] | null;
  action?: string;
  secret?: true;
}
interface Connection {
  clientId: string;
  rows: SheetRow[];
  preset: { preset: string; where: string; rows: SheetRow[] } | null;
}
interface AppBody {
  clientId: string;
  name: string;
  description: string;
  clientType: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  backchannelLogoutUri: string | null;
  roles: { key: string; displayName: string; description: string; isDefault: boolean; sortOrder: number }[];
  preset: string | null;
  presetInputs: Record<string, string>;
}
interface Created {
  app: AppBody;
  secret?: string;
  connection: Connection;
}

const row = (rows: SheetRow[], id: string): SheetRow | undefined => rows.find((candidate) => candidate.id === id);
const ADDRESS = 'https://photos.d3auth.test';

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  ownerId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
  await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
});

afterAll(async () => {
  await h.service.db.app.deleteMany({ where: { clientId: { startsWith: 'preset-' } } });
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  await h.service.db.app.deleteMany({ where: { clientId: { startsWith: 'preset-' } } });
  await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
});

describe('the preset list', () => {
  it('is served from the registry, to the owner only', async () => {
    const call = await consoleSession();
    const answer = (await (await call('/api/admin/app-presets')).json()) as { presets: { key: string; name: string; inputs: { key: string }[] }[] };
    expect(answer.presets.map((preset) => preset.key)).toContain('immich');
    expect(answer.presets.find((preset) => preset.key === 'immich')?.inputs.map((input) => input.key)).toEqual(['address', 'client_id']);

    await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'admin' } });
    expect((await call('/api/admin/app-presets')).status).toBe(403);
  });
});

describe('previewing a preset', () => {
  it('builds the manifest and the same diff a manifest preview gives, and registers nothing', async () => {
    const call = await consoleSession();
    const answer = await call('/api/admin/app-presets/immich/preview', { inputs: { address: `${ADDRESS}/`, client_id: 'preset-preview' } });
    expect(answer.status).toBe(200);
    const body = (await answer.json()) as { inputs: Record<string, string>; manifest: { redirect_uris: string[] }; diff: { isNew: boolean } };
    expect(body.inputs).toEqual({ address: ADDRESS, client_id: 'preset-preview' });
    expect(body.manifest.redirect_uris).toEqual([`${ADDRESS}/auth/login`, `${ADDRESS}/user-settings`, `${ADDRESS}/api/oauth/mobile-redirect`]);
    expect(body.diff.isNew).toBe(true);
    expect(await h.service.db.app.findUnique({ where: { clientId: 'preset-preview' } })).toBeNull();
  });

  it('refuses a preset that does not exist, including names that are only properties of objects', async () => {
    const call = await consoleSession();
    for (const key of ['nope', '__proto__', 'constructor', 'toString']) {
      const answer = await call(`/api/admin/app-presets/${key}/preview`, { inputs: { address: ADDRESS } });
      expect(answer.status, key).toBe(404);
    }
  });

  it('names the input that is wrong, not the manifest field', async () => {
    const call = await consoleSession();
    const answer = await call('/api/admin/app-presets/immich/preview', { inputs: { address: 'http://photos.example.com/immich' } });
    expect(answer.status).toBe(400);
    const body = (await answer.json()) as { error: string; problems: { field: string; message: string }[] };
    expect(body.error).toBe('invalid_inputs');
    expect(body.problems).toEqual([{ field: 'address', message: expect.stringMatching(/^Immich address: /) as string }]);
  });
});

describe('registering from a preset', () => {
  it('is registering the equivalent manifest: same app, same roles, same URIs — plus the preset remembered', async () => {
    const call = await consoleSession();
    const viaPreset = await call('/api/admin/apps/from-preset', { preset: 'immich', inputs: { address: ADDRESS, client_id: 'preset-a' } });
    expect(viaPreset.status).toBe(201);
    const fromPreset = (await viaPreset.json()) as Created;

    const manifest = immich.manifest({ address: ADDRESS, client_id: 'preset-b' });
    const viaManifest = await call('/api/admin/apps', { manifest });
    expect(viaManifest.status).toBe(201);
    const fromManifest = (await viaManifest.json()) as Created;

    const shape = (app: AppBody) => ({
      name: app.name,
      description: app.description,
      clientType: app.clientType,
      redirectUris: [...app.redirectUris].sort(),
      postLogoutRedirectUris: app.postLogoutRedirectUris,
      backchannelLogoutUri: app.backchannelLogoutUri,
      roles: app.roles,
    });
    expect(shape(fromPreset.app)).toEqual(shape(fromManifest.app));
    expect(fromPreset.app).toMatchObject({ preset: 'immich', presetInputs: { address: ADDRESS, client_id: 'preset-a' } });
    expect(fromManifest.app).toMatchObject({ preset: null, presetInputs: {} });

    // Both answers carry the sheet; only the preset one carries Immich's.
    expect(fromManifest.connection.preset).toBeNull();
    expect(fromPreset.connection.preset?.preset).toBe('immich');
  });

  it('shows the secret exactly once, in the answer and its sheet, and the new app works at once', async () => {
    const call = await consoleSession();
    const created = (await (await call('/api/admin/apps/from-preset', { preset: 'immich', inputs: { address: ADDRESS, client_id: 'preset-once' } })).json()) as Created;
    expect(created.secret).toEqual(expect.any(String));
    const secret = created.secret ?? '';
    expect(row(created.connection.rows, 'client_secret')?.value).toBe(secret);
    expect(row(created.connection.preset?.rows ?? [], 'client_secret')?.value).toBe(secret);

    const stored = await h.service.db.app.findUniqueOrThrow({ where: { clientId: 'preset-once' } });
    expect(stored.clientSecretHash).toMatch(/^\$argon2id\$/);
    expect(JSON.stringify(stored.presetInputs)).not.toContain(secret);

    // No restart: the provider serves the brand new client, with the secret the sheet showed.
    const discovered = await discover(h, 'preset-once', client.ClientSecretBasic(secret));
    const url = client.buildAuthorizationUrl(discovered, {
      redirect_uri: `${ADDRESS}/auth/login`,
      scope: 'openid email profile d3:roles',
      code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
      code_challenge_method: 'S256',
      state: client.randomState(),
      nonce: client.randomNonce(),
    });
    const { response } = await new Browser(h.opFetch).navigate(url.toString());
    expect(response.status).toBe(200);
    expect(new URL(response.url).pathname).toMatch(/^\/login\//);
  });

  it('writes app.registered with the preset in its detail', async () => {
    const call = await consoleSession();
    const before = await h.service.db.auditEvent.aggregate({ _max: { id: true } });
    await call('/api/admin/apps/from-preset', { preset: 'immich', inputs: { address: ADDRESS, client_id: 'preset-audit' } });
    const rows = await h.service.db.auditEvent.findMany({ where: { id: { gt: before._max.id ?? 0n }, event: AUDIT_EVENTS.appRegistered } });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.detail).toMatchObject({ clientId: 'preset-audit', preset: 'immich', roles: ['admin', 'user'] });
    expect(rows[0]?.actorUserId).toBe(ownerId);
  });

  it('refuses an unknown preset, a bad answer and a duplicate, and registers nothing for any of them', async () => {
    const call = await consoleSession();
    expect((await call('/api/admin/apps/from-preset', { preset: 'nope', inputs: { address: ADDRESS, client_id: 'preset-x' } })).status).toBe(404);
    expect((await call('/api/admin/apps/from-preset', { preset: '__proto__', inputs: { address: ADDRESS, client_id: 'preset-x' } })).status).toBe(404);
    expect((await call('/api/admin/apps/from-preset', { inputs: { address: ADDRESS, client_id: 'preset-x' } })).status).toBe(404);

    const bad = await call('/api/admin/apps/from-preset', { preset: 'immich', inputs: { address: 'https://*.example.com', client_id: 'preset-x' } });
    expect(bad.status).toBe(400);
    expect(((await bad.json()) as { problems: { message: string }[] }).problems[0]?.message).toMatch(/^Immich address: /);

    // The console's own client id is refused by parseManifest, exactly as for a pasted manifest.
    const console = await call('/api/admin/apps/from-preset', { preset: 'immich', inputs: { address: ADDRESS, client_id: 'd3auth-console' } });
    expect(console.status).toBe(400);
    expect(((await console.json()) as { problems: { field: string }[] }).problems[0]?.field).toBe('client_id');
    expect(await h.service.db.app.findUnique({ where: { clientId: 'preset-x' } })).toBeNull();

    expect((await call('/api/admin/apps/from-preset', { preset: 'immich', inputs: { address: ADDRESS, client_id: 'preset-dup' } })).status).toBe(201);
    const again = await call('/api/admin/apps/from-preset', { preset: 'immich', inputs: { address: 'https://other.d3auth.test', client_id: 'preset-dup' } });
    expect(again.status).toBe(409);
    const kept = await h.service.db.app.findUniqueOrThrow({ where: { clientId: 'preset-dup' }, include: { redirectUris: true } });
    expect(kept.redirectUris.map((uri) => uri.uri)).not.toContain('https://other.d3auth.test/auth/login');
  });

  it('needs step-up, like registering a manifest, and writes nothing without it', async () => {
    const { call, sessionUid } = await consoleSessionWithUid();
    const stale = new Date(Date.now() - STEP_UP_WINDOW_MS - 60_000);
    await h.service.db.session.updateMany({ where: { oidcSessionUid: sessionUid }, data: { steppedUpAt: stale } });
    const stored = await h.service.provider.Session.findByUid(sessionUid);
    if (stored) {
      stored.loginTs = Math.floor(stale.getTime() / 1000);
      await stored.save(60 * 60);
    }

    const answer = await call('/api/admin/apps/from-preset', { preset: 'immich', inputs: { address: ADDRESS, client_id: 'preset-cold' } });
    expect(answer.status).toBe(401);
    expect(await answer.json()).toMatchObject({ error: 'step_up_required' });
    expect(await h.service.db.app.findUnique({ where: { clientId: 'preset-cold' } })).toBeNull();

    // Previewing changes nothing, so it is not behind that guard.
    expect((await call('/api/admin/app-presets/immich/preview', { inputs: { address: ADDRESS, client_id: 'preset-cold' } })).status).toBe(200);
  });

  it('is the owner’s alone', async () => {
    const call = await consoleSession();
    await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'admin' } });
    expect((await call('/api/admin/apps/from-preset', { preset: 'immich', inputs: { address: ADDRESS, client_id: 'preset-admin' } })).status).toBe(403);
    expect((await call('/api/admin/app-presets/immich/preview', { inputs: { address: ADDRESS } })).status).toBe(403);
    expect(await h.service.db.app.findUnique({ where: { clientId: 'preset-admin' } })).toBeNull();
  });
});

describe('the connection sheet', () => {
  it('matches what the provider publishes in discovery', async () => {
    const call = await consoleSession();
    await call('/api/admin/apps/from-preset', { preset: 'immich', inputs: { address: ADDRESS, client_id: 'preset-sheet' } });
    const sheet = (await (await call('/api/admin/apps/preset-sheet/connection')).json()) as Connection;
    const metadata = (await (await h.opFetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    const value = (id: string) => row(sheet.rows, id)?.value;

    expect(value('issuer')).toBe(metadata.issuer);
    expect(value('discovery')).toBe(`${ISSUER}/.well-known/openid-configuration`);
    expect(value('end_session_endpoint')).toBe(metadata.end_session_endpoint);
    expect(metadata.id_token_signing_alg_values_supported).toContain(value('id_token_signing_alg'));
    expect(metadata.token_endpoint_auth_methods_supported).toContain(value('token_endpoint_auth_method'));
    expect(metadata.code_challenge_methods_supported).toEqual([value('pkce')]);
    for (const scope of String(value('scopes')).split(' ')) expect(metadata.scopes_supported).toContain(scope);
    expect(metadata.claims_supported).toContain(value('roles_claim'));

    // And with the app row, and with the client metadata the provider actually serves.
    const app = await h.service.db.app.findUniqueOrThrow({ where: { clientId: 'preset-sheet' }, include: { redirectUris: true } });
    expect([...(value('redirect_uris') as string[])].sort()).toEqual(app.redirectUris.map((uri) => uri.uri).sort());
    expect(value('backchannel_logout_uri')).toBe(app.backchannelLogoutUri);
    const served = await h.service.provider.Client.find('preset-sheet');
    expect(served?.idTokenSignedResponseAlg).toBe(value('id_token_signing_alg'));
    expect(served?.tokenEndpointAuthMethod).toBe(value('token_endpoint_auth_method'));

    // The preset sheet is Immich's settings screen, with this app's values.
    expect(sheet.preset?.where).toBe('Administration → Settings → Authentication → OAuth');
    expect(row(sheet.preset?.rows ?? [], 'issuer_url')?.value).toBe(metadata.issuer);
    expect(row(sheet.preset?.rows ?? [], 'client_id')?.value).toBe('preset-sheet');
  });

  it('gives a rotated secret once, in the rotation’s answer and its sheet', async () => {
    const call = await consoleSession();
    const created = (await (await call('/api/admin/apps/from-preset', { preset: 'immich', inputs: { address: ADDRESS, client_id: 'preset-rotate' } })).json()) as Created;
    const rotated = (await (await call('/api/admin/apps/preset-rotate/secret', {})).json()) as { secret: string; connection: Connection };
    expect(rotated.secret).not.toBe(created.secret);
    expect(row(rotated.connection.rows, 'client_secret')?.value).toBe(rotated.secret);
    expect(row(rotated.connection.preset?.rows ?? [], 'client_secret')?.value).toBe(rotated.secret);

    const text = await (await call('/api/admin/apps/preset-rotate/connection')).text();
    expect(text).not.toContain(rotated.secret);
  });

  it('shows a manifest app its generic sheet, and 404s an app that does not exist', async () => {
    const call = await consoleSession();
    const sheet = (await (await call('/api/admin/apps/web-app/connection')).json()) as Connection;
    expect(sheet.preset).toBeNull();
    expect(row(sheet.rows, 'client_id')?.value).toBe('web-app');
    expect((await call('/api/admin/apps/not-an-app/connection')).status).toBe(404);
  });
});

// Attack: read a secret back. The secret is shown when it is made and never again; the sheet is
// the obvious place somebody would go looking for it, so this tries every way in.
describe('reading a secret back from the sheet', () => {
  it('finds no secret and no hash, however it is asked', async () => {
    const call = await consoleSession();
    const created = (await (await call('/api/admin/apps/from-preset', { preset: 'immich', inputs: { address: ADDRESS, client_id: 'preset-leak' } })).json()) as Created;
    const secret = created.secret ?? '';
    expect(secret).not.toBe('');
    const rotated = (await (await call('/api/admin/apps/preset-leak/secret', {})).json()) as { secret: string };
    const { clientSecretHash } = await h.service.db.app.findUniqueOrThrow({ where: { clientId: 'preset-leak' } });
    expect(clientSecretHash).toBeTruthy();

    const reads = [
      '/api/admin/apps/preset-leak/connection',
      '/api/admin/apps/preset-leak/connection?secret=1&reveal=true',
      '/api/admin/apps/preset-leak/connection?includeSecret=true',
      '/api/admin/apps/preset-leak',
      '/api/admin/apps',
      '/api/admin/app-presets',
    ];
    for (const path of reads) {
      const answer = await call(path);
      expect(answer.status, path).toBe(200);
      const text = await answer.text();
      expect(text, path).not.toContain(secret);
      expect(text, path).not.toContain(rotated.secret);
      expect(text, path).not.toContain(clientSecretHash ?? 'unreachable');
      expect(text, path).not.toMatch(/argon2/i);
    }

    // A POST to the sheet is not a way to mint or read one either.
    expect([404, 405]).toContain((await call('/api/admin/apps/preset-leak/connection', {})).status);

    const sheet = (await (await call('/api/admin/apps/preset-leak/connection')).json()) as Connection;
    for (const secretRow of [...sheet.rows, ...(sheet.preset?.rows ?? [])].filter((candidate) => candidate.secret)) {
      expect(secretRow.value).toBeNull();
    }

    // The state file carries the preset and its answers, and still no secret.
    const state = JSON.stringify(await exportState(h.service.db));
    expect(state).not.toContain(rotated.secret);
    expect(state).not.toMatch(/argon2/i);
  });

  it('is not readable without a session, or by an admin who is not the owner', async () => {
    const call = await consoleSession();
    await call('/api/admin/apps/from-preset', { preset: 'immich', inputs: { address: ADDRESS, client_id: 'preset-guarded' } });
    expect((await h.opFetch(`${ISSUER}/api/admin/apps/preset-guarded/connection`, { headers: { accept: 'application/json' } })).status).toBe(401);
    await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'admin' } });
    expect((await call('/api/admin/apps/preset-guarded/connection')).status).toBe(403);
  });
});

describe('the state file', () => {
  it('carries the preset and its answers, and brings them back', async () => {
    const call = await consoleSession();
    await call('/api/admin/apps/from-preset', { preset: 'immich', inputs: { address: ADDRESS, client_id: 'preset-state' } });
    const state = await exportState(h.service.db);
    const exported = state.apps.find((app) => app.client_id === 'preset-state');
    expect(exported).toMatchObject({ preset: 'immich', preset_inputs: { address: ADDRESS, client_id: 'preset-state' } });

    await h.service.db.app.delete({ where: { clientId: 'preset-state' } });
    const parsed = stateSchema.parse(JSON.parse(JSON.stringify({ ...state, apps: [exported], people: [], groups: [], settings: {} })));
    await importState(h.service.db, parsed, {});
    const back = await h.service.db.app.findUniqueOrThrow({ where: { clientId: 'preset-state' } });
    expect(back.preset).toBe('immich');
    expect(back.presetInputs).toEqual({ address: ADDRESS, client_id: 'preset-state' });
  });

  it('imports a file from before presets, leaving a recorded preset alone', async () => {
    const call = await consoleSession();
    await call('/api/admin/apps/from-preset', { preset: 'immich', inputs: { address: ADDRESS, client_id: 'preset-old-file' } });
    const old = stateSchema.parse({
      version: 1,
      apps: [{ client_id: 'preset-old-file', name: 'Immich', client_type: 'confidential_web', redirect_uris: [`${ADDRESS}/auth/login`] }],
    });
    const result = await importState(h.service.db, old, {});
    expect(result.problems).toEqual([]);
    expect((await h.service.db.app.findUniqueOrThrow({ where: { clientId: 'preset-old-file' } })).preset).toBe('immich');
  });

  it('says so when a file names a preset this version does not know', async () => {
    const file = stateSchema.parse({
      version: 1,
      apps: [
        {
          client_id: 'preset-unknown',
          name: 'Something',
          client_type: 'confidential_web',
          redirect_uris: [`${ADDRESS}/cb`],
          preset: 'not-a-preset',
          preset_inputs: { address: ADDRESS },
        },
      ],
    });
    const result = await importState(h.service.db, file, { dryRun: true });
    expect(result.problems).toEqual([expect.stringContaining('"not-a-preset"') as string]);
    expect(stateSchema.safeParse({ version: 1, apps: [{ ...file.apps[0], preset_inputs: { address: 42 } }] }).success).toBe(false);
  });
});
