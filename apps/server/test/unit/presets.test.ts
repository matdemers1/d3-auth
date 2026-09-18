import { describe, expect, it } from 'vitest';
import { genericSheet, type SheetApp, type SheetRow } from '../../src/admin/connection.js';
import { parseManifest } from '../../src/admin/manifest.js';
import { buildFromPreset, connectionFor, describePreset, findPreset, PRESETS, readAddress } from '../../src/admin/presets/index.js';
import { bindery } from '../../src/admin/presets/bindery.js';
import { immich } from '../../src/admin/presets/immich.js';

// REQ-142, REQ-143, REQ-144.

const ISSUER = 'https://auth.d3cloud.io';

const built = (raw: unknown) => {
  const result = buildFromPreset(immich, raw);
  if (!result.ok) throw new Error(`expected the preset to build: ${JSON.stringify(result.problems)}`);
  return result;
};

const problemsOf = (raw: unknown): string[] => {
  const result = buildFromPreset(immich, raw);
  return result.ok ? [] : result.problems.map((problem) => `${problem.field} | ${problem.message}`);
};

const byId = (rows: SheetRow[]) => Object.fromEntries(rows.map((row) => [row.id, row]));

const sheetApp = (manifest: ReturnType<typeof built>['manifest']): SheetApp => ({
  clientId: manifest.client_id,
  clientType: manifest.client_type,
  redirectUris: manifest.redirect_uris,
  postLogoutRedirectUris: manifest.post_logout_redirect_uris,
  backchannelLogoutUri: manifest.backchannel_logout_uri ?? null,
  roles: manifest.roles,
});

describe('the registry', () => {
  it('finds presets by key and nothing else', () => {
    expect(findPreset('immich')).toBe(immich);
    expect(findPreset('Immich')).toBeUndefined();
    expect(findPreset('__proto__')).toBeUndefined();
    expect(findPreset('constructor')).toBeUndefined();
    expect(findPreset('toString')).toBeUndefined();
  });

  it('keys are unique and describe themselves without functions', () => {
    expect(new Set(PRESETS.map((preset) => preset.key)).size).toBe(PRESETS.length);
    const described = describePreset(immich);
    expect(JSON.parse(JSON.stringify(described))).toEqual(described);
    expect(described.inputs.map((input) => input.key)).toEqual(['address', 'client_id']);
  });
});

describe('reading an address', () => {
  it('keeps the origin, without a trailing slash', () => {
    expect(readAddress('https://photos.example.com', 'Immich address', 'Immich')).toEqual({ ok: true, value: 'https://photos.example.com' });
    expect(readAddress('  https://Photos.Example.com/ ', 'Immich address', 'Immich')).toEqual({ ok: true, value: 'https://photos.example.com' });
    expect(readAddress('https://photos.example.com:8443/', 'Immich address', 'Immich')).toEqual({ ok: true, value: 'https://photos.example.com:8443' });
    expect(readAddress('https://photos.example.com:443', 'Immich address', 'Immich')).toEqual({ ok: true, value: 'https://photos.example.com' });
    expect(readAddress('http://localhost:2283', 'Immich address', 'Immich')).toEqual({ ok: true, value: 'http://localhost:2283' });
  });

  it.each([
    ['', 'enter the address'],
    ['photos.example.com', 'not a web address'],
    ['http://photos.example.com', 'https://'],
    ['ftp://photos.example.com', 'https://'],
    ['https://photos.example.com/photos', 'nothing after it'],
    ['https://photos.example.com/auth/login', 'nothing after it'],
    ['https://photos.example.com?x=1', '"?"'],
    ['https://photos.example.com/?', '"?"'],
    ['https://photos.example.com#top', '"#"'],
    ['https://*.example.com', 'wildcards'],
    ['https://me:pw@photos.example.com', 'user name and password'],
  ])('refuses %j, naming the input', (value, says) => {
    const result = readAddress(value, 'Immich address', 'Immich');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.message.startsWith('Immich address: ')).toBe(true);
      expect(result.message).toContain(says);
    }
  });
});

describe('the Immich preset builds an ordinary manifest', () => {
  it('registers exactly what the plan says, from the address alone', () => {
    const { inputs, manifest } = built({ address: 'https://photos.example.com/' });
    expect(inputs).toEqual({ address: 'https://photos.example.com', client_id: 'immich' });
    expect(manifest).toMatchObject({
      client_id: 'immich',
      name: 'Immich',
      client_type: 'confidential_web',
      redirect_uris: [
        'https://photos.example.com/auth/login',
        'https://photos.example.com/user-settings',
        'https://photos.example.com/api/oauth/mobile-redirect',
      ],
      post_logout_redirect_uris: ['https://photos.example.com/auth/login'],
      backchannel_logout_uri: 'https://photos.example.com/api/oauth/backchannel-logout',
    });
    expect(manifest.roles.map((role) => [role.key, role.display, role.default])).toEqual([
      ['admin', 'Administrator', false],
      ['user', 'User', true],
    ]);
  });

  it('is the same manifest a person could have pasted', () => {
    const { inputs, manifest } = built({ address: 'https://photos.example.com', client_id: 'photos' });
    const pasted = parseManifest(JSON.parse(JSON.stringify(immich.manifest(inputs))));
    expect(pasted).toEqual({ ok: true, manifest });
  });

  it('names the input, never the manifest field', () => {
    expect(problemsOf({})).toEqual(['address | Immich address: enter the address you open Immich at, like https://photos.example.com.']);
    expect(problemsOf({ address: 'http://photos.example.com' })).toEqual([expect.stringMatching(/^address \| Immich address: /)]);
    expect(problemsOf({ address: 'https://photos.example.com', client_id: 'Not Valid' })).toEqual([expect.stringMatching(/^client_id \| Client ID: /)]);
    expect(problemsOf({ address: 42 })).toEqual(['address | Immich address: must be text.']);
    expect(problemsOf('nonsense')).toEqual([expect.stringMatching(/^address \| /)]);
  });

  it('cannot register something a manifest could not: the console’s own client id is refused through parseManifest', () => {
    expect(problemsOf({ address: 'https://photos.example.com', client_id: 'd3auth-console' })).toEqual([
      'client_id | Client ID: That client id belongs to D3 Auth itself.',
    ]);
  });

  it('ignores answers it did not ask for', () => {
    const { inputs } = built({ address: 'https://photos.example.com', redirect_uris: ['https://evil.example'], extra: 'x' });
    expect(Object.keys(inputs).sort()).toEqual(['address', 'client_id']);
  });
});

describe('the Immich paste sheet', () => {
  const { inputs, manifest } = built({ address: 'https://photos.example.com' });
  const app = sheetApp(manifest);

  it('lists Immich’s fields in Immich’s order, in Immich’s words', () => {
    expect(immich.sheet({ issuer: ISSUER, app, inputs }).map((row) => row.label)).toEqual([
      'Login with OAuth',
      'issuer_url',
      'client_id',
      'client_secret',
      'token_endpoint_auth_method',
      'scope',
      'id_token_signed_response_alg',
      'userinfo_signed_response_alg',
      'prompt',
      'end_session_endpoint',
      'Request Timeout',
      'Allow insecure requests',
      'Storage label claim',
      'Role Claim',
      'Storage quota claim',
      'Default storage quota (GiB)',
      'Button text',
      'Auto register',
      'Auto launch',
      'Mobile redirect URI override',
      'Mobile redirect URI',
    ]);
  });

  it('says what to paste and what to do with each field', () => {
    const rows = byId(immich.sheet({ issuer: ISSUER, app, inputs }));
    expect(rows.enabled).toMatchObject({ value: null, action: 'on' });
    expect(rows.issuer_url).toMatchObject({ value: ISSUER, action: 'set' });
    expect(rows.client_id).toMatchObject({ value: 'immich', action: 'set' });
    expect(rows.token_endpoint_auth_method).toMatchObject({ value: 'client_secret_basic', action: 'set' });
    expect(rows.scope).toMatchObject({ value: 'openid email profile d3:roles', action: 'set' });
    expect(rows.id_token_signed_response_alg).toMatchObject({ value: 'ES256', action: 'set' });
    expect(rows.userinfo_signed_response_alg).toMatchObject({ value: 'none', action: 'leave' });
    expect(rows.storage_label_claim).toMatchObject({ value: 'preferred_username', action: 'leave' });
    expect(rows.role_claim).toMatchObject({ value: 'roles', action: 'set' });
    expect(rows.storage_quota_claim).toMatchObject({ value: 'immich_quota', action: 'leave' });
    expect(rows.auto_register).toMatchObject({ action: 'leave' });
    expect(rows.mobile_override).toMatchObject({ value: null, action: 'on' });
    expect(rows.mobile_redirect_uri).toMatchObject({ value: 'https://photos.example.com/api/oauth/mobile-redirect', action: 'set' });
    // Every redirect Immich will use is one the manifest registered.
    expect(manifest.redirect_uris).toContain(rows.mobile_redirect_uri?.value);
  });

  it('says, before registering, when the secret will appear', () => {
    const before = byId(immich.sheet({ issuer: ISSUER, app, inputs, preview: true })).client_secret;
    expect(before).toMatchObject({ value: null, secret: true });
    expect(before?.why).toMatch(/Created when you press Register/);
    expect(byId(immich.sheet({ issuer: ISSUER, app, inputs })).client_secret?.why).toMatch(/Rotate it/);
  });

  it('never tells anyone to allow insecure requests', () => {
    expect(byId(immich.sheet({ issuer: ISSUER, app, inputs })).allow_insecure_requests).toMatchObject({ value: null, action: 'leave' });
  });

  it('carries the secret only when one is given', () => {
    expect(byId(immich.sheet({ issuer: ISSUER, app, inputs })).client_secret).toMatchObject({ value: null, secret: true });
    expect(byId(immich.sheet({ issuer: ISSUER, app, inputs, secret: 's3cret' })).client_secret).toMatchObject({ value: 's3cret', secret: true });
  });
});

describe('the generic sheet', () => {
  const { manifest } = built({ address: 'https://photos.example.com' });
  const app = sheetApp(manifest);

  it('derives every value from the provider’s protocol choices and the app', () => {
    const rows = byId(genericSheet(ISSUER, app));
    expect(rows.issuer?.value).toBe(ISSUER);
    expect(rows.discovery?.value).toBe(`${ISSUER}/.well-known/openid-configuration`);
    expect(rows.client_id?.value).toBe('immich');
    expect(rows.client_secret).toMatchObject({ value: null, secret: true });
    expect(rows.token_endpoint_auth_method?.value).toBe('client_secret_basic');
    expect(rows.id_token_signing_alg?.value).toBe('ES256');
    expect(rows.pkce?.value).toBe('S256');
    expect(rows.scopes?.value).toBe('openid profile email d3:roles');
    expect(rows.roles_claim?.value).toBe('roles');
    expect(rows.redirect_uris?.value).toEqual(manifest.redirect_uris);
    expect(rows.backchannel_logout_uri?.value).toBe('https://photos.example.com/api/oauth/backchannel-logout');
    expect(rows.end_session_endpoint?.value).toBe(`${ISSUER}/oidc/session/end`);
  });

  it('describes a native app with no roles and no back-channel honestly', () => {
    const rows = byId(
      genericSheet(ISSUER, { ...app, clientType: 'public_native', roles: [], backchannelLogoutUri: null, postLogoutRedirectUris: [] }),
    );
    expect(rows.client_secret).toBeUndefined();
    expect(rows.token_endpoint_auth_method?.value).toBe('none');
    expect(rows.scopes?.value).toBe('openid profile email');
    expect(rows.backchannel_logout_uri).toMatchObject({ value: null, why: expect.stringContaining('slow revoke') as string });
    expect(rows.post_logout_redirect_uris?.value).toBeNull();
  });
});

describe('the connection for a stored app', () => {
  const { inputs, manifest } = built({ address: 'https://photos.example.com' });
  const app = sheetApp(manifest);

  it('adds the paste sheet only for a preset it knows and answers that still read', () => {
    expect(connectionFor(ISSUER, { ...app, preset: 'immich', presetInputs: inputs }).preset?.rows.length).toBeGreaterThan(0);
    expect(connectionFor(ISSUER, { ...app, preset: null, presetInputs: {} }).preset).toBeNull();
    expect(connectionFor(ISSUER, { ...app, preset: 'gone', presetInputs: inputs }).preset).toBeNull();
    // An imported file can carry answers nobody typed here; they are read again, not trusted.
    expect(connectionFor(ISSUER, { ...app, preset: 'immich', presetInputs: { address: 'http://evil.example/x' } }).preset).toBeNull();
  });

  it('never carries a secret unless one is handed to it', () => {
    const text = JSON.stringify(connectionFor(ISSUER, { ...app, preset: 'immich', presetInputs: inputs }));
    expect(text).not.toContain('argon2');
    const rows = connectionFor(ISSUER, { ...app, preset: 'immich', presetInputs: inputs }).rows.filter((row) => row.secret);
    expect(rows.every((row) => row.value === null)).toBe(true);
  });
});

describe('the Bindery preset', () => {
  const build = (raw: unknown) => {
    const result = buildFromPreset(bindery, raw);
    if (!result.ok) throw new Error(`expected the preset to build: ${JSON.stringify(result.problems)}`);
    return result;
  };

  it('builds every URI from the one address, so the http/https mistake cannot be made', () => {
    // The first real registration was refused with invalid_redirect_uri: the https address was
    // registered and Bindery sent the http form. One answer, three URIs, one scheme.
    const { manifest } = build({ address: 'https://bindery.example.com' });
    expect(manifest.redirect_uris).toEqual(['https://bindery.example.com/api/auth/oidc/callback']);
    expect(manifest.post_logout_redirect_uris).toEqual(['https://bindery.example.com/']);
    expect(manifest.backchannel_logout_uri).toBe('https://bindery.example.com/api/auth/oidc/backchannel-logout');
  });

  it('refuses an address that is not one origin over https', () => {
    for (const address of ['http://bindery.example.com', 'https://bindery.example.com/app', 'https://*.example.com', '']) {
      const result = buildFromPreset(bindery, { address });
      expect(result.ok, address).toBe(false);
    }
  });

  it('declares the three roles Bindery maps, with member as the default', () => {
    const { manifest } = build({ address: 'https://bindery.example.com' });
    expect(manifest.roles.map((role) => role.key)).toEqual(['admin', 'member', 'guest']);
    expect(manifest.roles.filter((role) => role.default).map((role) => role.key)).toEqual(['member']);
  });

  it('is a sheet of Bindery’s own fields, and the secret is never in it before there is one', () => {
    const { inputs, manifest } = build({ address: 'https://bindery.example.com' });
    const rows = byId(bindery.sheet({ issuer: ISSUER, app: sheetApp(manifest), inputs, preview: true }));
    // The card asks for exactly these, in this order, and nothing else is a Bindery setting.
    expect(rows.issuer?.value).toBe(ISSUER);
    expect(rows.client_id?.value).toBe('bindery');
    expect(rows.client_secret?.value).toBeNull();
    expect(rows.client_secret?.secret).toBe(true);
    expect(rows.sso_mode?.value).toBe('Optional');
    // Shown to be checked against what Bindery builds, not to be typed.
    expect(rows.redirect_uri?.action).toBe('leave');
    expect(rows.redirect_uri?.value).toBe('https://bindery.example.com/api/auth/oidc/callback');
  });

  it('carries the secret once, when there is one', () => {
    const { inputs, manifest } = build({ address: 'https://bindery.example.com' });
    const rows = byId(bindery.sheet({ issuer: ISSUER, app: sheetApp(manifest), inputs, secret: 'a-secret' }));
    expect(rows.client_secret?.value).toBe('a-secret');
  });
});
