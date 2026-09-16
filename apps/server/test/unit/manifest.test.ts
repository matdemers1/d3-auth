import { describe, expect, it } from 'vitest';
import { diffManifest, parseManifest, type ExistingApp, type Manifest } from '../../src/admin/manifest.js';

// REQ-046, REQ-047, REQ-048.

const good = {
  client_id: 'bindery',
  name: 'Bindery',
  client_type: 'confidential_web',
  redirect_uris: ['https://bindery.d3cloud.io/api/auth/oidc/callback'],
  post_logout_redirect_uris: ['https://bindery.d3cloud.io/'],
  backchannel_logout_uri: 'https://bindery.d3cloud.io/api/auth/oidc/backchannel-logout',
  roles: [
    { key: 'admin', display: 'Administrator', description: 'Manages accounts and libraries' },
    { key: 'member', display: 'Member', description: 'Own libraries', default: true },
  ],
};

const parsed = (input: unknown): Manifest => {
  const result = parseManifest(input);
  if (!result.ok) throw new Error(`expected a valid manifest: ${JSON.stringify(result.problems)}`);
  return result.manifest;
};

const problemsOf = (input: unknown): string[] => {
  const result = parseManifest(input);
  return result.ok ? [] : result.problems.map((problem) => `${problem.field}: ${problem.message}`);
};

describe('reading a manifest', () => {
  it('accepts the documented example and fills in the defaults', () => {
    const manifest = parsed(good);
    expect(manifest).toMatchObject({ client_id: 'bindery', roles_claim_name: 'roles', description: '' });
    expect(manifest.roles[0]).toMatchObject({ key: 'admin', default: false });
    expect(manifest.roles[1]).toMatchObject({ key: 'member', default: true });
  });

  it('names the field that is wrong', () => {
    expect(problemsOf({ ...good, client_id: 'Not A Client Id' })).toEqual([expect.stringContaining('client_id') as string]);
    expect(problemsOf({ ...good, redirect_uris: [] })).toEqual([expect.stringContaining('at least one redirect URI') as string]);
    expect(problemsOf({ ...good, name: '' })).toEqual([expect.stringContaining('name') as string]);
  });

  it('refuses redirect URIs that an exact match cannot save you from', () => {
    // A wildcard is not a URI; http on a real host puts an authorization code in the clear; a
    // fragment is not sent to the server at all.
    expect(problemsOf({ ...good, redirect_uris: ['https://bindery.d3cloud.io/*'] })).toEqual([expect.stringContaining('wildcard') as string]);
    expect(problemsOf({ ...good, redirect_uris: ['http://bindery.d3cloud.io/cb'] })).toEqual([expect.stringContaining('https') as string]);
    expect(problemsOf({ ...good, redirect_uris: ['https://bindery.d3cloud.io/cb#token'] })).toEqual([
      expect.stringContaining('fragment') as string,
    ]);
    expect(problemsOf({ ...good, redirect_uris: ['/callback'] })).toEqual([expect.stringContaining('absolute') as string]);
  });

  it('allows localhost for development and a custom scheme for a native app', () => {
    expect(problemsOf({ ...good, redirect_uris: ['http://localhost:4000/callback'] })).toEqual([]);
    expect(
      problemsOf({
        ...good,
        client_type: 'public_native',
        backchannel_logout_uri: undefined,
        redirect_uris: ['com.d3cloud.burrow:/callback', 'http://127.0.0.1:1717/cb'],
      }),
    ).toEqual([]);
  });

  it('refuses a role declared twice', () => {
    const twice = { ...good, roles: [...good.roles, { key: 'admin', display: 'Admin again' }] };
    expect(problemsOf(twice)).toEqual([expect.stringContaining('declared twice') as string]);
  });
});

describe('diffing a manifest against what is registered', () => {
  const existing: ExistingApp = {
    name: 'Bindery',
    description: '',
    clientType: 'confidential_web',
    backchannelLogoutUri: 'https://bindery.d3cloud.io/api/auth/oidc/backchannel-logout',
    rolesClaimName: 'roles',
    postLogoutRedirectUris: ['https://bindery.d3cloud.io/'],
    redirectUris: [{ uri: 'https://bindery.d3cloud.io/api/auth/oidc/callback' }],
    roles: [
      { key: 'admin', displayName: 'Administrator', description: 'Manages accounts and libraries', sortOrder: 2, isDefault: false, _count: { grantRoles: 0 } },
      { key: 'member', displayName: 'Member', description: 'Own libraries', sortOrder: 1, isDefault: true, _count: { grantRoles: 3 } },
    ],
  };

  it('says nothing changed when nothing changed', () => {
    const diff = diffManifest(parsed(good), existing);
    expect(diff).toMatchObject({ isNew: false, changed: [], blocking: [] });
    expect(diff.roles).toEqual({ added: [], removed: [], changed: [] });
    expect(diff.redirectUris).toEqual({ added: [], removed: [] });
  });

  it('reports a brand new app as new', () => {
    const diff = diffManifest(parsed(good), null);
    expect(diff.isNew).toBe(true);
    expect(diff.roles.added.map((role) => role.key)).toEqual(['admin', 'member']);
  });

  it('lists what would change', () => {
    const changed = parsed({
      ...good,
      name: 'Bindery, renamed',
      redirect_uris: ['https://bindery.d3cloud.io/api/auth/oidc/callback', 'https://bindery.d3cloud.io/other'],
      roles: [...good.roles, { key: 'guest', display: 'Guest' }],
    });
    const diff = diffManifest(changed, existing);
    expect(diff.changed).toEqual([{ field: 'name', from: 'Bindery', to: 'Bindery, renamed' }]);
    expect(diff.redirectUris.added).toEqual(['https://bindery.d3cloud.io/other']);
    expect(diff.roles.added.map((role) => role.key)).toEqual(['guest']);
  });

  it('blocks removing a role somebody holds, and allows removing one nobody does', () => {
    const withoutMember = parsed({ ...good, roles: [good.roles[0]] });
    const blocked = diffManifest(withoutMember, existing);
    expect(blocked.roles.removed.map((role) => role.key)).toEqual(['member']);
    expect(blocked.blocking.map((role) => role.key)).toEqual(['member']);

    const withoutAdmin = parsed({ ...good, roles: [good.roles[1]] });
    const allowed = diffManifest(withoutAdmin, existing);
    expect(allowed.roles.removed.map((role) => role.key)).toEqual(['admin']);
    expect(allowed.blocking).toEqual([]);
  });

  it('notices a renamed role without treating it as a removal', () => {
    const renamed = parsed({ ...good, roles: [{ ...good.roles[0], display: 'Admin' }, good.roles[1]] });
    const diff = diffManifest(renamed, existing);
    expect(diff.roles.changed.map((role) => role.key)).toEqual(['admin']);
    expect(diff.roles.removed).toEqual([]);
  });
});
