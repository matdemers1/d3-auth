import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { exportState, importState, planImport, type AdminState } from '../../src/admin/state.js';
import { seedOnBoot } from '../../src/boot/seed.js';
import { effectiveAccess } from '../../src/authz/effective-roles.js';
import { STEP_UP_WINDOW_MS } from '../../src/console/auth.js';
import { authorize, Browser, ISSUER, startHarness, USER, WEB_CLIENT, webClientConfig, type Harness } from './oidc-harness.js';

// REQ-072. Two things are being proved here.
//
// The first is that a round trip preserves the shape: apps, roles, groups, members and who may
// reach what all come back. The second matters more — that the file is *not* a backup. No
// secret, no password hash, no signing key travels in it, and an instance rebuilt from one tells
// the operator plainly that its apps are secret pending and its people cannot yet sign in.

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

async function consoleSessionWithUid(): Promise<{ call: Call; sessionUid: string }> {
  const call = await consoleSession();
  const row = await h.service.db.session.findFirstOrThrow({ where: { userId: ownerId }, orderBy: { createdAt: 'desc' } });
  return { call, sessionUid: row.oidcSessionUid ?? '' };
}

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  ownerId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
  await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
});

afterAll(async () => {
  // A group grant is access; another file asserting "no access" would be quietly wrong.
  await h.service.db.group.deleteMany({});
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  await h.service.db.group.deleteMany({});
});

describe('an export', () => {
  it('describes the instance and carries nothing secret', async () => {
    const state = await exportState(h.service.db);

    const app = state.apps.find((entry) => entry.client_id === WEB_CLIENT.clientId);
    expect(app).toMatchObject({ client_type: 'confidential_web', enabled: true });
    expect(app?.redirect_uris.length).toBeGreaterThan(0);
    expect(app?.roles.map((role) => role.key)).toContain('member');
    expect(state.people.map((person) => person.email)).toContain(USER.email);

    // The whole file, searched for anything that would let somebody in.
    const stored = await h.service.db.app.findUniqueOrThrow({ where: { clientId: WEB_CLIENT.clientId } });
    const text = JSON.stringify(state);
    expect(text).not.toContain(stored.clientSecretHash ?? '«no secret»');
    expect(text).not.toContain(WEB_CLIENT.secret);
    expect(text).not.toContain('argon2');
    expect(text).not.toContain('privateJwk');
    expect(text).not.toContain('password');
  });

  it('is offered to the owner as a file, and refused to an admin', async () => {
    const call = await consoleSession();
    const answer = await call('/api/admin/state/export');
    expect(answer.status).toBe(200);
    expect(answer.headers.get('content-disposition')).toContain('attachment; filename="d3auth-state-');

    await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'admin' } });
    try {
      expect((await (await consoleSession())('/api/admin/state/export')).status).toBe(403);
    } finally {
      await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
    }
  });
});

describe('an import', () => {
  const incoming = (): AdminState => ({
    version: 1,
    apps: [
      {
        client_id: 'imported-app',
        name: 'Imported App',
        description: 'Arrived in a file',
        client_type: 'confidential_web',
        redirect_uris: ['https://imported.example.test/callback'],
        post_logout_redirect_uris: [],
        roles_claim_name: 'roles',
        enabled: true,
        roles: [
          { key: 'reader', display: 'Reader', description: '', default: true },
          { key: 'writer', display: 'Writer', description: '', default: false },
        ],
      },
    ],
    people: [
      {
        email: 'imported@example.com',
        username: 'imported',
        display_name: 'Imported Person',
        kind: 'guest',
        status: 'active',
        grants: [{ client_id: 'imported-app', roles: ['reader'] }],
      },
    ],
    groups: [
      {
        name: 'Imported Group',
        description: '',
        members: ['imported@example.com'],
        grants: [{ client_id: 'imported-app', roles: ['writer'] }],
      },
    ],
    settings: {},
  });

  beforeEach(async () => {
    await h.service.db.app.deleteMany({ where: { clientId: 'imported-app' } });
    await h.service.db.user.deleteMany({ where: { email: 'imported@example.com' } });
  });

  it('says what it would do and changes nothing (REQ-072)', async () => {
    const plan = await planImport(h.service.db, incoming());
    expect(plan).toMatchObject({
      apps: { create: ['imported-app'] },
      people: { create: ['imported@example.com'] },
      groups: { create: ['Imported Group'] },
      secretPending: ['imported-app'],
      needsReEnrolment: ['imported@example.com'],
      problems: [],
    });

    expect(await h.service.db.app.findUnique({ where: { clientId: 'imported-app' } })).toBeNull();

    const dry = await importState(h.service.db, incoming(), { dryRun: true });
    expect(dry.applied).toBe(false);
    expect(await h.service.db.app.findUnique({ where: { clientId: 'imported-app' } })).toBeNull();
  });

  it('brings the apps, roles, groups and access with it', async () => {
    const result = await importState(h.service.db, incoming(), {});
    expect(result.applied).toBe(true);

    const app = await h.service.db.app.findUniqueOrThrow({
      where: { clientId: 'imported-app' },
      include: { roles: true, redirectUris: true },
    });
    expect(app.roles.map((role) => role.key).sort()).toEqual(['reader', 'writer']);
    expect(app.redirectUris.map((row) => row.uri)).toEqual(['https://imported.example.test/callback']);

    const person = await h.service.db.user.findUniqueOrThrow({ where: { email: 'imported@example.com' } });
    // Direct grant plus the group's, unioned.
    expect(await effectiveAccess(h.service.db, { userId: person.id, clientId: 'imported-app' })).toMatchObject({
      hasGrant: true,
      roles: ['reader', 'writer'],
      from: { direct: true, groups: ['Imported Group'] },
    });
  });

  it('leaves an imported app secret pending, so it cannot be signed in to (R-11)', async () => {
    await importState(h.service.db, incoming(), {});
    const app = await h.service.db.app.findUniqueOrThrow({ where: { clientId: 'imported-app' } });
    expect(app.clientSecretHash).toBeNull();

    // The provider will not serve a confidential client with no secret, so the flow stops here
    // rather than somewhere confusing later.
    const answer = await h.opFetch(
      `${ISSUER}/oidc/auth?client_id=imported-app&response_type=code&scope=openid&redirect_uri=${encodeURIComponent('https://imported.example.test/callback')}`,
      { redirect: 'manual' },
    );
    expect(answer.status).toBeGreaterThanOrEqual(400);
  });

  it('runs twice without doing anything the second time', async () => {
    await importState(h.service.db, incoming(), {});
    const again = await importState(h.service.db, incoming(), {});
    expect(again.apps.create).toEqual([]);
    expect(again.apps.update).toEqual(['imported-app']);
    expect(await h.service.db.role.count({ where: { app: { clientId: 'imported-app' } } })).toBe(2);
    expect(await h.service.db.groupMember.count({ where: { group: { name: 'Imported Group' } } })).toBe(1);
  });

  it('names what it cannot do rather than doing half of it', async () => {
    const base = incoming();
    const broken: AdminState = {
      ...base,
      people: base.people.map((person) => ({ ...person, grants: [...person.grants, { client_id: 'no-such-app', roles: ['reader'] }] })),
      groups: base.groups.map((group) => ({ ...group, members: [...group.members, 'stranger@example.com'] })),
    };

    const plan = await planImport(h.service.db, broken);
    expect(plan.problems).toEqual([
      'imported@example.com is granted "no-such-app", which is not in this file.',
      'Group "Imported Group" lists stranger@example.com, who is not in this file.',
    ]);
  });

  it('is previewed by an owner and applied while the proof is fresh', async () => {
    const call = await consoleSession();
    const preview = await call('/api/admin/state/import/preview', { state: incoming() });
    expect(preview.status).toBe(200);
    expect(await preview.json()).toMatchObject({ applied: false, secretPending: ['imported-app'] });
    // A preview is a preview: it wrote nothing.
    expect(await h.service.db.app.findUnique({ where: { clientId: 'imported-app' } })).toBeNull();

    const applied = await call('/api/admin/state/import', { state: incoming() });
    expect(applied.status).toBe(200);
    expect(await applied.json()).toMatchObject({ applied: true });
    expect(await h.service.db.app.findUnique({ where: { clientId: 'imported-app' } })).not.toBeNull();

    const audited = await h.service.db.auditEvent.findFirstOrThrow({ where: { event: 'state.imported' }, orderBy: { id: 'desc' } });
    expect(audited.detail).toMatchObject({ secretPending: ['imported-app'] });
  });

  it('is refused on a session that has gone cold, and writes nothing', async () => {
    const { call, sessionUid } = await consoleSessionWithUid();
    const stale = new Date(Date.now() - STEP_UP_WINDOW_MS - 60_000);
    await h.service.db.session.updateMany({ where: { oidcSessionUid: sessionUid }, data: { steppedUpAt: stale } });
    const stored = await h.service.provider.Session.findByUid(sessionUid);
    if (stored) {
      stored.loginTs = Math.floor(stale.getTime() / 1000);
      await stored.save(60 * 60);
    }

    const answer = await call('/api/admin/state/import', { state: incoming() });
    expect(answer.status).toBe(401);
    expect(await answer.json()).toMatchObject({ error: 'step_up_required' });
    expect(await h.service.db.app.findUnique({ where: { clientId: 'imported-app' } })).toBeNull();

    // The preview is not behind that guard, because reading what a file would do changes nothing.
    expect((await call('/api/admin/state/import/preview', { state: incoming() })).status).toBe(200);
  });

  it('refuses a file that is not one', async () => {
    const call = await consoleSession();
    const answer = await call('/api/admin/state/import/preview', { state: { version: 99, apps: 'lots' } });
    expect(answer.status).toBe(400);
    expect((await answer.json()) as { problems: string[] }).toMatchObject({ error: 'invalid' });
  });
});

describe('a round trip', () => {
  it('puts back what it took (REQ-072)', async () => {
    const call = await consoleSession();
    const group = (await (await call('/api/admin/groups', { name: 'Round Trip', description: 'There and back' })).json()) as { id: string };
    await call(`/api/admin/groups/${group.id}/members`, { userIds: [ownerId] });
    await call(`/api/admin/groups/${group.id}/access`, { clientId: WEB_CLIENT.clientId, roles: ['admin'] });

    const before = await exportState(h.service.db);

    // Lose the group, then bring it back from the file alone.
    await h.service.db.group.deleteMany({ where: { name: 'Round Trip' } });
    expect(await h.service.db.group.findUnique({ where: { name: 'Round Trip' } })).toBeNull();

    await importState(h.service.db, before, {});

    const after = await exportState(h.service.db);
    expect(after.groups.find((entry) => entry.name === 'Round Trip')).toMatchObject({
      description: 'There and back',
      members: [USER.email],
      grants: [{ client_id: WEB_CLIENT.clientId, roles: ['admin'] }],
    });
    expect(after.apps).toEqual(before.apps);
  });
});

describe('the seed file (REQ-057)', () => {
  const quiet = {
    info: () => undefined,
    warn: () => undefined,
    error: () => undefined,
  } as unknown as Parameters<typeof seedOnBoot>[2]['logger'];

  it('applies on boot, and again on the next boot without doubling anything', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'd3auth-seed-'));
    const file = join(dir, 'seed.json');
    await writeFile(
      file,
      JSON.stringify({
        version: 1,
        apps: [
          {
            client_id: 'seeded-app',
            name: 'Seeded App',
            client_type: 'public_native',
            redirect_uris: ['https://seeded.example.test/cb'],
            roles: [{ key: 'reader', display: 'Reader' }],
          },
        ],
      }),
    );

    await h.service.db.app.deleteMany({ where: { clientId: 'seeded-app' } });
    await seedOnBoot(h.service.db, file, { logger: quiet });
    await seedOnBoot(h.service.db, file, { logger: quiet });

    const app = await h.service.db.app.findUniqueOrThrow({ where: { clientId: 'seeded-app' }, include: { roles: true, redirectUris: true } });
    expect(app.roles).toHaveLength(1);
    expect(app.redirectUris).toHaveLength(1);
    await h.service.db.app.deleteMany({ where: { clientId: 'seeded-app' } });
  });

  it('carries on serving when the file is missing or nonsense', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'd3auth-seed-'));
    await expect(seedOnBoot(h.service.db, join(dir, 'absent.json'), { logger: quiet })).resolves.toBeUndefined();

    const bad = join(dir, 'bad.json');
    await writeFile(bad, JSON.stringify({ version: 99 }));
    await expect(seedOnBoot(h.service.db, bad, { logger: quiet })).resolves.toBeUndefined();
  });
});
