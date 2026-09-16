import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { importState, type AdminState } from '../../src/admin/state.js';
import { seedOnBoot } from '../../src/boot/seed.js';
import { startHarness, USER, webClientConfig, type Harness } from '../integration/oidc-harness.js';
import { consoleCaller } from './support.js';

// Attack class: becoming more powerful than you were made (REQ-035, REQ-042, REQ-037).
//
// The rule under attack: owner and admin are the two kinds that can change what the system
// trusts, so an account only becomes one with a verified factor, only the owner can make one,
// and there is exactly one owner. The functional tests prove the console's *kind* endpoint keeps
// that rule. An attacker does not use the front door they were shown, so this file tries every
// other door that writes `user.kind`.

let h: Harness;
let config: client.Configuration;
let ownerId: string;

const VICTIM = 'factorless@example.com';

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  ownerId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
  await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
});

afterAll(async () => {
  await h.service.db.user.deleteMany({ where: { email: { in: [VICTIM, 'newcomer@example.com'] } } });
  await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  await h.service.db.user.upsert({
    where: { email: VICTIM },
    create: { email: VICTIM, username: 'factorless', displayName: 'No Factor', status: 'active', kind: 'guest' },
    update: { kind: 'guest', status: 'active' },
  });
  await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
});

const promoting = (email: string, kind: 'owner' | 'admin' | 'guest'): AdminState => ({
  version: 1,
  apps: [],
  people: [{ email, username: email.split('@')[0] ?? 'x', display_name: 'Imported', kind, status: 'active', grants: [] }],
  groups: [],
  settings: {},
});

const kindOf = async (email: string): Promise<string | undefined> =>
  (await h.service.db.user.findUnique({ where: { email }, select: { kind: true } }))?.kind;

describe('through an import', () => {
  it('cannot make a factorless account an admin', async () => {
    const result = await importState(h.service.db, promoting(VICTIM, 'admin'), {});
    expect(await kindOf(VICTIM)).toBe('guest');
    expect(result.problems.join(' ')).toMatch(/factor/i);
  });

  it('cannot create a second owner, or a new admin out of nothing', async () => {
    await importState(h.service.db, promoting('newcomer@example.com', 'owner'), {});
    expect(await h.service.db.user.count({ where: { kind: 'owner' } })).toBe(1);

    await importState(h.service.db, promoting('newcomer@example.com', 'admin'), {});
    // A person the file invents has no credentials at all, so no factor either.
    expect(await kindOf('newcomer@example.com')).not.toBe('admin');
  });

  it('cannot demote the owner', async () => {
    await importState(h.service.db, promoting(USER.email, 'guest'), {});
    expect(await kindOf(USER.email)).toBe('owner');
  });

  it('cannot reactivate somebody who was suspended', async () => {
    await h.service.db.user.update({ where: { email: VICTIM }, data: { status: 'suspended' } });
    // The file says active; the suspension stands anyway.
    await importState(h.service.db, promoting(VICTIM, 'guest'), {});
    expect((await h.service.db.user.findUniqueOrThrow({ where: { email: VICTIM } })).status).toBe('suspended');
  });
});

describe('through the seed file', () => {
  it('is held to the same rule as an import', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'd3auth-adv-'));
    const file = join(dir, 'seed.json');
    await writeFile(file, JSON.stringify(promoting(VICTIM, 'admin')));
    const quiet = { info: () => undefined, warn: () => undefined, error: () => undefined } as unknown as Parameters<typeof seedOnBoot>[2]['logger'];
    await seedOnBoot(h.service.db, file, { logger: quiet });
    expect(await kindOf(VICTIM)).toBe('guest');
  });
});

describe('through the console', () => {
  it('an admin cannot make anybody an admin, themselves included', async () => {
    // An admin with a factor, so the only thing stopping them is the owner-only rule.
    await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'admin' } });
    try {
      const call = await consoleCaller(h, config);
      const victim = await h.service.db.user.findUniqueOrThrow({ where: { email: VICTIM } });
      expect((await call(`/api/admin/people/${victim.id}/kind`, { body: { kind: 'admin' } })).status).toBe(403);
      expect((await call(`/api/admin/people/${ownerId}/kind`, { body: { kind: 'admin' } })).status).toBe(403);
    } finally {
      await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
    }
  });

  it('refuses a kind that is not one, including owner', async () => {
    const call = await consoleCaller(h, config);
    const victim = await h.service.db.user.findUniqueOrThrow({ where: { email: VICTIM } });
    for (const kind of ['owner', 'OWNER', 'superuser', '', null, ['admin']]) {
      expect((await call(`/api/admin/people/${victim.id}/kind`, { body: { kind } })).status).toBe(400);
    }
    expect(await kindOf(VICTIM)).toBe('guest');
  });

  it('an import applied by an admin is refused outright', async () => {
    await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'admin' } });
    try {
      const call = await consoleCaller(h, config);
      expect((await call('/api/admin/state/import', { body: { state: promoting(VICTIM, 'admin') } })).status).toBe(403);
      expect((await call('/api/admin/state/import/preview', { body: { state: promoting(VICTIM, 'admin') } })).status).toBe(403);
    } finally {
      await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
    }
  });
});
