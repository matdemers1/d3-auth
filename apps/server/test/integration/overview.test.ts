import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { overview } from '../../src/admin/overview.js';
import { authorize, Browser, ISSUER, startHarness, USER, webClientConfig, type Harness } from './oidc-harness.js';

// REQ-073. The home screen is only worth having if it is wrong when the instance is wrong, so
// what is tested here is the unhappy half: a failing readiness check turns a tile red, a mail
// test that failed says invites are not arriving, and the checklist disappears once there is
// nothing left on it.

let h: Harness;
let config: client.Configuration;
let ownerId: string;

const allGood = () => Promise.resolve({ database: true, signingKeys: true, migrations: true });

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  ownerId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
  await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
});

afterAll(async () => {
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
});

describe('the tiles', () => {
  it('say what is wrong in words somebody can act on', async () => {
    const view = await overview(h.service.db, () => Promise.resolve({ database: true, signingKeys: false, migrations: false }));
    const tile = (key: string) => view.tiles.find((entry) => entry.key === key);

    expect(tile('database')).toMatchObject({ ok: true });
    expect(tile('keys')).toMatchObject({ ok: false });
    expect(tile('keys')?.detail).toContain('New sign-ins will fail');
    expect(tile('migrations')).toMatchObject({ ok: false });
    expect(tile('migrations')?.detail).toContain('has not run');
  });

  it('name the algorithms that are actually signing', async () => {
    const view = await overview(h.service.db, allGood);
    expect(view.tiles.find((tile) => tile.key === 'keys')?.detail).toMatch(/ES256|RS256/);
  });

  it('treat mail as working only if the *last* test delivered', async () => {
    // The audit table refuses deletes (REQ-111), so this walks forward the way an operator would:
    // a failed test, then a successful one. The latest is the one that counts.
    await h.service.db.auditEvent.create({ data: { event: 'mail.tested', detail: { delivered: false } } });
    const failed = await overview(h.service.db, allGood);
    expect(failed.tiles.find((tile) => tile.key === 'mail')).toMatchObject({ ok: false });
    expect(failed.tiles.find((tile) => tile.key === 'mail')?.detail).toContain('not arriving');

    await h.service.db.auditEvent.create({ data: { event: 'mail.tested', detail: { delivered: true } } });
    const worked = await overview(h.service.db, allGood);
    expect(worked.tiles.find((tile) => tile.key === 'mail')).toMatchObject({ ok: true });
    expect(worked.tiles.find((tile) => tile.key === 'mail')?.detail).toContain('delivered');
  });
});

describe('the rest of the page', () => {
  it('counts what the console links to, and shows what just happened', async () => {
    const view = await overview(h.service.db, allGood);
    expect(view.counts.people).toBeGreaterThan(0);
    expect(view.counts.apps).toBeGreaterThan(0);
    expect(view.recent.length).toBeGreaterThan(0);
    // The same shape the audit screen uses, actor resolved rather than a bare uuid.
    expect(view.recent[0]).toHaveProperty('event');
    expect(view.recent[0]).toHaveProperty('actor');
  });

  it('keeps the checklist only while something is undone', async () => {
    await h.service.db.auditEvent.create({ data: { event: 'mail.tested', detail: { delivered: false } } });
    const early = await overview(h.service.db, allGood);
    expect(early.checklist?.find((step) => step.key === 'mail')).toMatchObject({ done: false });
    // This instance already has an owner and an app, so those boxes are ticked without being told.
    expect(early.checklist?.find((step) => step.key === 'app')).toMatchObject({ done: true });
    expect(early.checklist?.find((step) => step.key === 'owner')).toMatchObject({ done: true });

    // With every box ticked — owner, an app, somebody invited, mail delivering — the checklist
    // stops taking up room. It is scaffolding, not furniture.
    await h.service.db.user.upsert({
      where: { email: 'checklist@example.com' },
      create: { email: 'checklist@example.com', username: 'checklist', displayName: 'Checklist Person' },
      update: {},
    });
    await h.service.db.auditEvent.create({ data: { event: 'mail.tested', detail: { delivered: true } } });
    const done = await overview(h.service.db, allGood);
    expect(done.checklist).toBeNull();
  });
});

describe('who may see it', () => {
  it('is for admins, not guests', async () => {
    const call = async () => {
      const { browser } = await authorize(h, config, {}, new Browser(h.opFetch));
      const cookie = [...browser.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
      return h.opFetch(`${ISSUER}/api/admin/overview`, { headers: { cookie, accept: 'application/json' } });
    };

    expect((await call()).status).toBe(200);

    await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'guest' } });
    try {
      expect((await call()).status).toBe(403);
    } finally {
      await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
    }
  });
});
