import { randomUUID } from 'node:crypto';
import { afterAll, describe, expect, it } from 'vitest';
import { createDb } from '../../src/db.js';

const db = createDb(process.env.DATABASE_URL ?? '');

afterAll(async () => {
  await db.$disconnect();
});

const unique = (): string => randomUUID().slice(0, 8);

function newUser(overrides: { email?: string; username?: string } = {}) {
  const tag = unique();
  return {
    email: overrides.email ?? `person-${tag}@example.com`,
    username: overrides.username ?? `person-${tag}`,
    displayName: 'Test Person',
  };
}

describe('user identity (REQ-021, REQ-022, REQ-023)', () => {
  it('assigns a UUIDv7 id as sub', async () => {
    const user = await db.user.create({ data: newUser() });
    expect(user.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it('rejects an email that differs only by case', async () => {
    const tag = unique();
    await db.user.create({ data: newUser({ email: `Case-${tag}@Example.com` }) });
    await expect(
      db.user.create({ data: newUser({ email: `case-${tag}@example.com` }) }),
    ).rejects.toThrow(/Unique constraint/);
  });

  it('rejects a username that differs only by case', async () => {
    const tag = unique();
    await db.user.create({ data: newUser({ username: `Alex${tag}` }) });
    await expect(db.user.create({ data: newUser({ username: `alex${tag}` }) })).rejects.toThrow(
      /Unique constraint/,
    );
  });

  it('keeps sub and username when the email changes', async () => {
    const user = await db.user.create({ data: newUser() });
    const updated = await db.user.update({
      where: { id: user.id },
      data: { email: `moved-${unique()}@example.com` },
    });
    expect(updated.id).toBe(user.id);
    expect(updated.username).toBe(user.username);
  });
});

describe('audit_event is append-only (REQ-111)', () => {
  it('accepts inserts', async () => {
    const row = await db.auditEvent.create({ data: { event: 'test.insert', detail: { ok: true } } });
    expect(row.id).toBeGreaterThan(0n);
  });

  it('rejects UPDATE', async () => {
    const row = await db.auditEvent.create({ data: { event: 'test.update' } });
    await expect(
      db.auditEvent.update({ where: { id: row.id }, data: { event: 'tampered' } }),
    ).rejects.toThrow(/append-only/);
  });

  it('rejects DELETE', async () => {
    const row = await db.auditEvent.create({ data: { event: 'test.delete' } });
    await expect(db.auditEvent.delete({ where: { id: row.id } })).rejects.toThrow(/append-only/);
  });

  it('rejects TRUNCATE', async () => {
    await expect(db.$executeRawUnsafe('TRUNCATE audit_event')).rejects.toThrow(/append-only/);
  });

  it('keeps the actor UUID after the user is deleted', async () => {
    const user = await db.user.create({ data: newUser() });
    const row = await db.auditEvent.create({ data: { event: 'test.actor', actorUserId: user.id } });
    await db.user.delete({ where: { id: user.id } });
    const kept = await db.auditEvent.findUniqueOrThrow({ where: { id: row.id } });
    expect(kept.actorUserId).toBe(user.id);
  });
});

describe('cascades', () => {
  it('deleting a user removes credentials and grants but not the app', async () => {
    const user = await db.user.create({ data: newUser() });
    const app = await db.app.create({
      data: {
        clientId: `app-${unique()}`,
        name: 'Cascade App',
        clientType: 'confidential_web',
        roles: { create: [{ key: 'member', displayName: 'Member', sortOrder: 1 }] },
      },
      include: { roles: true },
    });
    await db.passwordCredential.create({ data: { userId: user.id, argon2idHash: 'x' } });
    await db.grant.create({
      data: {
        userId: user.id,
        appId: app.id,
        roles: { create: app.roles.map((r) => ({ roleId: r.id })) },
      },
    });

    await db.user.delete({ where: { id: user.id } });

    expect(await db.passwordCredential.count({ where: { userId: user.id } })).toBe(0);
    expect(await db.grant.count({ where: { userId: user.id } })).toBe(0);
    expect(await db.app.count({ where: { id: app.id } })).toBe(1);
  });
});
