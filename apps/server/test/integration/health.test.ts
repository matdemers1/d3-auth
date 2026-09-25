import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, describe, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import { createDb } from '../../src/db.js';
import { appliedSchema, databaseReadiness, shippedMigrations, type ReadinessProbe, type SchemaProbe } from '../../src/health.js';
import { loadSigningKeys } from '../../src/oidc/keys.js';
import { createKekCrypto } from '../../src/security/kek.js';
import { testDb } from './helpers.js';

const db = testDb();

afterAll(async () => {
  await db.$disconnect();
});

async function readyz(readiness: ReadinessProbe): Promise<{ status: number; body: { status: string; checks: Record<string, boolean> } }> {
  const server: Server = createApp({ readiness }).listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const { port } = server.address() as AddressInfo;
    const res = await fetch(`http://127.0.0.1:${port}/readyz`);
    return { status: res.status, body: (await res.json()) as { status: string; checks: Record<string, boolean> } };
  } finally {
    server.close();
  }
}

async function health(
  readiness: ReadinessProbe,
  schema: SchemaProbe = appliedSchema(db),
): Promise<{ status: number; body: { ok: boolean; schema: string | null } }> {
  const server: Server = createApp({ readiness, schema }).listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const { port } = server.address() as AddressInfo;
    const res = await fetch(`http://127.0.0.1:${port}/health`);
    return { status: res.status, body: (await res.json()) as { ok: boolean; schema: string | null } };
  } finally {
    server.close();
  }
}

describe('/readyz (REQ-113)', () => {
  it('is ready when the database answers, keys exist and migrations are applied', async () => {
    await db.signingKey.deleteMany();
    await loadSigningKeys(db, createKekCrypto(randomBytes(32)));
    const res = await readyz(databaseReadiness(db));
    expect(res.status).toBe(200);
    expect(res.body.checks).toEqual({ database: true, signingKeys: true, migrations: true });
  });

  it('is unavailable when the database is down', async () => {
    const unreachable = createDb('postgresql://d3auth:d3auth@127.0.0.1:1/d3auth_test');
    try {
      const res = await readyz(databaseReadiness(unreachable));
      expect(res.status).toBe(503);
      expect(res.body.checks.database).toBe(false);
    } finally {
      await unreachable.$disconnect();
    }
  });

  it('is unavailable without a current signing key', async () => {
    await db.signingKey.deleteMany();
    const res = await readyz(databaseReadiness(db));
    expect(res.status).toBe(503);
    expect(res.body.checks).toMatchObject({ database: true, signingKeys: false });
  });

  it('is unavailable when the image ships a migration the database has not applied', async () => {
    const res = await readyz(databaseReadiness(db, [...shippedMigrations(), '9999_not_applied']));
    expect(res.status).toBe(503);
    expect(res.body.checks.migrations).toBe(false);
  });

  it('knows the migrations this build ships', () => {
    expect(shippedMigrations()).toContain('0001_init');
  });
});

describe('/health (SHP-D-019, SHP-D-022)', () => {
  it('is ok with the newest migration schema when the database answers and migrations are applied', async () => {
    await db.signingKey.deleteMany();
    const res = await health(databaseReadiness(db));
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true, schema: shippedMigrations().at(-1) });
  });

  it('reports the database, not the image, after an image-only rollback past a migration', async () => {
    // An older image ships one migration fewer; the database keeps the newer one applied.
    const older = shippedMigrations().slice(0, -1);
    const res = await health(databaseReadiness(db, older));
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true, schema: shippedMigrations().at(-1) });
  });

  it('does not require a signing key, unlike /readyz', async () => {
    await db.signingKey.deleteMany();
    const readiness = databaseReadiness(db);
    const [ready, health200] = await Promise.all([readyz(readiness), health(readiness)]);
    expect(ready.status).toBe(503);
    expect(ready.body.checks.signingKeys).toBe(false);
    expect(health200.status).toBe(200);
  });

  it('is unavailable when the database is down', async () => {
    const unreachable = createDb('postgresql://d3auth:d3auth@127.0.0.1:1/d3auth_test');
    try {
      const res = await health(databaseReadiness(unreachable), appliedSchema(unreachable));
      expect(res.status).toBe(503);
      expect(res.body).toEqual({ ok: false, schema: null });
    } finally {
      await unreachable.$disconnect();
    }
  });

  it('is unavailable when the image ships a migration the database has not applied', async () => {
    const res = await health(databaseReadiness(db, [...shippedMigrations(), '9999_not_applied']));
    expect(res.status).toBe(503);
    expect(res.body).toEqual({ ok: false, schema: null });
  });
});
