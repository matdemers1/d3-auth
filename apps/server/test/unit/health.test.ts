import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import { newestMigration, shippedMigrations, type ReadinessProbe } from '../../src/health.js';

describe('health endpoints', () => {
  let server: Server;
  let base: string;

  beforeAll(async () => {
    server = createApp().listen(0, '127.0.0.1');
    await once(server, 'listening');
    const { port } = server.address() as AddressInfo;
    base = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  });

  it.each(['/healthz', '/readyz'])('%s answers 200 and is never cached', async (path) => {
    const res = await fetch(base + path);
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
  });

  it('does not advertise Express', async () => {
    const res = await fetch(`${base}/healthz`);
    expect(res.headers.get('x-powered-by')).toBeNull();
  });

  it('/health is 503 with no readiness wired, and never cached', async () => {
    const res = await fetch(`${base}/health`);
    expect(res.status).toBe(503);
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(await res.json()).toEqual({ ok: false, schema: null });
  });
});

describe('/health (SHP-D-019, SHP-D-022)', () => {
  async function health(readiness: ReadinessProbe): Promise<{ status: number; body: { ok: boolean; schema: string | null } }> {
    const server: Server = createApp({ readiness }).listen(0, '127.0.0.1');
    await once(server, 'listening');
    try {
      const { port } = server.address() as AddressInfo;
      const res = await fetch(`http://127.0.0.1:${port}/health`);
      return { status: res.status, body: (await res.json()) as { ok: boolean; schema: string | null } };
    } finally {
      server.close();
    }
  }

  it('is ok with the newest shipped migration when the database answers and migrations are applied', async () => {
    const res = await health(() => Promise.resolve({ database: true, signingKeys: false, migrations: true }));
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true, schema: newestMigration() });
    expect(res.body.schema).toBe(shippedMigrations().at(-1));
  });

  it('ignores signingKeys — /health only cares about the database and migrations', async () => {
    const res = await health(() => Promise.resolve({ database: true, signingKeys: false, migrations: true }));
    expect(res.status).toBe(200);
  });

  it('is unavailable when the database is down', async () => {
    const res = await health(() => Promise.resolve({ database: false, signingKeys: true, migrations: false }));
    expect(res.status).toBe(503);
    expect(res.body).toEqual({ ok: false, schema: null });
  });

  it('is unavailable when migrations are not fully applied', async () => {
    const res = await health(() => Promise.resolve({ database: true, signingKeys: true, migrations: false }));
    expect(res.status).toBe(503);
    expect(res.body).toEqual({ ok: false, schema: null });
  });
});
