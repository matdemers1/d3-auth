import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';

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
});
