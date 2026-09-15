import { once } from 'node:events';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import { consoleRouter } from '../../src/static.js';

describe('console statics (REQ-061)', () => {
  let dist: string;
  let server: Server;
  let base: string;

  beforeAll(async () => {
    dist = mkdtempSync(join(tmpdir(), 'd3auth-console-'));
    mkdirSync(join(dist, 'assets'));
    writeFileSync(join(dist, 'index.html'), '<!doctype html><div id="root"></div>');
    writeFileSync(join(dist, 'assets', 'index-abc123.js'), 'console.log(1)');
    writeFileSync(join(dist, 'secret.txt'), 'outside assets');
    server = createApp({ routers: [consoleRouter(dist)] }).listen(0, '127.0.0.1');
    await once(server, 'listening');
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => {
    server.close();
    rmSync(dist, { recursive: true, force: true });
  });

  it.each(['/login', '/login/uid-1', '/account', '/account/security', '/admin', '/admin/users/42'])(
    'serves the shell at %s without caching',
    async (path) => {
      const res = await fetch(base + path);
      expect(res.status).toBe(200);
      expect(res.headers.get('cache-control')).toBe('no-store');
      expect(await res.text()).toContain('id="root"');
    },
  );

  it('serves hashed assets as immutable', async () => {
    const res = await fetch(`${base}/assets/index-abc123.js`);
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toMatch(/immutable/);
  });

  it('does not serve files outside assets or unknown surfaces', async () => {
    expect((await fetch(`${base}/assets/missing.js`)).status).toBe(404);
    expect((await fetch(`${base}/assets/..%2Fsecret.txt`)).status).not.toBe(200);
    expect((await fetch(`${base}/secret.txt`)).status).toBe(404);
    expect((await fetch(`${base}/loginx`)).status).toBe(404);
  });

  it('answers 503 on console routes when the build is missing', async () => {
    const empty = mkdtempSync(join(tmpdir(), 'd3auth-empty-'));
    const s = createApp({ routers: [consoleRouter(empty)] }).listen(0, '127.0.0.1');
    await once(s, 'listening');
    try {
      const res = await fetch(`http://127.0.0.1:${(s.address() as AddressInfo).port}/login`);
      expect(res.status).toBe(503);
    } finally {
      s.close();
      rmSync(empty, { recursive: true, force: true });
    }
  });
});
