import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import { consoleRouter, faviconCsp, unavailableGate } from '../../src/static.js';

// The real favicon, as the build copies it (AUTH-T-8.1).
const favicon = readFileSync(new URL('../../../console/public/favicon.svg', import.meta.url), 'utf8');

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
    writeFileSync(join(dist, 'favicon.svg'), favicon);
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

  it('serves the favicon as an SVG, with a policy that allows its one style by hash and nothing else', async () => {
    const res = await fetch(`${base}/favicon.svg`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toMatch(/^image\/svg\+xml/);
    expect(await res.text()).toBe(favicon);
    const csp = res.headers.get('content-security-policy') ?? '';
    const style = /<style>([\s\S]*?)<\/style>/.exec(favicon)?.[1] ?? '';
    expect(csp).toBe(faviconCsp(favicon));
    expect(csp).toContain(`style-src 'sha256-${createHash('sha256').update(style).digest('base64')}'`);
    expect(csp).toContain("default-src 'none'");
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('script-src');
  });

  it('draws the same mark in the favicon as in the console: the Keyhole, its lit star in the accent', () => {
    expect(favicon).toContain('<circle cx="32" cy="32" r="26"');
    expect(favicon).toContain('d="M28.5 31.5 L25 45 L39 45 L35.5 31.5"');
    expect(favicon).toMatch(/\.star \{ fill: #8b7cf6; \}/);
    expect(favicon).toContain('@media (prefers-color-scheme: dark)');
  });

  it('does not serve files outside assets or unknown surfaces', async () => {
    expect((await fetch(`${base}/assets/missing.js`)).status).toBe(404);
    expect((await fetch(`${base}/assets/..%2Fsecret.txt`)).status).not.toBe(200);
    expect((await fetch(`${base}/secret.txt`)).status).toBe(404);
    expect((await fetch(`${base}/loginx`)).status).toBe(404);
  });

  it('serves the static unavailable page when readiness is failing (REQ-084)', async () => {
    // The probe stands in for a database that is down; the page must render without one.
    const failing = () => Promise.resolve({ database: false, signingKeys: false, migrations: false });
    const s = createApp({ beforeRouters: [unavailableGate(failing)], routers: [consoleRouter(dist)] }).listen(0, '127.0.0.1');
    await once(s, 'listening');
    try {
      const res = await fetch(`http://127.0.0.1:${(s.address() as AddressInfo).port}/login/abc`);
      expect(res.status).toBe(503);
      expect(res.headers.get('cache-control')).toBe('no-store');
      const html = await res.text();
      expect(html).toMatch(/Sign-in is unavailable/);
      expect(html).not.toMatch(/<script/i);
    } finally {
      s.close();
    }
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
