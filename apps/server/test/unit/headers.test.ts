import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { consoleCsp, PROVIDER_CSP, securityHeaders, THEME_BOOT_SCRIPT_HASH, withStyleNonce } from '../../src/security/headers.js';

const CONSOLE_CSP = consoleCsp('NONCE');

// The console's one inline script (REQ-132, D-066): the theme boot script in index.html. The CSP
// has no 'unsafe-inline', so the script runs only because its hash is allowed — and only that
// script. The hash here is computed from the file, so editing either one alone fails.

const indexHtml = readFileSync(new URL('../../../console/index.html', import.meta.url), 'utf8');
const inlineScripts = [...indexHtml.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((match) => match[1] ?? '');

describe('the console CSP and its one inline script', () => {
  it('index.html has exactly one inline script', () => {
    expect(inlineScripts).toHaveLength(1);
  });

  it('allows that script by its sha256, and nothing inline besides', () => {
    const hash = `'sha256-${createHash('sha256').update(inlineScripts[0] ?? '').digest('base64')}'`;
    expect(THEME_BOOT_SCRIPT_HASH).toBe(hash);
    const scriptSrc = CONSOLE_CSP.split('; ').find((directive) => directive.startsWith('script-src '));
    expect(scriptSrc).toBe(`script-src 'self' ${hash}`);
    expect(CONSOLE_CSP).not.toContain('unsafe-inline');
  });

  it('allows styles only by nonce, never inline', () => {
    expect(CONSOLE_CSP).toContain("style-src 'self' 'nonce-NONCE'");
    expect(withStyleNonce('<html><head lang="x"><title>t</title>', 'N')).toBe('<html><head lang="x"><meta name="d3-style-nonce" content="N"><title>t</title>');
  });

  it('keeps the provider policy free of the console hash', () => {
    expect(PROVIDER_CSP).toContain("script-src 'self'");
    expect(PROVIDER_CSP).not.toContain(THEME_BOOT_SCRIPT_HASH);
  });

  describe('on the wire', () => {
    let server: Server;
    let base: string;

    beforeAll(async () => {
      const app = express();
      app.use(securityHeaders({ hsts: false }));
      app.get(['/login/abc', '/admin/people', '/oidc/jwks'], (_req, res) => {
        res.type('html').send(indexHtml);
      });
      server = app.listen(0, '127.0.0.1');
      await once(server, 'listening');
      base = `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`;
    });

    afterAll(() => {
      server.close();
    });

    const nonceIn = (csp: string | null): string => /style-src 'self' 'nonce-([A-Za-z0-9_-]+)'/.exec(csp ?? '')?.[1] ?? '';

    it.each(['/login/abc', '/admin/people'])('sends the hash and a style nonce on the console page %s', async (path) => {
      const res = await fetch(base + path);
      const csp = res.headers.get('content-security-policy');
      const nonce = nonceIn(csp);
      expect(nonce).toMatch(/^[A-Za-z0-9_-]{24}$/);
      expect(csp).toBe(consoleCsp(nonce));
      expect(csp).toContain(THEME_BOOT_SCRIPT_HASH);
      // The page carries the same nonce, where the console reads it.
      expect(await res.text()).toContain(`<meta name="d3-style-nonce" content="${nonce}">`);
    });

    it('gives every response its own nonce', async () => {
      const [a, b] = await Promise.all([fetch(`${base}/admin/people`), fetch(`${base}/admin/people`)]);
      expect(nonceIn(a.headers.get('content-security-policy'))).not.toBe(nonceIn(b.headers.get('content-security-policy')));
    });

    it('does not send it on the provider', async () => {
      const res = await fetch(`${base}/oidc/jwks`);
      expect(res.headers.get('content-security-policy')).toBe(PROVIDER_CSP);
      expect(await res.text()).not.toContain('d3-style-nonce');
    });
  });
});
