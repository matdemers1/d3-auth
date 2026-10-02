import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import express, { Router, type RequestHandler } from 'express';
import { allPass, type ReadinessProbe } from './health.js';

// Serves the built console (REQ-061): hashed assets cached forever, and the SPA shell for the
// three surfaces. Anything else falls through to the provider. A missing build is a 503 on
// the console routes only — sign-in for apps keeps working.

export const CONSOLE_SURFACES = ['/login', '/account', '/admin'] as const;

export function defaultConsoleDist(): string {
  return fileURLToPath(new URL('../../console/dist/', import.meta.url));
}

export function consoleBuilt(dist: string): boolean {
  return existsSync(join(dist, 'index.html'));
}

export function unavailablePage(): string {
  return fileURLToPath(new URL('../public/unavailable.html', import.meta.url));
}

/**
 * Serves a static "sign-in unavailable" page instead of the console when readiness is failing
 * (REQ-084). It touches no database, so it still renders when Postgres is the thing that is down.
 */
export function unavailableGate(readiness: ReadinessProbe): RequestHandler {
  const page = unavailablePage();
  return (req, res, next) => {
    void readiness()
      .then((checks) => {
        if (allPass(checks)) {
          next();
          return;
        }
        res.status(503).set('Cache-Control', 'no-store').sendFile(page);
      })
      .catch(() => {
        res.status(503).set('Cache-Control', 'no-store').sendFile(page);
      });
  };
}

/**
 * The policy for the favicon (AUTH-T-8.1). It is an SVG whose one `<style>` switches the ink between
 * light and dark, and a browser may apply the response's own CSP to an SVG it draws — under the
 * page policy (styles by nonce only) that style would be refused and the mark would draw blank.
 * So this one response allows exactly that style by its sha256, and nothing else at all: no script,
 * no fetch, no inline style beyond the hashed one.
 */
export function faviconCsp(svg: string): string {
  const styles = [...svg.matchAll(/<style>([\s\S]*?)<\/style>/g)].map((match) => match[1] ?? '');
  const hashes = styles.map((css) => `'sha256-${createHash('sha256').update(css).digest('base64')}'`);
  return ["default-src 'none'", `style-src ${hashes.length > 0 ? hashes.join(' ') : "'none'"}`, "base-uri 'none'", "frame-ancestors 'none'"].join('; ');
}

export function consoleRouter(dist: string): Router {
  const router = Router();
  const index = join(dist, 'index.html');
  let shell: string | undefined;
  let favicon: { body: string; csp: string } | undefined;

  // The one file from the build's root that is served: Vite copies public/favicon.svg there. Named,
  // not a static directory, so nothing else that lands beside index.html is reachable.
  router.get('/favicon.svg', (_req, res, next) => {
    const file = join(dist, 'favicon.svg');
    if (!favicon) {
      if (!existsSync(file)) {
        next();
        return;
      }
      const body = readFileSync(file, 'utf8');
      favicon = { body, csp: faviconCsp(body) };
    }
    res.set({ 'Cache-Control': 'public, max-age=86400', 'Content-Security-Policy': favicon.csp }).type('image/svg+xml').send(favicon.body);
  });

  router.use(
    '/assets',
    express.static(join(dist, 'assets'), { index: false, immutable: true, maxAge: '365d', fallthrough: false, dotfiles: 'deny' }),
  );

  const paths = CONSOLE_SURFACES.flatMap((surface) => [surface, `${surface}/*splat`]);
  router.get(paths, (_req, res) => {
    res.set('Cache-Control', 'no-store');
    if (!consoleBuilt(dist)) {
      res.status(503).type('text').send('The console is not available on this build.');
      return;
    }
    // Sent as a string rather than a file so the security headers can add this response's style
    // nonce (see security/headers.ts). The path is the build's own index.html, fixed at startup.
    shell ??= readFileSync(index, 'utf8');
    res.type('html').send(shell);
  });

  return router;
}
