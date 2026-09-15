import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import express, { Router } from 'express';

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

export function consoleRouter(dist: string): Router {
  const router = Router();
  const index = join(dist, 'index.html');

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
    res.sendFile(index);
  });

  return router;
}
