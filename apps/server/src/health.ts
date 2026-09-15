import { readdirSync } from 'node:fs';
import { Router } from 'express';
import type { Db } from './db.js';
import { SIGNING_ALGS } from './oidc/keys.js';

// /healthz: the process is up. /readyz: the service can actually sign people in — the database
// answers, a current signing key exists for every algorithm, and every migration shipped in this
// image has been applied (REQ-113). Responses carry pass/fail only, never error detail.

export type ReadinessChecks = Record<string, boolean>;
export type ReadinessProbe = () => Promise<ReadinessChecks>;

const CHECK_TIMEOUT_MS = 2_000;

function withTimeout<T>(promise: Promise<T>): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => setTimeout(() => { reject(new Error('readiness check timed out')); }, CHECK_TIMEOUT_MS).unref()),
  ]);
}

async function passes(check: () => Promise<boolean>): Promise<boolean> {
  try {
    return await withTimeout(check());
  } catch {
    return false;
  }
}

export function shippedMigrations(dir = new URL('../prisma/migrations/', import.meta.url)): string[] {
  return readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
}

export function databaseReadiness(db: Db, migrations: string[] = shippedMigrations()): ReadinessProbe {
  return async () => {
    const [database, signingKeys, migrationsApplied] = await Promise.all([
      passes(async () => {
        await db.$queryRaw`SELECT 1`;
        return true;
      }),
      passes(async () => {
        const current = await db.signingKey.findMany({ where: { status: 'current' }, select: { alg: true } });
        return SIGNING_ALGS.every((alg) => current.some((key) => key.alg === alg));
      }),
      passes(async () => {
        const rows = await db.$queryRaw<{ migration_name: string }[]>`
          SELECT migration_name FROM _prisma_migrations WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL`;
        const applied = new Set(rows.map((row) => row.migration_name));
        return migrations.every((name) => applied.has(name));
      }),
    ]);
    return { database, signingKeys, migrations: migrationsApplied };
  };
}

export function healthRouter(readiness?: ReadinessProbe): Router {
  const router = Router();

  router.use(['/healthz', '/readyz'], (_req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });

  router.get('/healthz', (_req, res) => {
    res.json({ status: 'ok' });
  });

  router.get('/readyz', async (_req, res) => {
    const checks = readiness ? await readiness() : {};
    const ready = Object.values(checks).every(Boolean);
    res.status(ready ? 200 : 503).json({ status: ready ? 'ready' : 'unavailable', checks });
  });

  return router;
}
