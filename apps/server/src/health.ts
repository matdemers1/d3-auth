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

/** Readiness is checked on a short cache: the gate runs on every page request. */
export function cached(probe: ReadinessProbe, ttlMs = 5_000): ReadinessProbe {
  let at = 0;
  let last: Promise<ReadinessChecks> | undefined;
  return () => {
    const now = Date.now();
    if (!last || now - at > ttlMs) {
      at = now;
      last = probe();
    }
    return last;
  };
}

export const allPass = (checks: ReadinessChecks): boolean => Object.values(checks).every(Boolean);

/** The newest migration this image ships — the same value CI stamps on the image as
 * `dev.d3cloud.shipyard.schema`. */
export function newestMigration(migrations: string[] = shippedMigrations()): string | null {
  return migrations.at(-1) ?? null;
}

/** The schema the database is actually on: null when it cannot be read. */
export type SchemaProbe = () => Promise<string | null>;

/**
 * The newest migration *applied* to the database — what /health reports, so Shipyard compares
 * the label against the database rather than against what the image merely ships. After an
 * image-only rollback past an expand migration the two differ, and the database is the truth.
 * Names sort in the same order CI uses to pick the label.
 */
export function appliedSchema(db: Db): SchemaProbe {
  return async () => {
    try {
      const rows = await withTimeout(db.$queryRaw<{ migration_name: string }[]>`
        SELECT migration_name FROM _prisma_migrations
        WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL
        ORDER BY migration_name DESC LIMIT 1`);
      return rows[0]?.migration_name ?? null;
    } catch {
      return null;
    }
  };
}

export function healthRouter(readiness?: ReadinessProbe, schemaProbe?: SchemaProbe): Router {
  const router = Router();

  router.use(['/healthz', '/readyz', '/health'], (_req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });

  router.get('/healthz', (_req, res) => {
    res.json({ status: 'ok' });
  });

  router.get('/readyz', async (_req, res) => {
    const checks = readiness ? await readiness() : {};
    const ready = allPass(checks);
    res.status(ready ? 200 : 503).json({ status: ready ? 'ready' : 'unavailable', checks });
  });

  // /health (SHP-D-019, SHP-D-022): the Shipyard deploy contract. No auth, no secrets — just
  // whether the database answers, migrations are applied, and which schema is running.
  router.get('/health', async (_req, res) => {
    const [checks, schema] = await Promise.all([readiness ? readiness() : Promise.resolve<ReadinessChecks>({}), schemaProbe ? schemaProbe() : null]);
    const ok = (checks.database ?? false) && (checks.migrations ?? false) && schema !== null;
    res.status(ok ? 200 : 503).json({ ok, schema: ok ? schema : null });
  });

  return router;
}
