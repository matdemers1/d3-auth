import { execFile } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import type { Db } from '../db.js';
import { shippedMigrations } from '../health.js';
import type { Logger } from '../log.js';

// Migrations run at boot, after an automatic dump of what is about to change (REQ-121).
// Nothing serves traffic until they succeed: the process exits instead, so the container is
// unhealthy rather than half-migrated, and rollback is "restore the dump, run the old image".

const run = promisify(execFile);

export interface MigrateOptions {
  databaseUrl: string;
  /** Volume the dump lands in; /backups in the image. */
  backupDir: string;
  logger: Logger;
  migrations?: string[];
  now?: () => Date;
  /** Seam for tests; production shells out to pg_dump and the Prisma CLI. */
  exec?: (command: string, args: string[], env: NodeJS.ProcessEnv) => Promise<void>;
}

export interface MigrateResult {
  pending: string[];
  dumpPath?: string;
}

async function appliedMigrations(db: Db): Promise<string[] | undefined> {
  try {
    const rows = await db.$queryRaw<{ migration_name: string }[]>`
      SELECT migration_name FROM _prisma_migrations WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL`;
    return rows.map((row) => row.migration_name);
  } catch {
    // No _prisma_migrations table yet: this is a first boot against an empty database.
    return undefined;
  }
}

const defaultExec = async (command: string, args: string[], env: NodeJS.ProcessEnv): Promise<void> => {
  await run(command, args, { env });
};

export async function migrateOnBoot(db: Db, options: MigrateOptions): Promise<MigrateResult> {
  const { logger, databaseUrl, backupDir } = options;
  const exec = options.exec ?? defaultExec;
  const shipped = options.migrations ?? shippedMigrations();
  const applied = await appliedMigrations(db);
  const pending = shipped.filter((name) => !(applied ?? []).includes(name));

  if (pending.length === 0) {
    logger.info({ applied: shipped.length }, 'database is up to date');
    return { pending: [] };
  }

  const result: MigrateResult = { pending };

  // Nothing to lose on a first boot, so the dump is skipped when the database is still empty.
  if (applied !== undefined) {
    const stamp = (options.now?.() ?? new Date()).toISOString().replace(/[:.]/g, '-');
    const dumpPath = join(backupDir, `pre-migration-${stamp}.dump`);
    mkdirSync(backupDir, { recursive: true });
    logger.info({ pending, dumpPath }, 'dumping the database before migrating');
    await exec('pg_dump', ['--format=custom', '--file', dumpPath, databaseUrl], process.env);
    result.dumpPath = dumpPath;
  }

  logger.info({ pending }, 'applying migrations');
  const prisma = fileURLToPath(new URL('../../node_modules/.bin/prisma', import.meta.url));
  await exec(prisma, ['migrate', 'deploy'], { ...process.env, DATABASE_URL: databaseUrl });
  logger.info({ pending }, 'migrations applied');
  return result;
}
