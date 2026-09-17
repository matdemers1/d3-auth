import { execFileSync } from 'node:child_process';
import { createDb } from '../../src/db.js';

/**
 * Creates a *_test database if needed, empties it, and applies every migration. Refuses any other
 * name. Used once per run by the global setup, and by a file that needs a database of its own
 * because what it writes would be seen by other files (the audit table cannot be cleaned up).
 */
export async function prepareTestDatabase(raw: string): Promise<void> {
  const url = new URL(raw);
  const database = url.pathname.slice(1);
  if (!database.endsWith('_test')) {
    throw new Error(`Refusing to reset "${database}": integration tests only run against a *_test database.`);
  }

  const admin = new URL(raw);
  admin.pathname = '/postgres';
  const server = createDb(admin.toString());
  try {
    const exists = await server.$queryRaw<unknown[]>`SELECT 1 FROM pg_database WHERE datname = ${database}`;
    if (exists.length === 0) await server.$executeRawUnsafe(`CREATE DATABASE "${database}"`);
  } finally {
    await server.$disconnect();
  }

  const db = createDb(raw);
  try {
    // Gets past the append-only trigger, which blocks TRUNCATE on audit_event.
    await db.$executeRawUnsafe('DROP SCHEMA IF EXISTS public CASCADE');
    await db.$executeRawUnsafe('CREATE SCHEMA public');
  } finally {
    await db.$disconnect();
  }

  execFileSync('pnpm', ['exec', 'prisma', 'migrate', 'deploy'], { stdio: 'ignore', env: { ...process.env, DATABASE_URL: raw } });
}

/** A sibling of the run's test database, e.g. d3auth_test → d3auth_alerts_test. */
export function siblingDatabase(raw: string, purpose: string): string {
  const url = new URL(raw);
  url.pathname = `/${url.pathname.slice(1).replace(/_test$/, `_${purpose}_test`)}`;
  return url.toString();
}
