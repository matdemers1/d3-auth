import { execFileSync } from 'node:child_process';
import { createDb } from '../../src/db.js';

// Rebuilds the schema from migrations once per run: proves migrations apply from empty,
// and gets past the append-only trigger, which blocks TRUNCATE on audit_event.
export default async function setup(): Promise<void> {
  const raw = process.env.DATABASE_URL;
  if (!raw) {
    throw new Error(
      'Integration tests need DATABASE_URL, e.g. postgresql://d3auth:d3auth@127.0.0.1:5432/d3auth_test',
    );
  }
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
    await db.$executeRawUnsafe('DROP SCHEMA IF EXISTS public CASCADE');
    await db.$executeRawUnsafe('CREATE SCHEMA public');
  } finally {
    await db.$disconnect();
  }

  execFileSync('pnpm', ['exec', 'prisma', 'migrate', 'deploy'], { stdio: 'inherit', env: process.env });
}
