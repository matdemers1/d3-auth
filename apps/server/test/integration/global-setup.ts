import { prepareTestDatabase } from './test-database.js';

// Rebuilds the schema from migrations once per run: proves migrations apply from empty.
export default async function setup(): Promise<void> {
  const raw = process.env.DATABASE_URL;
  if (!raw) {
    throw new Error(
      'Integration tests need DATABASE_URL, e.g. postgresql://d3auth:d3auth@127.0.0.1:5432/d3auth_test',
    );
  }
  await prepareTestDatabase(raw);
}
