import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { migrateOnBoot } from '../../src/boot/migrate.js';
import { createLogger } from '../../src/log.js';
import { shippedMigrations } from '../../src/health.js';
import { testDb } from './helpers.js';

const db = testDb();
const logger = createLogger({ level: 'silent', destination: { write: () => undefined } });
const databaseUrl = process.env.DATABASE_URL ?? '';

afterAll(async () => {
  await db.$disconnect();
});

describe('migrations on boot (REQ-121)', () => {
  it('does nothing when the database is already up to date', async () => {
    const backupDir = mkdtempSync(join(tmpdir(), 'd3auth-dump-'));
    try {
      const result = await migrateOnBoot(db, { databaseUrl, backupDir, logger });
      expect(result.pending).toEqual([]);
      expect(result.dumpPath).toBeUndefined();
      expect(readdirSync(backupDir)).toEqual([]);
    } finally {
      rmSync(backupDir, { recursive: true, force: true });
    }
  });

  it('dumps before applying anything to a database that already holds data', async () => {
    const backupDir = mkdtempSync(join(tmpdir(), 'd3auth-dump-'));
    const calls: string[][] = [];
    try {
      const result = await migrateOnBoot(db, {
        databaseUrl,
        backupDir,
        logger,
        migrations: [...shippedMigrations(), '9999_pretend_new'],
        now: () => new Date('2026-09-16T12:00:00Z'),
        exec: (command, args) => {
          calls.push([command.split('/').pop() ?? command, ...args.slice(0, 1)]);
          return Promise.resolve();
        },
      });

      expect(result.pending).toEqual(['9999_pretend_new']);
      expect(result.dumpPath).toMatch(/pre-migration-2026-09-16T12-00-00-000Z\.dump$/);
      // The dump runs first, and only then the migration.
      expect(calls).toEqual([
        ['pg_dump', '--format=custom'],
        ['prisma', 'migrate'],
      ]);
    } finally {
      rmSync(backupDir, { recursive: true, force: true });
    }
  });

  it('refuses to continue when a migration fails', async () => {
    const backupDir = mkdtempSync(join(tmpdir(), 'd3auth-dump-'));
    try {
      await expect(
        migrateOnBoot(db, {
          databaseUrl,
          backupDir,
          logger,
          migrations: [...shippedMigrations(), '9999_pretend_new'],
          exec: (command) => (command.includes('prisma') ? Promise.reject(new Error('migration exploded')) : Promise.resolve()),
        }),
      ).rejects.toThrow(/migration exploded/);
    } finally {
      rmSync(backupDir, { recursive: true, force: true });
    }
  });
});
