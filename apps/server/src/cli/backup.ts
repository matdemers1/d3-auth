import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

// Backups by hand (T-6.1, T-6.2, ADR-004):
//
//   docker compose exec server node dist/cli/backup.js --now          # bundle and upload, as tonight's job would
//   docker compose exec server node dist/cli/backup.js --list         # what is offsite
//   docker compose exec server node dist/cli/backup.js --drill        # restore the newest into a throwaway database
//   docker compose exec server node dist/cli/backup.js --restore <key> --into <empty database url>
//
// `--restore` is the disaster path in docs/runbooks/backup-restore.md. It restores into a database
// that must already exist and be empty, and it never touches the one the service is using.

export type Action = 'now' | 'list' | 'drill' | 'restore';

export interface BackupArgs {
  action: Action;
  key?: string;
  into?: string;
  /** A directory to use instead of S3, for a copy on a disk you can carry. */
  dir?: string;
}

export class UsageError extends Error {}

const USAGE = 'usage: backup --now | --list | --drill | --restore <key> --into <database url>  [--dir <directory instead of S3>]';

export function parseArgs(argv: readonly string[]): BackupArgs {
  let action: Action | undefined;
  let key: string | undefined;
  let into: string | undefined;
  let dir: string | undefined;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i] ?? '';
    const next = argv[i + 1];
    switch (arg) {
      case '--now':
      case '--list':
      case '--drill':
        action = arg.slice(2) as Action;
        break;
      case '--restore':
        if (!next || next.startsWith('--')) throw new UsageError('--restore needs a bundle key (see --list)');
        action = 'restore';
        key = next;
        i += 1;
        break;
      case '--into':
        if (!next) throw new UsageError('--into needs a database url');
        into = next;
        i += 1;
        break;
      case '--dir':
        if (!next) throw new UsageError('--dir needs a directory');
        dir = next;
        i += 1;
        break;
      default:
        throw new UsageError(`unknown option ${arg}`);
    }
  }
  if (!action) throw new UsageError(USAGE);
  if (action === 'restore' && !into) throw new UsageError('--restore needs --into <database url>: it never restores over the live database');
  return { action, ...(key ? { key } : {}), ...(into ? { into } : {}), ...(dir ? { dir } : {}) };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const { loadConfig } = await import('../config.js');
  const { createDb } = await import('../db.js');
  const { createLogger } = await import('../log.js');
  const { createAuditWriter } = await import('../audit/writer.js');
  const { offsiteStore } = await import('../backup/from-config.js');
  const { createDirectoryStore } = await import('../backup/store.js');

  const config = loadConfig();
  const logger = createLogger({ level: 'warn' });
  const store = args.dir ? createDirectoryStore(args.dir) : offsiteStore(config);
  if (!store) throw new Error('No offsite store: set BACKUP_S3_BUCKET and BACKUP_KMS_KEY_ID, or pass --dir.');

  const db = createDb(config.DATABASE_URL);
  const audit = createAuditWriter(db, logger);
  try {
    if (args.action === 'list') {
      const bundles = await store.list('bundles/');
      console.log(`\n${String(bundles.length)} bundle(s) in ${store.describe}, newest first:\n`);
      for (const bundle of bundles.slice(0, 30)) {
        console.log(`  ${bundle.key}  ${(bundle.size / 1024).toFixed(0).padStart(6)} KB  ${bundle.modified.toISOString().slice(0, 16)}`);
      }
      console.log('');
      return;
    }

    if (args.action === 'now') {
      const { runBackup } = await import('../backup/operations.js');
      const result = await runBackup({ db, databaseUrl: config.DATABASE_URL, kek: config.KEK, store, backupDir: config.BACKUP_DIR, audit, logger });
      console.log(`\nWrote ${result.key} (${(result.bytes / 1024).toFixed(0)} KB) to ${store.describe}.`);
      console.log(`Schema ${result.manifest.schema ?? 'unknown'}, ${String(result.manifest.keys.length)} signing keys, KEK ${result.manifest.kekFingerprint}.\n`);
      return;
    }

    if (args.action === 'drill') {
      const { runDrill } = await import('../backup/operations.js');
      const result = await runDrill({
        databaseUrl: config.DATABASE_URL,
        kek: config.KEK,
        pepper: config.PEPPER,
        cookieKeys: config.COOKIE_KEYS,
        issuer: config.ISSUER,
        store,
        audit,
        logger,
      });
      for (const step of result.steps) console.log(`  ✓ ${step}`);
      if (!result.ok) {
        console.error(`  ✗ ${result.failure ?? 'failed'}\n`);
        process.exitCode = 1;
        return;
      }
      console.log(`\nThe drill passed: ${result.key ?? ''} restores, decrypts and serves.\n`);
      return;
    }

    // --restore: the disaster path.
    const { openBundle, kekFingerprint } = await import('../backup/bundle.js');
    const { restoreDatabase } = await import('../backup/pg.js');
    const work = await mkdtemp(join(tmpdir(), 'd3auth-restore-'));
    try {
      const archive = join(work, 'bundle.tar.gz');
      await store.get(args.key ?? '', archive);
      const { dir, manifest } = await openBundle(archive, work);
      console.log(`\nBundle ${args.key ?? ''}: created ${manifest.createdAt}, schema ${manifest.schema ?? 'unknown'}, checksums match.`);
      if (manifest.kekFingerprint !== kekFingerprint(config.KEK)) {
        throw new Error('The KEK in this environment did not seal this bundle. Find the right KEK before restoring: without it the signing keys and TOTP secrets are unreadable.');
      }
      await restoreDatabase(args.into ?? '', join(dir, 'database.dump'));
      console.log('Restored. Point DATABASE_URL at it and start the service: migrations run on boot.\n');
    } finally {
      await rm(work, { recursive: true, force: true });
    }
  } finally {
    await db.$disconnect();
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().catch((err: unknown) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
