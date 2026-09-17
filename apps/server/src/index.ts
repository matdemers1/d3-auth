import { migrateOnBoot } from './boot/migrate.js';
import { ConfigError, loadConfig, type Config } from './config.js';
import { createDb } from './db.js';
import { createLogger } from './log.js';
import { offsiteStore } from './backup/from-config.js';
import { runBackup, runDrill } from './backup/operations.js';
import { scheduleDaily } from './jobs/daily.js';
import { createAuditWriter } from './audit/writer.js';
import { createService } from './service.js';

function readConfig(): Config {
  try {
    return loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) {
      // Before a logger exists; the message names variables, never values.
      console.error(err.message);
      process.exit(1);
    }
    throw err;
  }
}

const config = readConfig();
const logger = createLogger({ level: config.LOG_LEVEL });

if (config.INSECURE_HTTP_ISSUER) logger.warn({ issuer: config.ISSUER }, 'running with an http issuer — local testing only');

// Migrations first (REQ-121): nothing listens until the schema this build expects is in place.
const migrationDb = createDb(config.DATABASE_URL);
try {
  await migrateOnBoot(migrationDb, { databaseUrl: config.DATABASE_URL, backupDir: config.BACKUP_DIR, logger });
} catch (err) {
  logger.fatal({ err }, 'migrations failed; refusing to serve');
  process.exit(1);
} finally {
  await migrationDb.$disconnect();
}

const service = await createService(config, logger).catch((err: unknown) => {
  logger.fatal({ err }, 'failed to start');
  process.exit(1);
});

const server = service.app.listen(config.PORT, (err?: Error) => {
  if (err) {
    logger.fatal({ err }, 'failed to listen');
    process.exit(1);
  }
  logger.info({ port: config.PORT, issuer: config.ISSUER }, 'listening');
});

// Nightly backup and restore drill (T-6.1, T-6.2, ADR-004). Without an offsite store the service
// runs anyway and says so; the alert rules then flag the missing backups.
const store = offsiteStore(config);
const jobs: { stop(): void }[] = [];
if (store) {
  const audit = createAuditWriter(service.db, logger);
  jobs.push(
    scheduleDaily('backup', config.BACKUP_AT, () =>
      runBackup({ db: service.db, databaseUrl: config.DATABASE_URL, kek: config.KEK, store, backupDir: config.BACKUP_DIR, audit, logger }),
    logger),
    scheduleDaily('restore-drill', config.DRILL_AT, () =>
      runDrill({
        databaseUrl: config.DATABASE_URL,
        kek: config.KEK,
        pepper: config.PEPPER,
        cookieKeys: config.COOKIE_KEYS,
        issuer: config.ISSUER,
        store,
        audit,
        logger,
      }),
    logger),
  );
} else {
  logger.warn('offsite backups are not configured (BACKUP_S3_BUCKET); only pre-migration dumps are kept');
}

function shutdown(signal: NodeJS.Signals): void {
  for (const job of jobs) job.stop();
  logger.info({ signal }, 'shutting down');
  server.close((err) => {
    void service.close().finally(() => process.exit(err ? 1 : 0));
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.once('SIGTERM', shutdown);
process.once('SIGINT', shutdown);
