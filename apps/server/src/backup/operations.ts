import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtemp, readdir, readFile, rm, stat, copyFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AUDIT_EVENTS } from '../audit/events.js';
import type { AuditWriter } from '../audit/writer.js';
import { migrateOnBoot } from '../boot/migrate.js';
import { createDb, type Db } from '../db.js';
import { createLogger, type Logger } from '../log.js';
import { decryptPublishedKeys } from '../oidc/keys.js';
import { createKekCrypto } from '../security/kek.js';
import { bundleKey, createBundle, kekFingerprint, openBundle, type BundleManifest } from './bundle.js';
import { restoreDatabase } from './pg.js';
import type { ObjectStore } from './store.js';

// Taking a backup, and proving last night's can be restored (T-6.1, T-6.2, ADR-004).

const LOCAL_COPIES = 7;

export interface BackupContext {
  db: Db;
  databaseUrl: string;
  kek: Buffer;
  store: ObjectStore;
  /** The local copies live here, beside the pre-migration dumps. */
  backupDir: string;
  audit: AuditWriter;
  logger: Logger;
  now?: Date;
}

export interface BackupResult {
  key: string;
  bytes: number;
  manifest: BundleManifest;
}

/** Builds a bundle, uploads it, keeps a local copy, and says so in the audit trail either way. */
export async function runBackup(context: BackupContext): Promise<BackupResult> {
  const { db, databaseUrl, kek, store, backupDir, audit, logger } = context;
  const now = context.now ?? new Date();
  const work = await mkdtemp(join(tmpdir(), 'd3auth-backup-'));
  try {
    const { path, manifest } = await createBundle({ db, databaseUrl, kek, workDir: work, now });
    const name = path.split('/').at(-1) ?? 'bundle.tar.gz';
    const key = bundleKey(name, now);
    await store.put(key, path);
    const bytes = (await stat(path)).size;

    // A local copy too: the fastest restore is the one that does not need AWS.
    const localDir = join(backupDir, 'bundles');
    await mkdir(localDir, { recursive: true });
    await copyFile(path, join(localDir, name));
    const local = (await readdir(localDir)).filter((file) => file.startsWith('d3auth-') && file.endsWith('.tar.gz')).sort();
    for (const old of local.slice(0, Math.max(0, local.length - LOCAL_COPIES))) await rm(join(localDir, old), { force: true });

    await audit.write({ event: AUDIT_EVENTS.backupCreated, detail: { key, bytes, store: store.describe, schema: manifest.schema, keys: manifest.keys.length } });
    logger.info({ key, bytes, store: store.describe }, 'backup bundle written');
    return { key, bytes, manifest };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await audit.write({ event: AUDIT_EVENTS.backupFailed, detail: { error: message, store: store.describe } }).catch(() => undefined);
    logger.error({ err: message }, 'backup failed');
    throw err;
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

export interface DrillContext {
  /** The live service's database, used only to create and drop the throwaway one. */
  databaseUrl: string;
  kek: Buffer;
  pepper: Buffer;
  cookieKeys: string[];
  issuer: string;
  store: ObjectStore;
  audit: AuditWriter;
  logger: Logger;
  /** Seam for tests: which bundle to drill. Production takes the newest. */
  key?: string;
  now?: Date;
}

export interface DrillResult {
  ok: boolean;
  key?: string;
  /** Which step failed, in words an operator can act on. */
  failure?: string;
  steps: string[];
}

const DRILL_DB = /^d3auth_drill_\d{14}$/;

/**
 * Restores the newest bundle into a throwaway database and proves it works: the KEK opens it, the
 * signing keys decrypt, and a second copy of the service boots on it and publishes the same keys.
 */
export async function runDrill(context: DrillContext): Promise<DrillResult> {
  const { databaseUrl, kek, store, audit, logger } = context;
  const now = context.now ?? new Date();
  const steps: string[] = [];
  const work = await mkdtemp(join(tmpdir(), 'd3auth-drill-'));
  const drillName = `d3auth_drill_${now.toISOString().replace(/\D/g, '').slice(0, 14)}`;
  const drillUrl = new URL(databaseUrl);
  drillUrl.pathname = `/${drillName}`;
  const admin = createDb(databaseUrl);
  let created = false;
  let key = context.key;

  const fail = async (failure: string): Promise<DrillResult> => {
    await audit.write({ event: AUDIT_EVENTS.drillFailed, detail: { key, failure, steps } }).catch(() => undefined);
    logger.error({ key, failure }, 'restore drill failed');
    return { ok: false, ...(key ? { key } : {}), failure, steps };
  };

  try {
    // 1. The newest bundle, from the offsite copy — not the local one.
    if (!key) {
      const [newest] = await store.list('bundles/');
      if (!newest) return await fail(`no bundles in ${store.describe}`);
      key = newest.key;
    }
    const archive = join(work, key.split('/').at(-1) ?? 'bundle.tar.gz');
    await store.get(key, archive);
    steps.push(`downloaded ${key}`);

    // 2. Every file matches the manifest.
    const { dir, manifest } = await openBundle(archive, work);
    steps.push('checksums match the manifest');

    // 3. This KEK is the one that sealed it.
    if (manifest.kekFingerprint !== kekFingerprint(kek)) return await fail('the KEK on this host is not the one that sealed this bundle');
    steps.push('KEK fingerprint matches');

    // 4. A throwaway database, restored and migrated the way a real restore would be.
    if (!DRILL_DB.test(drillName)) return await fail(`refusing to create a database named ${drillName}`);
    await admin.$executeRawUnsafe(`CREATE DATABASE "${drillName}"`);
    created = true;
    await restoreDatabase(drillUrl.toString(), join(dir, 'database.dump'));
    const restored = createDb(drillUrl.toString());
    try {
      await migrateOnBoot(restored, { databaseUrl: drillUrl.toString(), backupDir: join(work, 'pre-migration'), logger: quiet(logger) });
      steps.push(`restored into ${drillName}`);

      // 5. The keys decrypt (R-03: not a row count), and they are the keys the bundle says.
      const decrypted = await decryptPublishedKeys(restored, createKekCrypto(kek));
      const expected = manifest.keys.map((entry) => entry.kid).sort();
      const found = decrypted.map((jwk) => jwk.kid).sort();
      if (expected.length === 0) return await fail('the bundle has no published signing keys');
      if (JSON.stringify(found) !== JSON.stringify(expected)) return await fail(`restored keys ${found.join(',')} are not the bundle's ${expected.join(',')}`);
      steps.push(`decrypted ${String(found.length)} signing keys`);

      // The people and apps came back too.
      const [people, apps] = await Promise.all([restored.user.count(), restored.app.count()]);
      if (people !== manifest.counts.people || apps !== manifest.counts.apps) {
        return await fail(`restored ${String(people)} people and ${String(apps)} apps; the bundle has ${String(manifest.counts.people)} and ${String(manifest.counts.apps)}`);
      }
      const state = JSON.parse(await readFile(join(dir, 'state.json'), 'utf8')) as { apps: unknown[] };
      if (state.apps.length !== apps) return await fail('the state file and the dump disagree about the apps');
      steps.push(`${String(people)} people and ${String(apps)} apps restored`);
    } finally {
      await restored.$disconnect();
    }

    // 6. A second copy of the service boots on it and publishes those keys.
    const published = await bootAndReadKeys({ ...context, databaseUrl: drillUrl.toString() });
    if (published.issuer !== context.issuer) return await fail(`the restored service calls itself ${published.issuer}`);
    const expectedKids = manifest.keys.map((entry) => entry.kid).sort();
    if (JSON.stringify(published.kids) !== JSON.stringify(expectedKids)) {
      return await fail(`the restored service publishes ${published.kids.join(',')}, not ${expectedKids.join(',')}`);
    }
    steps.push('booted a second service; discovery and JWKS match');

    await audit.write({ event: AUDIT_EVENTS.drillPassed, detail: { key, steps, bundleCreatedAt: manifest.createdAt, schema: manifest.schema } });
    logger.info({ key }, 'restore drill passed');
    return { ok: true, key, steps };
  } catch (err) {
    return await fail(err instanceof Error ? err.message : String(err));
  } finally {
    if (created && DRILL_DB.test(drillName)) {
      await admin.$executeRawUnsafe(`DROP DATABASE IF EXISTS "${drillName}" WITH (FORCE)`).catch((err: unknown) => {
        logger.error({ err, drillName }, 'could not drop the drill database');
      });
    }
    await admin.$disconnect();
    await rm(work, { recursive: true, force: true });
  }
}

const quiet = (logger: Logger): Logger => logger.child({ drill: true }, { level: 'warn' });

async function bootAndReadKeys(context: DrillContext): Promise<{ issuer: string; kids: string[] }> {
  // Imported here, not at the top: the service module is heavy, and only the drill needs a second one.
  const { createService } = await import('../service.js');
  const service = await createService(
    {
      ISSUER: context.issuer,
      DATABASE_URL: context.databaseUrl,
      // Copied into buffers of their own: the config types want an ArrayBuffer-backed Buffer.
      KEK: Buffer.from(context.kek),
      PEPPER: Buffer.from(context.pepper),
      COOKIE_KEYS: context.cookieKeys,
    },
    createLogger({ level: 'silent' }),
  );
  const server: Server = service.app.listen(0, '127.0.0.1');
  try {
    await once(server, 'listening');
    const { port } = server.address() as AddressInfo;
    const issuer = new URL(context.issuer);
    // Behind the tunnel the service sees these headers; it computes its URLs from them.
    const headers = { 'x-forwarded-proto': issuer.protocol.replace(':', ''), 'x-forwarded-host': issuer.host };
    const discovery = (await (await fetch(`http://127.0.0.1:${String(port)}/.well-known/openid-configuration`, { headers })).json()) as { issuer: string };
    const jwks = (await (await fetch(`http://127.0.0.1:${String(port)}/oidc/jwks`, { headers })).json()) as { keys: { kid: string }[] };
    return { issuer: discovery.issuer, kids: jwks.keys.map((entry) => entry.kid).sort() };
  } finally {
    await new Promise<void>((resolve) => server.close(() => { resolve(); }));
    await service.close();
  }
}
