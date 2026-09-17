import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { kekFingerprint, openBundle } from '../../src/backup/bundle.js';
import { runBackup, runDrill, type DrillContext } from '../../src/backup/operations.js';
import { createDirectoryStore, type ObjectStore } from '../../src/backup/store.js';
import { createLogger } from '../../src/log.js';
import { createAuditWriter, type AuditWriter } from '../../src/audit/writer.js';
import type { Prisma } from '../../src/generated/prisma/client.js';
import { ISSUER, startHarness, type Harness } from './oidc-harness.js';

// Backups and the restore drill (T-6.1, T-6.2, REQ-119, REQ-120, ADR-004).
//
// The drill is the test that matters, and it is only worth anything if it fails when a backup is
// bad. So after the happy path, every test here hands it a bundle that should not restore: the
// wrong KEK, a file that does not match its checksum, a database with no signing keys.

// pg_dump and pg_restore must match the server's major version. CI has them; a laptop may not, and
// then they run inside the dev stack's database container.
const pgToolsAvailable = (() => {
  try {
    execFileSync('pg_dump', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();
if (!pgToolsAvailable && !process.env.PG_TOOLS_PREFIX) process.env.PG_TOOLS_PREFIX = 'docker exec -i d3-auth-postgres-1';

let h: Harness;
let root: string;
let store: ObjectStore;
const logger = createLogger({ level: 'silent' });
const DATABASE_URL = process.env.DATABASE_URL ?? '';

/** The real writer, created lazily because the harness starts in beforeAll. */
const audit: AuditWriter = {
  write: (entry) => createAuditWriter(h.service.db, logger).write(entry),
};

const drillContext = (overrides: Partial<DrillContext> = {}): DrillContext => ({
  databaseUrl: DATABASE_URL,
  kek: h.kek,
  pepper: randomBytes(32),
  cookieKeys: [randomBytes(32).toString('base64')],
  issuer: ISSUER,
  store,
  audit,
  logger,
  ...overrides,
});

beforeAll(async () => {
  h = await startHarness();
  root = await mkdtemp(join(tmpdir(), 'd3auth-backups-'));
  store = createDirectoryStore(join(root, 'offsite'));
});

afterAll(async () => {
  await rm(root, { recursive: true, force: true });
  await h.close();
});

const backup = () =>
  runBackup({
    db: h.service.db,
    databaseUrl: DATABASE_URL,
    kek: h.kek,
    store,
    backupDir: join(root, 'local'),
    audit,
    logger,
  });

describe('a backup bundle', () => {
  it('holds the dump, the state file, the public keys and a manifest — and never the KEK', async () => {
    const result = await backup();
    expect(result.key).toMatch(/^bundles\/\d{4}\/\d{2}\/\d{2}\/d3auth-\d{8}T\d{6}Z\.tar\.gz$/);

    const archive = join(root, 'check.tar.gz');
    await store.get(result.key, archive);
    const { dir, manifest } = await openBundle(archive, join(root, 'open'));

    expect(manifest.files.map((file) => file.name).sort()).toEqual(['database.dump', 'keys.json', 'state.json']);
    expect(manifest.kekFingerprint).toBe(kekFingerprint(h.kek));
    expect(manifest.keys.length).toBeGreaterThanOrEqual(2);
    expect(manifest.schema).toMatch(/^\d{4}_/);

    // The KEK is in none of it, in any encoding a careless write would use.
    for (const name of ['manifest.json', 'state.json', 'keys.json']) {
      const text = await readFile(join(dir, name), 'utf8');
      expect(text).not.toContain(h.kek.toString('base64'));
      expect(text).not.toContain(h.kek.toString('hex'));
    }
    const dump = await readFile(join(dir, 'database.dump'));
    expect(dump.includes(h.kek)).toBe(false);
    expect(dump.includes(Buffer.from(h.kek.toString('base64')))).toBe(false);
    // And no private key is in the readable key file.
    expect(await readFile(join(dir, 'keys.json'), 'utf8')).not.toMatch(/"d"\s*:/);

    const audited = await h.service.db.auditEvent.findFirstOrThrow({ where: { event: 'backup.created' }, orderBy: { id: 'desc' } });
    expect(audited.detail).toMatchObject({ key: result.key });
  });
});

describe('the restore drill', () => {
  it('restores the newest bundle, decrypts the keys, boots a second service and finds the same kids', async () => {
    await backup();
    const result = await runDrill(drillContext());
    expect(result.failure).toBeUndefined();
    expect(result.ok).toBe(true);
    expect(result.steps).toEqual(
      expect.arrayContaining([
        'checksums match the manifest',
        'KEK fingerprint matches',
        expect.stringMatching(/^decrypted \d+ signing keys$/),
        'booted a second service; discovery and JWKS match',
      ]),
    );

    // It leaves nothing behind.
    const leftovers = await h.service.db.$queryRaw<{ datname: string }[]>`SELECT datname FROM pg_database WHERE datname LIKE 'd3auth_drill_%'`;
    expect(leftovers).toEqual([]);
  });

  it('fails, by name, with a KEK that did not seal the bundle', async () => {
    await backup();
    const result = await runDrill(drillContext({ kek: randomBytes(32) }));
    expect(result.ok).toBe(false);
    expect(result.failure).toBe('the KEK on this host is not the one that sealed this bundle');
    const audited = await h.service.db.auditEvent.findFirstOrThrow({ where: { event: 'backup.drill_failed' }, orderBy: { id: 'desc' } });
    expect(audited.detail).toMatchObject({ failure: result.failure });
  });

  it('fails when a file in the bundle has been changed', async () => {
    const { key } = await backup();
    const tampered = await mkdtemp(join(root, 'tamper-'));
    const archive = join(tampered, 'bundle.tar.gz');
    await store.get(key, archive);
    const { dir } = await openBundle(archive, tampered);
    await writeFile(join(dir, 'state.json'), '{"version":1,"apps":[],"people":[],"groups":[]}\n');
    execFileSync('tar', ['-czf', archive, '-C', dir, 'manifest.json', 'database.dump', 'state.json', 'keys.json']);
    const badKey = key.replace('.tar.gz', '-tampered.tar.gz');
    await store.put(badKey, archive);

    const result = await runDrill(drillContext({ key: badKey }));
    expect(result.ok).toBe(false);
    expect(result.failure).toMatch(/state\.json does not match the manifest/);
  });

  it('fails when the bundle has no signing keys to decrypt, rather than minting new ones', async () => {
    // A backup of a database whose keys were lost is exactly the backup the drill exists to catch.
    const saved = await h.service.db.signingKey.findMany();
    await h.service.db.signingKey.deleteMany();
    try {
      await backup();
    } finally {
      for (const key of saved) await h.service.db.signingKey.create({ data: { ...key, publicJwk: key.publicJwk as Prisma.InputJsonObject } });
    }
    const result = await runDrill(drillContext());
    expect(result.ok).toBe(false);
    expect(result.failure).toBe('the bundle has no published signing keys');
  });

  it('fails plainly when there is nothing to restore', async () => {
    const empty = createDirectoryStore(join(root, 'empty'));
    const result = await runDrill(drillContext({ store: empty }));
    expect(result.ok).toBe(false);
    expect(result.failure).toMatch(/^no bundles in /);
  });
});

