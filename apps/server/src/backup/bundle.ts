import { execFile } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { promisify } from 'node:util';
import { exportState } from '../admin/state.js';
import type { Db } from '../db.js';
import { shippedMigrations } from '../health.js';
import { dumpDatabase } from './pg.js';

// The backup bundle (T-6.1, REQ-119, ADR-004).
//
// A gzipped tar of four files: the database dump, the export state file, the published public
// keys, and a manifest that names every other file's SHA-256. What it never contains is the KEK.
// The dump holds the signing keys and TOTP secrets *sealed*; whoever has the bundle without the KEK
// has ciphertext, and whoever has both has everything — so they never travel together.
//
// The manifest does carry a KEK *fingerprint*: an HMAC under the KEK of a fixed label, which says
// which key opens this bundle without saying anything about the key. A restore with the wrong KEK
// fails with that name instead of an opaque decryption error halfway through.

const run = promisify(execFile);

export const BUNDLE_FORMAT = 1;
const FILES = ['database.dump', 'state.json', 'keys.json'] as const;

export interface BundleManifest {
  format: typeof BUNDLE_FORMAT;
  createdAt: string;
  /** The migration the database was at: a restore needs this image or a newer one. */
  schema: string | null;
  kekFingerprint: string;
  keys: { kid: string; alg: string; status: string }[];
  counts: { people: number; apps: number; groups: number; auditEvents: number };
  files: { name: string; bytes: number; sha256: string }[];
}

export const kekFingerprint = (kek: Buffer): string =>
  createHmac('sha256', kek).update('d3auth:kek-fingerprint:v1').digest().subarray(0, 16).toString('hex');

async function sha256(file: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

export const bundleName = (now: Date): string => `d3auth-${now.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z')}.tar.gz`;

/** Where a bundle lives in the object store: one folder per day, so a listing reads like a calendar. */
export const bundleKey = (name: string, now: Date): string =>
  `bundles/${now.toISOString().slice(0, 4)}/${now.toISOString().slice(5, 7)}/${now.toISOString().slice(8, 10)}/${name}`;

export interface CreateBundleOptions {
  db: Db;
  databaseUrl: string;
  kek: Buffer;
  /** A scratch directory; the finished bundle is written inside it. */
  workDir: string;
  now?: Date;
}

export async function createBundle({ db, databaseUrl, kek, workDir, now = new Date() }: CreateBundleOptions): Promise<{ path: string; manifest: BundleManifest }> {
  const staging = join(workDir, 'staging');
  await mkdir(staging, { recursive: true });

  await dumpDatabase(databaseUrl, join(staging, 'database.dump'));
  await writeFile(join(staging, 'state.json'), `${JSON.stringify(await exportState(db), null, 2)}\n`);

  const published = await db.signingKey.findMany({
    where: { status: { in: ['next', 'current', 'retiring'] } },
    select: { kid: true, alg: true, status: true, publicJwk: true },
    orderBy: { kid: 'asc' },
  });
  await writeFile(join(staging, 'keys.json'), `${JSON.stringify(published, null, 2)}\n`);

  const [people, apps, groups, auditEvents, migration] = await Promise.all([
    db.user.count(),
    db.app.count(),
    db.group.count(),
    db.auditEvent.count(),
    db.$queryRaw<{ migration_name: string }[]>`
      SELECT migration_name FROM _prisma_migrations WHERE finished_at IS NOT NULL ORDER BY migration_name DESC LIMIT 1`,
  ]);

  const manifest: BundleManifest = {
    format: BUNDLE_FORMAT,
    createdAt: now.toISOString(),
    schema: migration[0]?.migration_name ?? null,
    kekFingerprint: kekFingerprint(kek),
    keys: published.map(({ kid, alg, status }) => ({ kid, alg, status })),
    counts: { people, apps, groups, auditEvents },
    files: await Promise.all(
      FILES.map(async (name) => {
        const file = join(staging, name);
        return { name, bytes: (await stat(file)).size, sha256: await sha256(file) };
      }),
    ),
  };
  await writeFile(join(staging, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);

  const path = join(workDir, bundleName(now));
  await run('tar', ['-czf', path, '-C', staging, 'manifest.json', ...FILES]);
  return { path, manifest };
}

export class BundleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BundleError';
  }
}

/** Unpacks a bundle and checks every file against the manifest. Returns where the files are. */
export async function openBundle(path: string, into: string): Promise<{ dir: string; manifest: BundleManifest }> {
  const dir = join(into, basename(path).replace(/\.tar\.gz$/, ''));
  await mkdir(dir, { recursive: true });
  await run('tar', ['-xzf', path, '-C', dir]);

  const raw = JSON.parse(await readFile(join(dir, 'manifest.json'), 'utf8')) as Omit<BundleManifest, 'format'> & { format: number };
  if (raw.format !== BUNDLE_FORMAT) throw new BundleError(`unknown bundle format ${String(raw.format)}`);
  const manifest = raw as BundleManifest;
  for (const name of FILES) {
    const entry = manifest.files.find((file) => file.name === name);
    if (!entry) throw new BundleError(`the manifest does not list ${name}`);
    const actual = await sha256(join(dir, name)).catch(() => 'missing');
    if (actual !== entry.sha256) throw new BundleError(`${name} does not match the manifest (${actual === 'missing' ? 'missing' : 'checksum differs'})`);
  }
  return { dir, manifest };
}

/** The newest migration this image ships, for comparing against a bundle's schema. */
export const imageSchema = (): string | undefined => shippedMigrations().at(-1);
