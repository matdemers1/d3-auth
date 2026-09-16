import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { z } from 'zod';
import type { Db } from '../db.js';
import type { SecretHasher } from '../security/hash.js';

// THROWAWAY (Phase 0). Seeds a development user and static clients for the flow script, the
// integration suite and the conformance harness. The real, idempotent seed file is T-4.6.
//
//   node dist/cli/dev-seed.js seed.json      (reads DATABASE_URL, PEPPER and the other boot secrets)

const clientSchema = z.object({
  clientId: z.string().min(1),
  name: z.string().min(1),
  type: z.enum(['confidential_web', 'public_native']),
  secret: z.string().min(32, 'client secrets must be at least 32 characters').optional(),
  redirectUris: z.array(z.url()).min(1),
  postLogoutRedirectUris: z.array(z.url()).default([]),
});

export const devSeedSchema = z.object({
  users: z
    .array(
      z.object({
        email: z.email(),
        username: z.string().min(1),
        displayName: z.string().min(1),
        password: z.string().min(12),
      }),
    )
    .default([]),
  clients: z.array(clientSchema).default([]),
});

export type DevSeed = z.input<typeof devSeedSchema>;

export async function applyDevSeed(db: Db, hasher: SecretHasher, input: DevSeed): Promise<void> {
  const seed = devSeedSchema.parse(input);

  for (const u of seed.users) {
    const user = await db.user.upsert({
      where: { email: u.email },
      create: { email: u.email, username: u.username, displayName: u.displayName, status: 'active', emailVerified: true },
      update: { username: u.username, displayName: u.displayName, status: 'active', emailVerified: true },
    });
    // A seeded user is a fixture, so seeding resets it completely: same password every time, and
    // no factors left over from a previous test run.
    await db.passwordCredential.deleteMany({ where: { userId: user.id } });
    await db.webauthnCredential.deleteMany({ where: { userId: user.id } });
    await db.totpCredential.deleteMany({ where: { userId: user.id } });
    await db.passwordCredential.create({ data: { userId: user.id, argon2idHash: await hasher.hash(u.password) } });
    await db.auditEvent.create({ data: { event: 'dev.seed.user', targetType: 'user', targetId: user.id } });
  }

  for (const c of seed.clients) {
    if (c.type === 'confidential_web' && !c.secret) throw new Error(`${c.clientId}: confidential clients need a secret`);
    const clientSecretHash = c.type === 'confidential_web' && c.secret ? await hasher.hash(c.secret) : null;
    const data = {
      name: c.name,
      clientType: c.type,
      clientSecretHash,
      postLogoutRedirectUris: c.postLogoutRedirectUris,
      enabled: true,
    };
    const app = await db.app.upsert({
      where: { clientId: c.clientId },
      create: { clientId: c.clientId, ...data },
      update: data,
    });
    await db.redirectUri.deleteMany({ where: { appId: app.id } });
    await db.redirectUri.createMany({ data: c.redirectUris.map((uri) => ({ appId: app.id, uri })) });
    await db.auditEvent.create({ data: { event: 'dev.seed.app', targetType: 'app', targetId: app.id } });
  }
}

async function main(): Promise<void> {
  const [path] = process.argv.slice(2);
  if (!path) throw new Error('usage: dev-seed <seed.json>');
  const { loadConfig } = await import('../config.js');
  const { createDb } = await import('../db.js');
  const { createSecretHasher } = await import('../security/hash.js');
  const config = loadConfig();
  const db = createDb(config.DATABASE_URL);
  try {
    await applyDevSeed(db, createSecretHasher(config.PEPPER), JSON.parse(readFileSync(path, 'utf8')) as DevSeed);
    console.log(JSON.stringify({ level: 'info', msg: 'dev seed applied', path }));
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
