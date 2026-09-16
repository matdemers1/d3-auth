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
  /** Roles the fixture app declares. Real apps declare them in a manifest (REQ-047). */
  roles: z.array(z.object({ key: z.string().min(1), display: z.string().min(1), default: z.boolean().default(false) })).default([]),
});

export const devSeedSchema = z.object({
  users: z
    .array(
      z.object({
        email: z.email(),
        username: z.string().min(1),
        displayName: z.string().min(1),
        password: z.string().min(12),
        /** Development fixtures need an owner to open the admin screens with. */
        kind: z.enum(['owner', 'admin', 'guest']).default('guest'),
        /** Access is deny-by-default (REQ-051), so a fixture user needs grants to sign in at all. */
        grants: z.array(z.object({ clientId: z.string().min(1), roles: z.array(z.string()).default([]) })).default([]),
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
      create: { email: u.email, username: u.username, displayName: u.displayName, kind: u.kind, status: 'active', emailVerified: true },
      update: { username: u.username, displayName: u.displayName, kind: u.kind, status: 'active', emailVerified: true },
    });
    // A seeded user is a fixture, so seeding resets it completely: same password every time, and
    // no factors left over from a previous test run.
    await db.passwordCredential.deleteMany({ where: { userId: user.id } });
    await db.webauthnCredential.deleteMany({ where: { userId: user.id } });
    await db.totpCredential.deleteMany({ where: { userId: user.id } });
    await db.passwordCredential.create({ data: { userId: user.id, argon2idHash: await hasher.hash(u.password) } });
    await db.auditEvent.create({ data: { event: 'dev.seed.user', targetType: 'user', targetId: user.id } });
  }

  // Clients first: a grant needs the app and its roles to exist.
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

    const keys = c.roles.map((role) => role.key);
    await db.role.deleteMany({ where: { appId: app.id, ...(keys.length > 0 ? { key: { notIn: keys } } : {}) } });
    for (const [index, role] of c.roles.entries()) {
      const roleData = { displayName: role.display, description: '', sortOrder: c.roles.length - index, isDefault: role.default };
      await db.role.upsert({
        where: { appId_key: { appId: app.id, key: role.key } },
        create: { appId: app.id, key: role.key, ...roleData },
        update: roleData,
      });
    }
    await db.auditEvent.create({ data: { event: 'dev.seed.app', targetType: 'app', targetId: app.id } });
  }

  // Then the grants, because without one a seeded user cannot sign in to a seeded app at all.
  for (const u of seed.users) {
    const user = await db.user.findUniqueOrThrow({ where: { email: u.email } });
    await db.grant.deleteMany({ where: { userId: user.id } });
    for (const wanted of u.grants) {
      const app = await db.app.findUnique({ where: { clientId: wanted.clientId }, include: { roles: true } });
      if (!app) throw new Error(`${u.email}: no app with the client id "${wanted.clientId}"`);
      const roleIds = wanted.roles.map((key) => {
        const role = app.roles.find((candidate) => candidate.key === key);
        if (!role) throw new Error(`${u.email}: ${wanted.clientId} has no role "${key}"`);
        return role.id;
      });
      const grant = await db.grant.create({ data: { userId: user.id, appId: app.id } });
      await db.grantRole.createMany({ data: roleIds.map((roleId) => ({ grantId: grant.id, roleId })) });
    }
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
