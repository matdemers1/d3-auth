import { pathToFileURL } from 'node:url';

// The sealed second admin, from the host (T-6.5, docs/runbooks/sealed-admin.md):
//
//   docker compose exec -T server node dist/cli/seal-admin.js --email sealed@example.com --name "Sealed admin"
//   docker compose exec -T server node dist/cli/seal-admin.js --email sealed@example.com --rotate
//
// Prints the credentials once, to this terminal and nowhere else. Print them, seal them, and clear
// the terminal. They are not logged and cannot be shown again.

export interface SealArgs {
  email: string;
  name: string;
  rotate: boolean;
}

export class UsageError extends Error {}

export function parseArgs(argv: readonly string[]): SealArgs {
  let email = '';
  let name = 'Sealed admin';
  let rotate = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i] ?? '';
    const next = argv[i + 1];
    if (arg === '--email' && next) {
      email = next;
      i += 1;
    } else if (arg === '--name' && next) {
      name = next;
      i += 1;
    } else if (arg === '--rotate') {
      rotate = true;
    } else {
      throw new UsageError(`unknown option ${arg}`);
    }
  }
  if (!email.includes('@')) throw new UsageError('usage: seal-admin --email <address used for nothing else> [--name "Sealed admin"] [--rotate]');
  return { email, name, rotate };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const { loadConfig } = await import('../config.js');
  const { createDb } = await import('../db.js');
  const { createLogger } = await import('../log.js');
  const { createAuditWriter } = await import('../audit/writer.js');
  const { createSecretHasher } = await import('../security/hash.js');
  const { createKekCrypto } = await import('../security/kek.js');
  const { createTotp } = await import('../security/totp.js');
  const { sealAdmin } = await import('../admin/sealed-admin.js');

  const config = loadConfig();
  const db = createDb(config.DATABASE_URL);
  try {
    const credentials = await sealAdmin(
      {
        db,
        hasher: createSecretHasher(config.PEPPER),
        totp: createTotp(db, createKekCrypto(config.KEK), new URL(config.ISSUER).host),
        audit: createAuditWriter(db, createLogger({ level: 'warn' })),
      },
      { email: args.email, displayName: args.name, rotate: args.rotate },
    );
    const rule = '─'.repeat(64);
    console.log(`\n${rule}\n  D3 Auth — sealed admin for ${config.ISSUER}\n${rule}`);
    console.log(`  Email            ${credentials.email}`);
    console.log(`  Password         ${credentials.password}`);
    console.log(`  Authenticator    ${credentials.manualKey}`);
    console.log(`                   (type it into an authenticator app, or make a QR code of the line below)`);
    console.log(`  ${credentials.uri}`);
    console.log(`  Sealed           ${new Date().toISOString().slice(0, 10)}`);
    console.log(rule);
    console.log('  Signing in with this account emails every alert recipient.');
    console.log('  After any use, rotate:  seal-admin --email ' + credentials.email + ' --rotate');
    console.log(`${rule}\n\nPrint this, seal it, then clear the terminal and its scrollback.\n`);
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
