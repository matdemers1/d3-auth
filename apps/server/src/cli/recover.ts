import { pathToFileURL } from 'node:url';

// Break-glass, from the host (REQ-122):
//
//   docker compose exec server node dist/cli/recover.js --user you@example.com --minutes 15
//
// It prints a link. Opening the link clears that account's factors and lets it sign in with the
// password alone for the window, then the account is left with no second factor until a new one
// is enrolled. Whoever runs this needs a shell on the host *and* the account's password:
// see ADR-003 for why the link alone is deliberately not enough.

export interface RecoverArgs {
  user: string;
  minutes: number;
}

export class UsageError extends Error {}

export function parseArgs(argv: readonly string[]): RecoverArgs {
  let user = '';
  let minutes = 15;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i] ?? '';
    const next = argv[i + 1];
    if (arg === '--user' || arg === '-u') {
      if (!next) throw new UsageError('--user needs an email address');
      user = next;
      i += 1;
    } else if (arg === '--minutes' || arg === '-m') {
      const parsed = Number(next);
      if (!next || !Number.isFinite(parsed) || parsed <= 0) throw new UsageError('--minutes needs a positive number');
      minutes = parsed;
      i += 1;
    } else {
      throw new UsageError(`unknown option ${arg}`);
    }
  }

  if (!user) throw new UsageError('usage: recover --user <email> [--minutes <n>]');
  return { user, minutes };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const { loadConfig } = await import('../config.js');
  const { createDb } = await import('../db.js');
  const { createAuditWriter } = await import('../audit/writer.js');
  const { createLogger } = await import('../log.js');
  const { createAdapterFactory } = await import('../oidc/adapter.js');
  const { createTrustedDevices } = await import('../security/trusted-device.js');
  const { createRecovery } = await import('../setup/recovery.js');

  const config = loadConfig();
  const db = createDb(config.DATABASE_URL);
  const logger = createLogger({ level: 'silent', destination: { write: () => undefined } });
  try {
    const recovery = createRecovery({
      db,
      adapterFactory: createAdapterFactory(db),
      audit: createAuditWriter(db, logger),
      // Sessions are ended when the link is opened, which happens in the service, not here.
      sessions: { end: () => Promise.resolve(), revokeAll: () => Promise.resolve(0) },
      trustedDevices: createTrustedDevices(db),
      issuer: config.ISSUER,
    });
    const minted = await recovery.mint({ email: args.user, minutes: args.minutes });

    // Deliberately plain, not JSON: a person is reading this off a terminal in a bad moment.
    console.log(`\nRecovery link for ${args.user} — works once, expires ${minted.expiresAt.toUTCString()}:\n`);
    console.log(`  ${minted.url}\n`);
    console.log(`Opening it clears that account's passkeys and authenticator apps, then the password`);
    console.log(`alone signs in for ${String(minted.minutes)} minutes. Enrol a new factor straight away.\n`);
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
