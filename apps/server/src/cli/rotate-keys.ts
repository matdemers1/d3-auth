import { pathToFileURL } from 'node:url';

// Rotating the signing keys, from the host (REQ-118):
//
//   docker compose exec server node dist/cli/rotate-keys.js --list
//   docker compose exec server node dist/cli/rotate-keys.js --generate
//   ... wait ...
//   docker compose exec server node dist/cli/rotate-keys.js --promote
//   docker compose restart server           # the new key starts signing here
//   ... wait ...
//   docker compose exec server node dist/cli/rotate-keys.js --retire
//
// The waits are the whole point, and the CLI refuses to skip them. A consumer caches the key
// set: promote before it has seen the new key and real tokens fail to verify; retire before the
// old tokens expire and the same thing happens from the other end.

export type Action = 'list' | 'generate' | 'promote' | 'retire';

export interface RotateArgs {
  action: Action;
  alg: 'ES256' | 'RS256';
  /** Skips the wait. Only for a key somebody else is holding. */
  force: boolean;
  kid?: string;
}

export class UsageError extends Error {}

export function parseArgs(argv: readonly string[]): RotateArgs {
  let action: Action | undefined;
  let alg: RotateArgs['alg'] = 'ES256';
  let force = false;
  let kid: string | undefined;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i] ?? '';
    const next = argv[i + 1];
    switch (arg) {
      case '--list':
      case '--generate':
      case '--promote':
      case '--retire':
        action = arg.slice(2) as Action;
        break;
      case '--alg':
        if (next !== 'ES256' && next !== 'RS256') throw new UsageError('--alg must be ES256 or RS256');
        alg = next;
        i += 1;
        break;
      case '--kid':
        if (!next) throw new UsageError('--kid needs a key id');
        kid = next;
        i += 1;
        break;
      case '--force':
        force = true;
        break;
      default:
        throw new UsageError(`unknown option ${arg}`);
    }
  }

  if (!action) throw new UsageError('usage: rotate-keys --list | --generate | --promote | --retire [--alg ES256|RS256] [--force]');
  return { action, alg, force, ...(kid ? { kid } : {}) };
}

const when = (date: Date | null): string => (date ? date.toISOString().replace('T', ' ').slice(0, 16) : '—');

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const { loadConfig } = await import('../config.js');
  const { createDb } = await import('../db.js');
  const { createKekCrypto } = await import('../security/kek.js');
  const { generateNext, listKeys, MINIMUM_OVERLAP_MS, promoteNext, retire } = await import('../oidc/keys.js');

  const config = loadConfig();
  const db = createDb(config.DATABASE_URL);
  try {
    if (args.action === 'list') {
      const keys = await listKeys(db);
      console.log('\nstatus     alg     kid                                              created           ready');
      for (const key of keys) {
        console.log(
          `${key.status.padEnd(10)} ${key.alg.padEnd(7)} ${key.kid.padEnd(46)} ${when(key.createdAt)}  ${
            key.status === 'next' || key.status === 'retiring' ? (key.ready ? 'now' : when(key.readyAt)) : ''
          }`,
        );
      }
      console.log('');
      return;
    }

    if (args.action === 'generate') {
      const key = await generateNext(db, createKekCrypto(config.KEK), args.alg);
      console.log(`\nGenerated a next ${args.alg} key: ${key.kid}`);
      console.log(`It is published now and signs nothing. Promote it after ${when(key.readyAt)} (${String(MINIMUM_OVERLAP_MS / 3_600_000)} hours).\n`);
      return;
    }

    if (args.action === 'promote') {
      const { promoted, retiring } = await promoteNext(db, args.alg, { force: args.force });
      console.log(`\n${promoted.kid} is now the current ${args.alg} key.`);
      if (retiring) console.log(`${retiring} is retiring and still verifies what it signed.`);
      // The process loaded its keys at boot, so this is not finished until it starts again.
      console.log('\nRestart the service to start signing with it:  docker compose restart server\n');
      return;
    }

    const retired = await retire(db, { ...(args.kid ? { kid: args.kid } : {}), force: args.force });
    console.log(`\nRetired: ${retired.map((key) => key.kid).join(', ')}`);
    console.log('They are out of the key set. Restart the service so it stops offering them.\n');
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
