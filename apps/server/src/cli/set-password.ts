import { pathToFileURL } from 'node:url';

// A forgotten owner password, from the host (REQ-145, ADR-010, docs/runbooks/break-glass.md):
//
//   docker compose exec server node dist/cli/set-password.js --user you@example.com
//
// It asks for the new password twice with echo off. The password is never an argument, so it never
// reaches shell history, `ps`, or a log. No `-T`: without a terminal there is nothing to type into,
// and piping a password in means it was already written down somewhere.

export interface SetPasswordArgs {
  user: string;
}

export class UsageError extends Error {}

export function parseArgs(argv: readonly string[]): SetPasswordArgs {
  let user = '';
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i] ?? '';
    const next = argv[i + 1];
    if (arg === '--user' || arg === '-u') {
      if (!next) throw new UsageError('--user needs an email address');
      user = next;
      i += 1;
    } else if (arg === '--password' || arg.startsWith('--password=')) {
      throw new UsageError('the password is never an argument; leave it out and type it at the prompt');
    } else {
      throw new UsageError(`unknown option ${arg}`);
    }
  }
  if (!user) throw new UsageError('usage: set-password --user <owner email>');
  return { user };
}

/**
 * Asks each question in turn and reads one line per answer, with nothing echoed. The terminal stays
 * in raw mode for all of them: dropping out of it between two questions echoes whatever is typed
 * next. Ctrl-C leaves without changing anything.
 */
function promptHidden(questions: readonly string[]): Promise<string[]> {
  const input = process.stdin;
  const output = process.stdout;
  return new Promise((resolve, reject) => {
    const answers: string[] = [];
    let typed = '';
    const finish = (error?: Error): void => {
      input.off('data', onData);
      input.setRawMode(false);
      input.pause();
      if (error) {
        output.write('\n');
        reject(error);
      } else resolve(answers);
    };
    const onData = (chunk: Buffer): void => {
      for (const char of chunk.toString('utf8')) {
        if (char === '\u0003' || char === '\u0004') {
          finish(new UsageError('Stopped. Nothing was changed.'));
          return;
        }
        if (char === '\r' || char === '\n') {
          answers.push(typed);
          typed = '';
          output.write('\n');
          const next = questions[answers.length];
          if (next === undefined) {
            finish();
            return;
          }
          output.write(next);
        } else if (char === '\u007f' || char === '\b') typed = typed.slice(0, -1);
        else if (char >= ' ') typed += char;
      }
    };
    input.setRawMode(true);
    input.resume();
    input.on('data', onData);
    output.write(questions[0] ?? '');
  });
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (!process.stdin.isTTY) {
    throw new UsageError('set-password needs a terminal to type into. Run it with `docker compose exec`, without -T.');
  }

  const { loadConfig } = await import('../config.js');
  const { createDb } = await import('../db.js');
  const { createLogger } = await import('../log.js');
  const { createAuditWriter } = await import('../audit/writer.js');
  const { createSecretHasher } = await import('../security/hash.js');
  const { setOwnerPassword } = await import('../setup/owner-password.js');

  const [password = '', again] = await promptHidden([`New password for ${args.user}: `, 'Type it again: ']);
  if (password !== again) throw new UsageError('Those were not the same. Nothing was changed.');

  const config = loadConfig();
  const db = createDb(config.DATABASE_URL);
  try {
    const result = await setOwnerPassword(
      { db, hasher: createSecretHasher(config.PEPPER), audit: createAuditWriter(db, createLogger({ level: 'warn' })) },
      { email: args.user, password },
    );
    console.log(`\nThe password for ${result.email} is set. ${String(result.sessionsEnded)} session(s) ended.`);
    if (result.factors > 0) {
      console.log('Your passkeys and authenticator apps are unchanged: sign in with the new password and your usual second step.');
    } else {
      console.log('This account has no second factor. Sign in and add a passkey straight away: Account → How you sign in.');
    }
    console.log('Every alert recipient is emailed about this within five minutes.\n');
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
