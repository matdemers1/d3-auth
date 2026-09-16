import { readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

// Export and import from the host (REQ-072):
//
//   docker compose exec server node dist/cli/state.js --export > d3auth-state.json
//   docker compose exec -T server node dist/cli/state.js --import - --dry-run < d3auth-state.json
//   docker compose exec -T server node dist/cli/state.js --import - < d3auth-state.json
//
// The dry run is not a courtesy. An import brings people and access with it, and the difference
// between "this adds one app" and "this grants nine people access to everything" is a thing you
// want to read before it happens rather than after.

export interface StateArgs {
  action: 'export' | 'import';
  /** A path, or "-" for stdin/stdout. */
  file: string;
  dryRun: boolean;
}

export class UsageError extends Error {}

const USAGE = 'usage: state --export [file] | --import <file|-> [--dry-run]';

export function parseArgs(argv: readonly string[]): StateArgs {
  let action: StateArgs['action'] | undefined;
  let file = '-';
  let dryRun = false;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i] ?? '';
    const next = argv[i + 1];
    if (arg === '--export' || arg === '--import') {
      action = arg.slice(2) as StateArgs['action'];
      if (next && !next.startsWith('--')) {
        file = next;
        i += 1;
      }
    } else if (arg === '--dry-run') {
      dryRun = true;
    } else {
      throw new UsageError(`unknown option ${arg}`);
    }
  }

  if (!action) throw new UsageError(USAGE);
  if (action === 'import' && file === '-' && process.stdin.isTTY) throw new UsageError('--import needs a file, or "-" with the file on stdin');
  return { action, file, dryRun };
}

const readStdin = async (): Promise<string> => {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk as Buffer));
  return Buffer.concat(chunks).toString('utf8');
};

/** Renders a plan as something worth reading before agreeing to it. */
export function describePlan(plan: {
  apps: { create: string[]; update: string[] };
  people: { create: string[]; update: string[] };
  groups: { create: string[]; update: string[] };
  secretPending: string[];
  needsReEnrolment: string[];
  problems: string[];
}): string {
  const lines: string[] = [];
  const section = (label: string, part: { create: string[]; update: string[] }): void => {
    lines.push(`${label}:  ${String(part.create.length)} new, ${String(part.update.length)} updated`);
    for (const name of part.create) lines.push(`  + ${name}`);
    for (const name of part.update) lines.push(`  ~ ${name}`);
  };
  section('Apps  ', plan.apps);
  section('People', plan.people);
  section('Groups', plan.groups);

  if (plan.secretPending.length > 0) {
    lines.push('', 'Secret pending — these apps cannot be signed in to until a secret is rotated:');
    for (const name of plan.secretPending) lines.push(`  ! ${name}`);
  }
  if (plan.needsReEnrolment.length > 0) {
    lines.push('', 'No credentials — these people cannot sign in until they are re-enrolled:');
    for (const name of plan.needsReEnrolment) lines.push(`  ! ${name}`);
  }
  if (plan.problems.length > 0) {
    lines.push('', 'Problems:');
    for (const problem of plan.problems) lines.push(`  ✗ ${problem}`);
  }
  return lines.join('\n');
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const { loadConfig } = await import('../config.js');
  const { createDb } = await import('../db.js');
  const { exportState, importState, stateSchema } = await import('../admin/state.js');

  const config = loadConfig();
  const db = createDb(config.DATABASE_URL);
  try {
    if (args.action === 'export') {
      const state = await exportState(db);
      const json = `${JSON.stringify(state, null, 2)}\n`;
      if (args.file === '-') process.stdout.write(json);
      else {
        await writeFile(args.file, json, 'utf8');
        console.error(`Wrote ${args.file}: ${String(state.apps.length)} apps, ${String(state.people.length)} people, ${String(state.groups.length)} groups.`);
        console.error('It carries no secrets, no credentials and no keys — it is a shape, not a backup.');
      }
      return;
    }

    const raw = args.file === '-' ? await readStdin() : await readFile(args.file, 'utf8');
    const parsed = stateSchema.safeParse(JSON.parse(raw));
    if (!parsed.success) {
      console.error('That file is not a state file:');
      for (const issue of parsed.error.issues) console.error(`  ${issue.path.join('.')}: ${issue.message}`);
      process.exitCode = 1;
      return;
    }

    const result = await importState(db, parsed.data, { dryRun: args.dryRun });
    console.error(`\n${args.dryRun ? 'Dry run — nothing was changed.' : 'Imported.'}\n`);
    console.error(describePlan(result));
    console.error('');
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
