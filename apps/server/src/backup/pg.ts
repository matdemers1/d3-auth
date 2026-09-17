import { spawn } from 'node:child_process';
import { createReadStream, createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';

// pg_dump and pg_restore, by stream (T-6.1).
//
// Streams rather than file arguments, so the same code works when the tools run somewhere else:
// in the image they are local binaries; on a laptop without a matching Postgres client they run
// inside the database container through `PG_TOOLS_PREFIX="docker exec -i <container>"`. A newer
// client than the server is not an option — pg_dump 17 writes settings Postgres 16 refuses.

const prefix = (): string[] => (process.env.PG_TOOLS_PREFIX ?? '').split(' ').filter(Boolean);

function tool(name: 'pg_dump' | 'pg_restore', args: string[]) {
  const [command, ...rest] = [...prefix(), name, ...args];
  return spawn(command ?? name, rest, { stdio: ['pipe', 'pipe', 'pipe'] });
}

async function finished(child: ReturnType<typeof tool>, name: string): Promise<void> {
  let stderr = '';
  child.stderr.on('data', (chunk: Buffer) => {
    stderr += chunk.toString();
  });
  const code = await new Promise<number | null>((resolve, reject) => {
    child.on('error', reject);
    child.on('close', resolve);
  });
  // The connection string never appears here: it is an argument, and only stderr is reported.
  if (code !== 0) throw new Error(`${name} exited ${String(code)}: ${stderr.trim().split('\n').slice(-3).join(' | ')}`);
}

/** A custom-format dump of the whole database, written to `file`. */
export async function dumpDatabase(databaseUrl: string, file: string): Promise<void> {
  const child = tool('pg_dump', ['--format=custom', '--no-owner', '--no-privileges', `--dbname=${databaseUrl}`]);
  child.stdin.end();
  await Promise.all([pipeline(child.stdout, createWriteStream(file)), finished(child, 'pg_dump')]);
}

/** Restores a custom-format dump into an existing, empty database. */
export async function restoreDatabase(databaseUrl: string, file: string): Promise<void> {
  const child = tool('pg_restore', ['--no-owner', '--no-privileges', '--exit-on-error', `--dbname=${databaseUrl}`]);
  child.stdout.resume();
  await Promise.all([pipeline(createReadStream(file), child.stdin), finished(child, 'pg_restore')]);
}
