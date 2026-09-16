import { readFile } from 'node:fs/promises';
import { importState, stateSchema } from '../admin/state.js';
import { AUDIT_EVENTS } from '../audit/events.js';
import type { AuditWriter } from '../audit/writer.js';
import type { Db } from '../db.js';
import type { Logger } from '../log.js';

// The seed file (REQ-057). Point `SEED_FILE` at a mounted JSON file and the apps and roles it
// describes exist after boot. It runs on every boot on purpose: that is what makes it a
// declaration rather than a one-off, and `importState` only creates and updates, so running it
// twice does nothing the first run did not already do.
//
// It is the same file format as an export, so the loop is: export from a working instance, mount
// it on a fresh one, done. Secrets are not in that file, so every app it creates is **secret
// pending** until somebody rotates one — the log says so, loudly, because otherwise the first
// sign-in attempt is a mystery.

export async function seedOnBoot(
  db: Db,
  path: string,
  { logger, audit }: { logger: Logger; audit?: AuditWriter },
): Promise<void> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch (err) {
    // A missing seed file is a configuration mistake worth saying out loud, but it is not a
    // reason to refuse to serve: the instance is perfectly usable without one.
    logger.warn({ err, path }, 'seed file could not be read; continuing without it');
    return;
  }

  const parsed = stateSchema.safeParse(JSON.parse(raw));
  if (!parsed.success) {
    logger.error({ path, problems: parsed.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`) }, 'seed file is not a valid state file; ignoring it');
    return;
  }

  const result = await importState(db, parsed.data, {});
  for (const problem of result.problems) logger.warn({ path }, `seed: ${problem}`);
  if (result.secretPending.length > 0) {
    logger.warn({ apps: result.secretPending }, 'seeded apps have no client secret and cannot be signed in to until one is rotated');
  }

  const created = result.apps.create.length + result.people.create.length + result.groups.create.length;
  logger.info(
    { path, apps: result.apps.create.length, people: result.people.create.length, groups: result.groups.create.length },
    created > 0 ? 'seed applied' : 'seed already satisfied',
  );

  if (created > 0) {
    await audit?.write({
      event: AUDIT_EVENTS.seedApplied,
      targetType: 'app',
      detail: { apps: result.apps.create, people: result.people.create, groups: result.groups.create },
    });
  }
}
