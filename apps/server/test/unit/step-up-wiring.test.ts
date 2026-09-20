import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * A console screen that calls a step-up-protected route must ask for the proof.
 *
 * `requireFreshOwner` answers `401 step_up_required` when the last proof is older than the window.
 * The console has a `useStepUp` hook that catches exactly that, prompts, and repeats the call —
 * and `AppDetail` did not use it. Outside the window, Rotate secret, Disable sign-in and Apply
 * manifest all did nothing at all: no prompt, no error, no rotation. It fails *silently*, which is
 * why it survived an ASVS review, an e2e suite and months of use.
 *
 * This reads the server's own route table rather than a list written here, so a route that becomes
 * step-up protected later is covered the day it changes.
 */

const ROUTES = join(import.meta.dirname, '../../src/admin/routes.ts');
const SCREENS = join(import.meta.dirname, '../../../console/src');

/** Route paths guarded by `requireFreshOwner`, as the server declares them. */
function freshGuardedPaths(): string[] {
  const source = readFileSync(ROUTES, 'utf8');
  const paths: string[] = [];

  // Each registration is `router.post(<path>, ... auth.requireFreshOwner ...)`, sometimes wrapped
  // over several lines, so take the path that most recently preceded each guard.
  for (const [index] of [...source.matchAll(/auth\.requireFreshOwner/g)].map((m) => [m.index])) {
    const before = source.slice(0, index);
    const path = [...before.matchAll(/\$\{ADMIN_API\}([^`]*)/g)].at(-1)?.[1];
    if (path !== undefined) paths.push(path);
  }
  return [...new Set(paths)];
}

function screens(): { file: string; source: string }[] {
  const found: { file: string; source: string }[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.tsx')) found.push({ file: full, source: readFileSync(full, 'utf8') });
    }
  };
  walk(SCREENS);
  return found;
}

describe('step-up wiring', () => {
  it('finds the routes that demand fresh proof', () => {
    const paths = freshGuardedPaths();

    // Guard the guard: a regex that matched nothing would make every assertion below vacuous.
    expect(paths.length).toBeGreaterThan(3);
    expect(paths).toContain('/apps/:clientId/secret');
  });

  it('asks for the proof wherever one of them is called', () => {
    const paths = freshGuardedPaths();
    const files = screens();
    const missing: string[] = [];

    for (const path of paths) {
      // The console builds these from a `base`, so the full path is never written out. Two things
      // have to line up before a file counts as calling this route: it must build a base on the
      // same family, and it must post to this tail. Listing another family's records with a plain
      // GET — which `GroupDetail` does for apps — is not calling into it.
      const segments = path.split('/').filter((seg) => seg !== '' && !seg.startsWith(':'));
      const family = segments.at(0);
      const tail = segments.at(-1);
      if (family === undefined || tail === undefined) continue;

      for (const { file, source } of files) {
        const owns =
          family === tail
            ? new RegExp(`api\\.(post|del|patch)[^\\n]*/api/admin/${family}['\`]`).test(source)
            : source.includes(`/api/admin/${family}/\${`) &&
              new RegExp(`api\\.(post|del|patch)[^\\n]*['\`/]${tail}\\b`).test(source);
        if (owns && !source.includes('useStepUp')) missing.push(`${file} calls ${path}`);
      }
    }

    expect(missing, 'these would fail silently outside the step-up window').toEqual([]);
  });
});
