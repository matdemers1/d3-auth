import { describe, expect, it } from 'vitest';
import { describePlan, parseArgs, UsageError } from '../../src/cli/state.js';

// The CLI in front of export/import (REQ-072). What matters here is that a dry run cannot be
// asked for accidentally and cannot be lost accidentally: `--import file --dry-run` and
// `--import file` differ by one flag and by everything.

describe('parsing', () => {
  it('reads an export to stdout and to a file', () => {
    expect(parseArgs(['--export'])).toEqual({ action: 'export', file: '-', dryRun: false });
    expect(parseArgs(['--export', 'state.json'])).toEqual({ action: 'export', file: 'state.json', dryRun: false });
  });

  it('reads an import, with and without the dry run', () => {
    expect(parseArgs(['--import', 'state.json'])).toEqual({ action: 'import', file: 'state.json', dryRun: false });
    expect(parseArgs(['--import', 'state.json', '--dry-run'])).toEqual({ action: 'import', file: 'state.json', dryRun: true });
  });

  it('refuses nonsense rather than guessing', () => {
    expect(() => parseArgs([])).toThrow(UsageError);
    expect(() => parseArgs(['--restore', 'state.json'])).toThrow(UsageError);
    expect(() => parseArgs(['--dry-run'])).toThrow(UsageError);
  });
});

describe('the plan it prints', () => {
  it('leads with what changes and ends with what will still be broken', () => {
    const text = describePlan({
      apps: { create: ['bindery'], update: [] },
      people: { create: [], update: ['sam@example.com'] },
      groups: { create: [], update: [] },
      secretPending: ['bindery'],
      needsReEnrolment: ['sam@example.com'],
      problems: ['Group "Staff" lists nobody@example.com, who is not in this file.'],
    });

    expect(text).toContain('+ bindery');
    expect(text).toContain('~ sam@example.com');
    expect(text).toContain('Secret pending');
    expect(text).toContain('cannot sign in until they are re-enrolled');
    expect(text).toContain('✗ Group "Staff" lists nobody@example.com');
  });
});
