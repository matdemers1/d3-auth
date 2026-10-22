import { describe, expect, it } from 'vitest';
import { parseArgs, UsageError } from '../../src/cli/set-password.js';

// Like recover, this is run once, in a bad moment. And the one thing it must never accept is the
// password itself on the command line, where shell history and `ps` would keep it.

describe('set-password --user', () => {
  it('reads both spellings', () => {
    expect(parseArgs(['--user', 'you@example.com'])).toEqual({ user: 'you@example.com' });
    expect(parseArgs(['-u', 'you@example.com'])).toEqual({ user: 'you@example.com' });
  });

  it('says what it needs', () => {
    expect(() => parseArgs([])).toThrow(UsageError);
    expect(() => parseArgs(['--user'])).toThrow(/needs an email/);
    expect(() => parseArgs(['--force'])).toThrow(/unknown option/);
  });

  it('refuses a password on the command line, in either form', () => {
    expect(() => parseArgs(['--user', 'you@example.com', '--password', 'hunter2'])).toThrow(/never an argument/);
    expect(() => parseArgs(['--user', 'you@example.com', '--password=hunter2'])).toThrow(/never an argument/);
  });
});
