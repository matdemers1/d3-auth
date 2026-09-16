import { describe, expect, it } from 'vitest';
import { parseArgs, UsageError } from '../../src/cli/recover.js';

// The CLI is used once, in a bad moment, by someone who is already having a difficult day. It
// should fail with a sentence, not a stack trace.

describe('recover --user --minutes', () => {
  it('reads both spellings of each option', () => {
    expect(parseArgs(['--user', 'you@example.com'])).toEqual({ user: 'you@example.com', minutes: 15 });
    expect(parseArgs(['-u', 'you@example.com', '-m', '5'])).toEqual({ user: 'you@example.com', minutes: 5 });
    expect(parseArgs(['--minutes', '30', '--user', 'you@example.com'])).toEqual({ user: 'you@example.com', minutes: 30 });
  });

  it('says what it needs', () => {
    expect(() => parseArgs([])).toThrow(UsageError);
    expect(() => parseArgs(['--user'])).toThrow(/needs an email/);
    expect(() => parseArgs(['--user', 'you@example.com', '--minutes', 'soon'])).toThrow(/positive number/);
    expect(() => parseArgs(['--user', 'you@example.com', '--minutes', '-3'])).toThrow(/positive number/);
    expect(() => parseArgs(['--force'])).toThrow(/unknown option/);
  });
});
