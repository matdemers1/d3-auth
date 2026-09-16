import { describe, expect, it } from 'vitest';
import { parseArgs, UsageError } from '../../src/cli/rotate-keys.js';

// The CLI is used rarely, under pressure, by somebody following a runbook. It should fail with a
// sentence rather than a stack trace.

describe('rotate-keys arguments', () => {
  it('reads the four actions', () => {
    expect(parseArgs(['--list']).action).toBe('list');
    expect(parseArgs(['--generate']).action).toBe('generate');
    expect(parseArgs(['--promote']).action).toBe('promote');
    expect(parseArgs(['--retire']).action).toBe('retire');
  });

  it('defaults to ES256 and takes RS256 when asked', () => {
    expect(parseArgs(['--generate'])).toMatchObject({ alg: 'ES256', force: false });
    expect(parseArgs(['--generate', '--alg', 'RS256']).alg).toBe('RS256');
  });

  it('takes a kid and the force flag', () => {
    expect(parseArgs(['--retire', '--kid', 'abc', '--force'])).toMatchObject({ kid: 'abc', force: true });
  });

  it('says what it needs', () => {
    expect(() => parseArgs([])).toThrow(UsageError);
    expect(() => parseArgs(['--generate', '--alg', 'HS256'])).toThrow(/ES256 or RS256/);
    expect(() => parseArgs(['--retire', '--kid'])).toThrow(/needs a key id/);
    expect(() => parseArgs(['--rotate-everything'])).toThrow(/unknown option/);
  });
});
