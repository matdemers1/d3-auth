import { describe, expect, it } from 'vitest';
import { parseArgs, UsageError } from '../../src/cli/seal-admin.js';

describe('seal-admin arguments', () => {
  it('needs an address, and takes a name and --rotate', () => {
    expect(parseArgs(['--email', 'sealed@example.com'])).toEqual({ email: 'sealed@example.com', name: 'Sealed admin', rotate: false });
    expect(parseArgs(['--email', 'sealed@example.com', '--name', 'Envelope', '--rotate'])).toEqual({ email: 'sealed@example.com', name: 'Envelope', rotate: true });
  });

  it('refuses anything else rather than guessing', () => {
    expect(() => parseArgs([])).toThrow(UsageError);
    expect(() => parseArgs(['--email'])).toThrow(UsageError);
    expect(() => parseArgs(['--email', 'sealed@example.com', '--force'])).toThrow(/unknown option --force/);
  });
});
