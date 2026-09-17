import { describe, expect, it } from 'vitest';
import { parseArgs, UsageError } from '../../src/cli/backup.js';

describe('the backup command line', () => {
  it('reads each action', () => {
    expect(parseArgs(['--now'])).toEqual({ action: 'now' });
    expect(parseArgs(['--list', '--dir', '/mnt/usb'])).toEqual({ action: 'list', dir: '/mnt/usb' });
    expect(parseArgs(['--drill'])).toEqual({ action: 'drill' });
    expect(parseArgs(['--restore', 'bundles/2026/09/17/d3auth-x.tar.gz', '--into', 'postgresql://x/new'])).toEqual({
      action: 'restore',
      key: 'bundles/2026/09/17/d3auth-x.tar.gz',
      into: 'postgresql://x/new',
    });
  });

  it('never restores without being told where to, so it cannot restore over the live database by accident', () => {
    expect(() => parseArgs(['--restore', 'bundles/x.tar.gz'])).toThrow(/--into/);
  });

  it('refuses nonsense', () => {
    expect(() => parseArgs([])).toThrow(UsageError);
    expect(() => parseArgs(['--restore'])).toThrow(UsageError);
    expect(() => parseArgs(['--backup'])).toThrow(UsageError);
  });
});
