import { describe, expect, it } from 'vitest';
import { untilNext } from '../../src/jobs/daily.js';

describe('the daily schedule', () => {
  it('waits until later today when the time has not come yet', () => {
    expect(untilNext('02:30', new Date('2026-09-16T01:30:00Z'))).toBe(60 * 60 * 1000);
  });

  it('waits until tomorrow when it has passed, including exactly now', () => {
    expect(untilNext('02:30', new Date('2026-09-16T02:31:00Z'))).toBe(23 * 60 * 60 * 1000 + 59 * 60 * 1000);
    expect(untilNext('02:30', new Date('2026-09-16T02:30:00Z'))).toBe(24 * 60 * 60 * 1000);
  });

  it('is UTC, whatever the host thinks the time zone is', () => {
    // 23:00 at UTC−5 is 04:00 UTC, so the next midnight UTC is twenty hours away.
    expect(untilNext('00:00', new Date('2026-09-16T23:00:00-05:00'))).toBe(20 * 60 * 60 * 1000);
  });
});
