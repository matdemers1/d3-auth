import { describe, expect, it } from 'vitest';
import { ACCOUNT_POLICY, delayAfter, IP_POLICY } from '../../src/security/throttle.js';

describe('throttle maths (REQ-027, REQ-028)', () => {
  it('lets the first four account attempts through free', () => {
    expect([1, 2, 3, 4].map((n) => delayAfter(n, ACCOUNT_POLICY))).toEqual([0, 0, 0, 0]);
  });

  it('doubles from the fifth failure', () => {
    expect([5, 6, 7, 8, 9].map((n) => delayAfter(n, ACCOUNT_POLICY))).toEqual([2, 4, 8, 16, 32]);
  });

  it('caps at ten minutes and stays there', () => {
    expect(delayAfter(13, ACCOUNT_POLICY)).toBe(512);
    expect(delayAfter(20, ACCOUNT_POLICY)).toBe(600);
    expect(delayAfter(500, ACCOUNT_POLICY)).toBe(600);
  });

  it('is much looser per IP, because a household shares one (R-07)', () => {
    expect(delayAfter(20, IP_POLICY)).toBe(0);
    expect(delayAfter(21, IP_POLICY)).toBe(2);
    expect(IP_POLICY.freeAttempts).toBeGreaterThan(ACCOUNT_POLICY.freeAttempts);
  });

  it('never returns a negative or non-finite delay', () => {
    for (const n of [0, -5, 1, 50, 1000]) {
      const delay = delayAfter(n, ACCOUNT_POLICY);
      expect(Number.isFinite(delay)).toBe(true);
      expect(delay).toBeGreaterThanOrEqual(0);
      expect(delay).toBeLessThanOrEqual(ACCOUNT_POLICY.maxDelaySeconds);
    }
  });
});
