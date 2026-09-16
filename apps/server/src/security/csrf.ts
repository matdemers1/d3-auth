import { randomBytes, timingSafeEqual } from 'node:crypto';

// CSRF for interaction POSTs (REQ-031). The token is minted with the login flow, kept server-side
// beside its state, and echoed by the form. The browser binding is the provider's `__Host-`
// interaction cookie, so a token alone is useless from another origin.

export const csrfToken = (): string => randomBytes(32).toString('base64url');

export function csrfMatches(expected: string, received: unknown): boolean {
  if (typeof received !== 'string' || received.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(expected), Buffer.from(received));
}
