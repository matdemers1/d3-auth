// AUTH-T-8.2: what the entry screens' story panel says. Every claim is one a person can check:
//
// - Admins hold a second factor: an account cannot be made an admin without a verified passkey or
//   authenticator app, and an admin cannot remove their last one (REQ-035, REQ-042 —
//   apps/server/src/security/factors.ts, test/integration/admin-factor-rule.test.ts). Guests may
//   sign in with a password alone, so the claim is about admins and nobody else.
// - Apps are refused until granted: no grant means access_denied before any interstitial, audited
//   (REQ-051 — test/integration/deny-by-default.test.ts). The roles claim carries only the asking
//   app's roles (REQ-052 — test/integration/roles-claim.test.ts).
// - The OpenID conformance suite runs in CI on every pull request and every push to main
//   (.github/workflows/ci.yml, job `conformance`).
//
// The server draws the same words into the no-JavaScript page (apps/server/src/interaction/
// auth-markup.ts); test/entry-parity.test.tsx fails if the two ever differ.

export const ENTRY_PRODUCT = 'D3 Auth';
export const ENTRY_HEADLINE = 'One account —';
export const ENTRY_HEADLINE_ACCENT = 'for every app that uses it.';
export const ENTRY_PROMISE = 'Sign in here once, rather than in every app. Each app is told only the roles you were granted for it.';
export const ENTRY_CLAIMS: readonly { title: string; detail: string }[] = [
  { title: 'Admins hold a second factor.', detail: 'Nobody is made an admin without a passkey or a code.' },
  { title: 'Apps are refused until granted.', detail: 'Access is per app, and denied by default.' },
  { title: 'Tested against the OpenID conformance suite.', detail: 'On every change, in CI.' },
];
export const ENTRY_FOOT = 'self-hosted';
