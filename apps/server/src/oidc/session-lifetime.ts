import { interactionPolicy, type KoaContextWithOIDC } from 'oidc-provider';

// How long a sign-in lasts (REQ-029; ASVS 5.0 7.1.1, 7.3.1, 7.3.2).
//
// Two limits, and a session ends at whichever comes first:
//
// - **Idle.** Every request that touches the session pushes its expiry out again, by the number of
//   days the owner set in Settings (default 30). A browser nobody uses for that long is signed out.
// - **Absolute.** Ninety days after somebody last actually proved who they were, they prove it
//   again, however busy the session has been. Activity cannot keep a sign-in alive forever.
//
// Why these numbers and not NIST 800-63B's AAL2 (12 hours absolute, 30 minutes idle): the apps this
// provider serves are a household's and a small team's, used on personal devices, and every
// sensitive action already asks for fresh proof on its own — owner-only console actions within five
// minutes of signing in (REQ-037), password changes with the current password. A session is a
// convenience for reaching apps; the things worth protecting are behind their own re-authentication.
// Both limits are recorded in the ASVS self-assessment with that reasoning.

export const SESSION_ABSOLUTE_DAYS = 90;
export const SESSION_ABSOLUTE_SECONDS = SESSION_ABSOLUTE_DAYS * 24 * 60 * 60;
export const DEFAULT_IDLE_DAYS = 30;

const DAY = 24 * 60 * 60;
const nowSeconds = (): number => Math.floor(Date.now() / 1000);

/** True once the sign-in behind a session is older than the absolute limit. */
export function pastAbsoluteLifetime(loginTs: number | undefined, now = nowSeconds()): boolean {
  return typeof loginTs === 'number' && now - loginTs >= SESSION_ABSOLUTE_SECONDS;
}

/**
 * The session's TTL each time it is saved: the idle window, cut short by whatever remains of the
 * absolute one. Synchronous, because the provider calls it synchronously; the idle days are read
 * from a value the service keeps current.
 */
export function sessionTtl(idleDays: () => number) {
  return (_ctx: KoaContextWithOIDC, session: { loginTs?: number | undefined }): number => {
    const idle = Math.max(1, Math.min(idleDays(), SESSION_ABSOLUTE_DAYS)) * DAY;
    if (typeof session.loginTs !== 'number') return idle;
    const remaining = session.loginTs + SESSION_ABSOLUTE_SECONDS - nowSeconds();
    // The provider insists on a positive number. A session already past its limit is also refused a
    // login by the check below, so this second is never enough to be used.
    return Math.max(1, Math.min(idle, remaining));
  };
}

/**
 * The provider's default interaction policy, plus one check on the login prompt: a session whose
 * sign-in is older than the absolute limit must sign in again, exactly as if `max_age` had asked.
 */
export function interactionPolicyWithAbsoluteLifetime(): ReturnType<typeof interactionPolicy.base> {
  const policy = interactionPolicy.base();
  const login = policy.get('login');
  login?.checks.add(
    new interactionPolicy.Check(
      'session_absolute_lifetime',
      'the sign-in is older than the absolute session lifetime',
      (ctx) => (pastAbsoluteLifetime(ctx.oidc.session?.loginTs) ? interactionPolicy.Check.REQUEST_PROMPT : interactionPolicy.Check.NO_NEED_TO_PROMPT),
    ),
  );
  return policy;
}
