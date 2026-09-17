// Signing out of the console (ADR-005). Naming the console's own client and its registered
// post-logout address is what lets the provider send the browser back to the sign-in form once it
// has asked "Sign out?" — rather than leaving it on a page that says so and goes nowhere.

export const SIGN_OUT_HREF = `/oidc/session/end?${new URLSearchParams({
  client_id: 'd3auth-console',
  post_logout_redirect_uri: `${window.location.origin}/signed-out`,
}).toString()}`;
