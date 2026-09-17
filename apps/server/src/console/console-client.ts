import type { ClientMetadata } from 'oidc-provider';

// The console's own client (ADR-005).
//
// The console rides the SSO session, but a session only comes into being at the end of an
// authorization request — and every client used to be an app somebody registered. So a person who
// signed out, or who typed the address in, had no way to start one: the console showed empty pages
// and nothing on this origin would put a sign-in form in front of them.
//
// This client is how the console asks. It is built in, not a row in the App table: it cannot be
// disabled, edited, granted or exported, and no registered app may take its id. It is public and
// always uses PKCE; its one redirect URI is on this origin. Any active account may use it, because
// what it opens is the person's own account page — the console's own guards still decide who sees
// `/admin`. It asks for `openid` only, so a token issued to it says who you are and nothing more.

export const CONSOLE_CLIENT_ID = 'd3auth-console';

export const SIGNIN_PATH = '/signin';
export const SIGNIN_CALLBACK_PATH = '/signin/callback';
/** Where the console lands after signing out: a page that says so, with a way back in. */
export const SIGNED_OUT_PATH = '/signed-out';

export const isConsoleClient = (clientId: string): boolean => clientId === CONSOLE_CLIENT_ID;

export function consoleClientMetadata(issuer: string): ClientMetadata {
  const origin = new URL(issuer).origin;
  return {
    client_id: CONSOLE_CLIENT_ID,
    client_name: 'D3 Auth',
    application_type: 'web',
    token_endpoint_auth_method: 'none',
    redirect_uris: [`${origin}${SIGNIN_CALLBACK_PATH}`],
    post_logout_redirect_uris: [`${origin}${SIGNED_OUT_PATH}`, `${origin}${SIGNIN_PATH}`],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    response_modes: ['query'],
    scope: 'openid',
    id_token_signed_response_alg: 'ES256',
  };
}
