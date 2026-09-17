// The three surfaces the console serves (REQ-061). Each is its own lazy chunk, so a phone
// on the sign-in screen never downloads the admin console (REQ-077, R-09).

export type Surface = 'login' | 'account' | 'admin' | 'server-rendered' | 'not-found';

/**
 * Pages the server renders completely and React must not touch. The break-glass page (REQ-122)
 * is one: opening it is what claims the link, so a React screen that asked again on mount would
 * be told the link had already been used — by itself.
 */
const SERVER_RENDERED: readonly string[] = ['/login/recover/', '/oidc/session/end', '/signed-out'];

const PREFIXES: readonly (readonly [string, Surface])[] = [
  ['/login', 'login'],
  ['/account', 'account'],
  ['/admin', 'admin'],
];

export function surfaceFor(pathname: string): Surface {
  if (SERVER_RENDERED.some((prefix) => pathname.startsWith(prefix))) return 'server-rendered';
  for (const [prefix, surface] of PREFIXES) {
    if (pathname === prefix || pathname.startsWith(`${prefix}/`)) return surface;
  }
  return 'not-found';
}
