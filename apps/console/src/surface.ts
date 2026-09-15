// The three surfaces the console serves (REQ-061). Each is its own lazy chunk, so a phone
// on the sign-in screen never downloads the admin console (REQ-077, R-09).

export type Surface = 'login' | 'account' | 'admin' | 'not-found';

const PREFIXES: readonly (readonly [string, Surface])[] = [
  ['/login', 'login'],
  ['/account', 'account'],
  ['/admin', 'admin'],
];

export function surfaceFor(pathname: string): Surface {
  for (const [prefix, surface] of PREFIXES) {
    if (pathname === prefix || pathname.startsWith(`${prefix}/`)) return surface;
  }
  return 'not-found';
}
