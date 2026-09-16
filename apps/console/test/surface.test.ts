import { describe, expect, it } from 'vitest';
import { surfaceFor } from '../src/surface';

describe('surfaceFor', () => {
  it.each([
    ['/login', 'login'],
    ['/login/abc123', 'login'],
    ['/account', 'account'],
    ['/account/security', 'account'],
    ['/admin', 'admin'],
    ['/admin/users/1', 'admin'],
  ] as const)('%s → %s', (path, surface) => {
    expect(surfaceFor(path)).toBe(surface);
  });

  it.each(['/', '/loginx', '/administrator', '/oidc/auth'])('%s is not a console surface', (path) => {
    expect(surfaceFor(path)).toBe('not-found');
  });
});

describe('pages the server renders whole', () => {
  it('keeps React off the break-glass page', () => {
    expect(surfaceFor('/login/recover/abc123')).toBe('server-rendered');
    // Everything else under /login is still the login surface.
    expect(surfaceFor('/login/some-uid')).toBe('login');
    expect(surfaceFor('/login/invite/abc123')).toBe('login');
  });
});
