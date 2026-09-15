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
