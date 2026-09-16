import type { RequestHandler } from 'express';

// Security headers on every response, including errors (REQ-132).
//
// Two policies, because two kinds of response live here:
//   - Our own pages and API (console, interaction, health): locked down. Everything is
//     same-origin — fonts are self-hosted, there is no inline script, no framing, no form target
//     other than ourselves.
//   - The provider's own responses under /oidc: same locks, except `form-action`. Browsers apply
//     form-action to the redirect that *follows* a form submission, and the sign-out confirmation
//     is a form whose answer redirects to the app's registered post-logout URL. Locking it to
//     'self' would break sign-out for every app. The target is one the provider has already
//     matched exactly against the registration (REQ-005), and no page here renders anything a
//     person or app supplied. (ZAP reports the omission; it is filtered there with this reason.)
//
// No 'unsafe-inline' anywhere. The provider's one inline script — the auto-submitting form — gets a
// sha256 hash added to script-src by the provider itself.

const BASE_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "frame-src 'none'",
  "manifest-src 'self'",
];

export const CONSOLE_CSP = [...BASE_CSP, "form-action 'self'"].join('; ');
/** The provider redirects and form-posts to validated client URLs; it never renders our console. */
export const PROVIDER_CSP = BASE_CSP.join('; ');

export const HSTS = 'max-age=63072000; includeSubDomains; preload';

export interface HeaderOptions {
  /** HSTS is only meaningful over https; a local http issuer skips it. */
  hsts?: boolean;
}

export function securityHeaders(options: HeaderOptions = {}): RequestHandler {
  const hsts = options.hsts ?? true;
  return (req, res, next) => {
    res.set({
      'Content-Security-Policy': req.path.startsWith('/oidc') ? PROVIDER_CSP : CONSOLE_CSP,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    });
    // publickey-credentials-get stays available for passkeys in Phase 2 (same-origin by default).
    if (hsts) res.set('Strict-Transport-Security', HSTS);
    next();
  };
}
