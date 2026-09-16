import type { RequestHandler } from 'express';

// Security headers on every response, including errors (REQ-132).
//
// Two policies, because two kinds of response live here:
//   - Our own pages and API (console, interaction, health): locked down. Everything is
//     same-origin — fonts are self-hosted, there is no inline script, no framing, no form target
//     other than ourselves.
//   - The provider's own responses under /oidc: same locks, except `form-action`, because
//     form_post response mode and the logout confirmation post to a registered client URL that
//     the provider (not the browser) has already validated exactly.

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
export const PROVIDER_CSP = [...BASE_CSP.filter((d) => !d.startsWith('script-src')), "script-src 'self' 'unsafe-inline'"].join('; ');

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
