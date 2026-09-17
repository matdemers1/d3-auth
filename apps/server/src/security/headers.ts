import { randomBytes } from 'node:crypto';
import type { RequestHandler, Response } from 'express';

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
// sha256 hash added to script-src by the provider itself. The console has one too: the design
// system's theme boot script in apps/console/index.html, which sets light or dark before the first
// paint (D-066). It is allowed by the hash of exactly that script, and nothing else inline runs.
// test/unit/headers.test.ts hashes the file itself, so the two cannot drift apart.
//
// Styles are the same rule with a nonce instead of a hash. The design system's dialogs and phone
// drawer lock the page's scroll with a <style> element Radix writes at runtime; its contents vary,
// so no hash can allow it. Every console response gets a fresh random nonce in `style-src`, and any
// HTML it sends carries that nonce in <meta name="d3-style-nonce">, which the console hands to
// @d3cloud/ui (`setStyleNonce`) before it renders. The nonce is for styles only — scripts stay
// hash-only — and a page that injects markup cannot learn it: it changes with every response.

/** sha256 of the inline `<script>` in apps/console/index.html (`themeBootScript()` from @d3cloud/ui). */
export const THEME_BOOT_SCRIPT_HASH = "'sha256-59L8/iAzZ528VLBKND6XMlQ+evHRA0yaYEo85pD8VCc='";

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

/** The console policy for one response, allowing styles carrying `styleNonce`. */
export const consoleCsp = (styleNonce: string): string =>
  [
    ...BASE_CSP.map((directive) =>
      directive === "script-src 'self'"
        ? `script-src 'self' ${THEME_BOOT_SCRIPT_HASH}`
        : directive === "style-src 'self'"
          ? `style-src 'self' 'nonce-${styleNonce}'`
          : directive,
    ),
    "form-action 'self'",
  ].join('; ');

/** The nonce this response's styles must carry. Set by `securityHeaders` on every non-provider response. */
export const styleNonceOf = (res: Response): string | undefined => res.locals.styleNonce as string | undefined;

/** Puts the nonce where the console reads it: first thing in <head>. */
export function withStyleNonce(html: string, nonce: string): string {
  return html.replace(/<head([^>]*)>/i, (head) => `${head}<meta name="d3-style-nonce" content="${nonce}">`);
}
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
    const provider = req.path.startsWith('/oidc');
    const styleNonce = provider ? undefined : randomBytes(18).toString('base64url');
    if (styleNonce) {
      res.locals.styleNonce = styleNonce;
      // Any HTML this response sends carries the nonce. Pages built from index.html go through
      // res.send, so this one place covers the console shell and every server-rendered page.
      const send = res.send.bind(res);
      res.send = (body?: unknown) => {
        const type = res.get('Content-Type') ?? '';
        return send(typeof body === 'string' && type.includes('text/html') ? withStyleNonce(body, styleNonce) : body);
      };
    }
    res.set({
      'Content-Security-Policy': styleNonce ? consoleCsp(styleNonce) : PROVIDER_CSP,
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
