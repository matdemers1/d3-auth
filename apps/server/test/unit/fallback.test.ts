import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { fallbackForm, renderContinueAsPage, renderRecoveryPage } from '../../src/interaction/fallback.js';
import { inviteForm } from '../../src/interaction/invite-page.js';
import { setupFinishedPage, setupForm } from '../../src/setup/page.js';
import { start, type LoginState } from '../../src/interaction/machine.js';

// The no-JavaScript forms (REQ-010) and the break-glass page (REQ-122).

const identity = { accountId: 'user-1', factors: ['totp'] as const, deviceTrusted: false };

const view = (state: LoginState) => ({
  uid: 'abc',
  flow: { state, csrf: 'token-1', attemptedEmail: 'them@example.com' },
  clientName: 'Web App',
  operatorDisplayName: 'Matthew',
});

describe('the form that arrives in the HTML', () => {
  it('posts each step to its own endpoint', () => {
    expect(fallbackForm(view(start()))).toContain('action="/api/interaction/abc/identify"');
    expect(fallbackForm(view({ name: 'awaiting_password', identity }))).toContain('action="/api/interaction/abc/password"');
    expect(fallbackForm(view({ name: 'awaiting_factor', identity, amr: ['pwd'] }))).toContain('action="/api/interaction/abc/totp"');
    expect(fallbackForm(view({ name: 'awaiting_trusted_device', identity, amr: ['pwd', 'otp'] }))).toContain(
      'action="/api/interaction/abc/trust"',
    );
  });

  it('carries the CSRF token on every step', () => {
    for (const state of [
      start(),
      { name: 'awaiting_password' as const, identity },
      { name: 'awaiting_factor' as const, identity, amr: ['pwd'] as const },
      { name: 'awaiting_trusted_device' as const, identity, amr: ['pwd', 'otp'] as const },
    ]) {
      expect(fallbackForm(view(state))).toContain('name="csrf" value="token-1"');
    }
  });

  it('offers both answers to the trusted-device question', () => {
    const html = fallbackForm(view({ name: 'awaiting_trusted_device', identity, amr: ['pwd', 'otp'] }));
    expect(html).toContain('name="trust" value="true"');
    expect(html).toContain('name="trust" value="false"');
  });

  it('escapes what the browser told us', () => {
    const nasty = view({ name: 'awaiting_password', identity });
    nasty.flow.attemptedEmail = '<script>alert(1)</script>';
    expect(fallbackForm(nasty)).not.toContain('<script>alert(1)</script>');
  });
});

describe('the classes it is drawn in', () => {
  // The no-JavaScript pages carry no styles of their own: they borrow the design system's, and the
  // entry shell's from the console (AUTH-T-8.2). A class renamed in either would leave them unstyled
  // with nothing failing, so every class they use has to exist in a stylesheet the console ships.
  const css = readFileSync(new URL('../../../console/node_modules/@d3cloud/ui/dist/index.css', import.meta.url), 'utf8');
  const consoleCss = ['src/entry/entry.css', 'src/brand/mark.css']
    .map((file) => readFileSync(new URL(`../../../console/${file}`, import.meta.url), 'utf8'))
    .join('\n');
  const pages = [
    fallbackForm(view(start())),
    fallbackForm(view({ name: 'awaiting_password', identity })),
    fallbackForm(view({ name: 'awaiting_factor', identity, amr: ['pwd'] })),
    fallbackForm(view({ name: 'awaiting_trusted_device', identity, amr: ['pwd', 'otp'] })),
    renderContinueAsPage('/nowhere', { uid: 'abc', csrf: 't', clientName: 'Web App', username: 'them', displayName: 'Them', operatorDisplayName: 'Matthew' }),
    renderRecoveryPage('/nowhere', { ok: true, email: 'owner@example.com', expiresAt: new Date(0) }, 'Matthew'),
    setupForm(),
    setupFinishedPage(),
    inviteForm({ valid: true, email: 'guest@example.com', token: 'tok', operatorDisplayName: 'Matthew' }),
  ];
  const used = new Set(pages.flatMap((html) => [...html.matchAll(/class="([^"]+)"/g)].flatMap((match) => (match[1] ?? '').split(/\s+/))));
  const pattern = (name: string) => new RegExp(`\\.${name.replace(/[-_]/g, (c) => `\\${c}`)}(?![\\w-])`);

  it('uses only the design system\'s d3- classes and the console\'s own auth- classes', () => {
    expect([...used].filter((name) => !name.startsWith('d3-') && !name.startsWith('auth-'))).toEqual([]);
  });

  it.each([...used].filter((name) => name.startsWith('d3-')))('%s exists in @d3cloud/ui', (name) => {
    expect(css).toMatch(pattern(name));
  });

  it.each([...used].filter((name) => name.startsWith('auth-')))('%s exists in the console\'s entry and mark styles', (name) => {
    expect(consoleCss).toMatch(pattern(name));
  });

  it('writes no style attribute and no script: the CSP allows neither', () => {
    for (const html of pages) {
      expect(html).not.toMatch(/\sstyle=/);
      expect(html).not.toMatch(/<script/i);
    }
  });

  it('labels every field it draws', () => {
    for (const html of pages) {
      for (const match of html.matchAll(/<input class="d3-inp__control" id="([^"]+)"/g)) {
        expect(html).toContain(`for="${match[1] ?? ''}"`);
      }
    }
  });
});

describe('the entry shell it is drawn in (AUTH-T-8.1, AUTH-T-8.2)', () => {
  const html = fallbackForm(view(start()));

  it('has exactly one h1, the task, and the story under an h2', () => {
    expect(html.match(/<h1[\s>]/g)).toHaveLength(1);
    expect(html).toContain('>Sign in to Web App</h1>');
    expect(html).toMatch(/<aside aria-label="About D3 Auth" class="auth-entry__story">/);
    expect(html).toMatch(/<h2 class="auth-entry__headline">/);
    expect(html).toContain('<main class="auth-entry__main">');
  });

  it('draws the D3 Auth mark, decorative beside the name, its star lit by class', () => {
    expect(html).toContain('viewBox="0 0 64 64"');
    expect(html).toContain('d="M28.5 31.5 L25 45 L39 45 L35.5 31.5"');
    expect(html).toContain('class="auth-mark__star"');
    expect(html).not.toMatch(/#[0-9a-f]{6}/i);
    expect(html).toMatch(/aria-hidden="true">.*<\/svg> D3 Auth<\/div>/);
  });

  it('puts the trouble line under the form, past the hairline', () => {
    expect(html).toContain('<div class="auth-entry__notes"><p>Trouble signing in? Ask Matthew.</p></div>');
  });

  it('gives the long forms the wide column', () => {
    expect(setupForm()).toContain('auth-entry__column--wide');
    expect(inviteForm({ valid: true, email: 'guest@example.com', token: 'tok', operatorDisplayName: 'Matthew' })).toContain('auth-entry__column--wide');
    expect(html).not.toContain('auth-entry__column--wide');
  });

  it('keeps the first submit button on the page the form\'s own (the conformance suite presses it)', () => {
    const first = /<button[^>]*type="submit"[^>]*>([^<]*)<\/button>/.exec(html);
    expect(first?.[1]).toBe('Continue');
  });
});

describe('the break-glass page', () => {
  // The path somebody reaches *because* things are already wrong. A missing console build must
  // not be one more thing in the way, so it renders on its own rather than failing.
  const noConsoleBuild = '/nowhere/at/all';

  it('renders without a console build', () => {
    const html = renderRecoveryPage(noConsoleBuild, { ok: true, email: 'owner@example.com', expiresAt: new Date(0), factorsCleared: 1 }, 'Matthew');
    expect(html).toContain('<!doctype html>');
    expect(html).toContain('Recovery is ready');
    expect(html).toContain('owner@example.com');
  });

  it('says so when the link is spent', () => {
    const html = renderRecoveryPage(noConsoleBuild, { ok: false }, 'Matthew');
    expect(html).toContain('expired');
    expect(html).toContain('Matthew');
    expect(html).not.toContain('Recovery is ready');
  });
});
