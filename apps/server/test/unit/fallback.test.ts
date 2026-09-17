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
  // The no-JavaScript pages carry no styles of their own: they borrow the design system's. A class
  // renamed in a release would leave them unstyled with nothing failing, so every class they use
  // has to exist in the stylesheet the console actually ships.
  const css = readFileSync(new URL('../../../console/node_modules/@d3cloud/ui/dist/index.css', import.meta.url), 'utf8');
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

  it('uses only d3- classes', () => {
    expect([...used].filter((name) => !name.startsWith('d3-'))).toEqual([]);
  });

  // Modifiers the components emit for their default, which the stylesheet has no rule for. Written
  // anyway so the markup matches what Card and Section render.
  const unstyledDefaults = new Set(['d3-crd--md', 'd3-sec--card']);

  it.each([...used].filter((name) => !unstyledDefaults.has(name)))('%s exists in @d3cloud/ui', (name) => {
    expect(css).toMatch(new RegExp(`\\.${name.replace(/[-_]/g, (c) => `\\${c}`)}(?![\\w-])`));
  });

  it('labels every field it draws', () => {
    for (const html of pages) {
      for (const match of html.matchAll(/<input class="d3-inp__control" id="([^"]+)"/g)) {
        expect(html).toContain(`for="${match[1] ?? ''}"`);
      }
    }
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
