import { describe, expect, it } from 'vitest';
import { fallbackForm, renderRecoveryPage } from '../../src/interaction/fallback.js';
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
