import { describe, expect, it } from 'vitest';
import { renderSignedOut, renderSignOutQuestion } from '../../src/interaction/signout-pages.js';

// Signing out (REQ-010, I-8). The question's two answers do different things, so the words must
// say which is which; and the conformance suite clicks the autofocused button and waits for
// "You are signed out", so both of those are pinned here.

const FORM = '<form id="op.logoutForm" method="post" action="/oidc/session/end/confirm"><input type="hidden" name="xsrf" value="x"/></form>';
const NO_BUILD = '/nonexistent-console-dist';

describe('the sign-out question', () => {
  it('asked by nobody in particular: sign out of D3 Auth, or stay', () => {
    const html = renderSignOutQuestion(NO_BUILD, { form: FORM, person: { displayName: 'Dev Person', email: 'dev@example.com' } });
    expect(html).toContain('Sign out of D3 Auth?');
    expect(html).toContain('Signed in as <strong>Dev Person</strong> · dev@example.com');
    expect(html).toMatch(/<button[^>]*name="logout" value="yes" autofocus[^>]*>Sign out<\/button>/);
    // Staying is a link, not a post: posting without logout=yes would still end an app's sign-in.
    expect(html).toContain('href="/signin">Stay signed in</a>');
    expect(html).toContain(FORM);
  });

  it('asked by an app: everywhere, or only that app', () => {
    const html = renderSignOutQuestion(NO_BUILD, { form: FORM, appName: 'Immich' });
    expect(html).toContain('Sign out of Immich?');
    expect(html).toMatch(/<button[^>]*value="yes" autofocus[^>]*>Sign out everywhere<\/button>/);
    expect(html).toMatch(/<button[^>]*form="op.logoutForm" type="submit">Only sign out of Immich<\/button>/);
  });

  it('escapes what it is given', () => {
    const html = renderSignOutQuestion(NO_BUILD, { form: FORM, appName: '<img src=x>', person: { displayName: '"><script>', email: 'a@b.c' } });
    expect(html).not.toContain('<img src=x>');
    expect(html).not.toContain('"><script>');
  });
});

describe('after signing out', () => {
  it('everything: says so, with a way back in', () => {
    const html = renderSignedOut(NO_BUILD);
    expect(html).toContain('You are signed out');
    expect(html).toContain('href="/signin">Sign in again</a>');
  });

  it('only one app: says the D3 Auth sign-in carries on', () => {
    const html = renderSignedOut(NO_BUILD, { onlyApp: 'Immich' });
    expect(html).toContain('Signed out of Immich');
    expect(html).toContain('still signed in to D3 Auth');
    expect(html).not.toContain('You are signed out');
  });
});
