import { actions, authPage, button, card, escape } from './auth-markup.js';
import { intoShell } from './fallback.js';

// Signing out (REQ-010, I-8), drawn like every other single-task page: AuthLayout, one Card, the
// actions stacked. Server-rendered, so the answer to "am I signed out?" never waits on JavaScript.
//
// The provider's question has two answers, and they are not "yes" and "no". Posting with
// `logout=yes` ends the whole D3 Auth session and every app it was used for. Posting without it
// ends only the app that asked — its grant is revoked and its authorization removed — and leaves the
// D3 Auth session alive. The old buttons said "Yes, sign me out" and "No, stay signed in", and the
// second one signed you out of the app anyway. These say what each one does.

/** A link drawn as a `Button`, for a way out that is not a form post. */
export const linkButton = (label: string, href: string, variant: 'primary' | 'ghost'): string =>
  `<a class="d3-btn d3-btn--${variant} d3-btn--md" href="${escape(href)}">${escape(label)}</a>`;

export interface SignOutQuestion {
  /** The provider's form: `<form id="op.logoutForm">` with its xsrf field. Markup, as the provider gives it. */
  form: string;
  /** Who is signed in, when the session names somebody we can find. */
  person?: { displayName: string; email: string } | undefined;
  /** The app that asked, when it is a registered app rather than the console itself. */
  appName?: string | undefined;
}

export function renderSignOutQuestion(consoleDist: string, view: SignOutQuestion): string {
  const who = view.person
    ? `Signed in as <strong>${escape(view.person.displayName)}</strong> · ${escape(view.person.email)}`
    : undefined;
  const everywhere = 'form="op.logoutForm" type="submit" name="logout" value="yes" autofocus';

  const body = view.appName
    ? card(
        `<div class="d3-stack d3-gap-16 d3-align-stretch"><p>${escape(view.appName)} asked to sign you out. You can leave it there, or end your D3 Auth sign-in as well, which signs you out of every app you used it for.</p>` +
          actions(button('Sign out everywhere', 'primary', everywhere), button(`Only sign out of ${view.appName}`, 'ghost', 'form="op.logoutForm" type="submit"')) +
          `</div>${view.form}`,
      )
    : card(
        `<div class="d3-stack d3-gap-16 d3-align-stretch"><p>This signs you out of D3 Auth and every app you signed in to with it.</p>` +
          actions(button('Sign out', 'primary', everywhere), linkButton('Stay signed in', '/signin', 'ghost')) +
          `</div>${view.form}`,
      );

  return intoShell(
    consoleDist,
    authPage({
      title: view.appName ? `Sign out of ${view.appName}?` : 'Sign out of D3 Auth?',
      ...(who ? { description: who } : {}),
      body,
    }),
  );
}

export interface SignedOut {
  /** Set when only this app was signed out and the D3 Auth session carries on. */
  onlyApp?: string | undefined;
}

export function renderSignedOut(consoleDist: string, view: SignedOut = {}): string {
  const page = view.onlyApp
    ? authPage({
        title: `Signed out of ${view.onlyApp}`,
        description: 'You are still signed in to D3 Auth, so your other apps keep working.',
        body: card(`<div class="d3-stack d3-gap-16 d3-align-stretch">${actions(linkButton('Go to your account', '/signin', 'primary'))}</div>`),
      })
    : authPage({
        // The conformance suite's logout plans wait for this exact text.
        title: 'You are signed out',
        description: 'Signed out of D3 Auth and every app you used it for.',
        body: card(`<div class="d3-stack d3-gap-16 d3-align-stretch">${actions(linkButton('Sign in again', '/signin', 'primary'))}</div>`),
        footer: 'You can close this tab.',
      });
  return intoShell(consoleDist, page);
}
