import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { actions, authPage, button, card, escape, field, form, hidden, section } from './auth-markup.js';
import type { LoginFlow } from './flow-store.js';

// A working sign-in form in the HTML itself, inside the console's shell.
//
// The console's React screens take over the moment they load, but the markup that arrives is a
// real form with a real action. That keeps sign-in working with JavaScript off or still loading,
// keeps it usable by very simple browsers (the OpenID conformance suite drives one), and means
// the slowest connection still gets a usable page. It is drawn in the design system's classes
// (auth-markup.ts), so it looks like the screen that replaces it.

export interface FallbackView {
  uid: string;
  flow: LoginFlow;
  clientName: string;
  operatorDisplayName: string;
}

export function fallbackForm(view: FallbackView): string {
  const action = `/api/interaction/${encodeURIComponent(view.uid)}`;
  const csrf = hidden('csrf', view.flow.csrf);
  const state = view.flow.state;
  const email = view.flow.attemptedEmail ?? '';
  const title = `Sign in to ${view.clientName}`;
  const footer = `Trouble signing in? Ask ${escape(view.operatorDisplayName)}.`;

  // Each step is its own small form, because each posts to its own endpoint. The passkey has no
  // no-JavaScript form at all: the ceremony *is* JavaScript, so that step offers the code instead.
  switch (state.name) {
    case 'awaiting_identifier':
      return authPage({
        title,
        footer,
        body: card(
          form(
            `${action}/identify`,
            csrf +
              field({
                id: 'email',
                label: 'Email',
                type: 'email',
                help: 'The address you were invited with.',
                attributes: 'autocomplete="username" inputmode="email" autofocus',
              }) +
              actions(button('Continue', 'primary')),
            'Sign in',
          ),
        ),
      });
    case 'awaiting_factor':
      return authPage({
        title,
        description: 'One more step: confirm it is you.',
        footer,
        body: card(
          form(
            `${action}/totp`,
            csrf +
              field({
                id: 'code',
                label: 'Code from your authenticator app',
                help: 'Six digits, from the app you set up.',
                attributes: 'inputmode="numeric" autocomplete="one-time-code" autofocus',
              }) +
              actions(button('Verify code', 'primary')),
            'Confirm it is you',
          ),
        ),
      });
    case 'awaiting_trusted_device':
      return authPage({
        title,
        footer,
        body: section(
          'trust-title',
          'Skip this step on this browser?',
          'We will not ask for your passkey or code here for the next 30 days. Use this only on a browser that is yours.',
          form(
            `${action}/trust`,
            csrf +
              actions(
                button('Yes, remember this browser', 'primary', 'type="submit" name="trust" value="true"'),
                button('Not this time', 'ghost', 'type="submit" name="trust" value="false"'),
              ),
            'Skip this step on this browser?',
          ),
        ),
      });
    default:
      return authPage({
        title,
        description: `Signing in as <strong>${escape(email)}</strong>`,
        footer,
        body: card(
          form(
            `${action}/password`,
            csrf +
              field({ id: 'password', label: 'Password', type: 'password', attributes: 'autocomplete="current-password" autofocus' }) +
              actions(button('Sign in', 'primary')),
            'Sign in',
          ),
        ),
      });
  }
}

/**
 * *Continue to {app} as {username}* (REQ-059). Shown once per app, on the first sign-in to it.
 *
 * It is not a consent screen — there is nothing to agree to, and no scopes to argue about
 * (REQ-060). It exists because somebody arriving at a new app from a shared or long-lived
 * session deserves to be told which account is about to be used, and offered a way out.
 */
export function renderContinueAsPage(
  consoleDist: string,
  view: { uid: string; csrf: string; clientName: string; username: string; displayName: string; operatorDisplayName: string },
): string {
  const action = `/api/interaction/${encodeURIComponent(view.uid)}`;
  const who = view.username || view.displayName;
  const csrf = hidden('csrf', view.csrf);
  // Two answers, two endpoints, so two forms: the way out is drawn as the stack's leading action.
  return intoShell(
    consoleDist,
    authPage({
      title: `Continue to ${view.clientName}`,
      description: `You are signed in as <strong>${escape(who)}</strong>.`,
      footer: `Trouble signing in? Ask ${escape(view.operatorDisplayName)}.`,
      body: card(
        '<div class="d3-stack d3-gap-16 d3-align-stretch">' +
          form(`${action}/continue`, csrf + actions(button(`Continue as ${who}`, 'primary')), `Continue as ${who}`) +
          form(`${action}/switch`, csrf + actions(button('Not you? Sign in as someone else', 'ghost')), 'Sign in as someone else') +
          '</div>',
      ),
    }),
  );
}

/**
 * The page the break-glass link lands on (REQ-122). Server-rendered, because it must work on a
 * browser the owner has never used, and it says what just happened rather than signing anybody in.
 */
export function renderRecoveryPage(
  consoleDist: string,
  claimed: { ok: boolean; email?: string; expiresAt?: Date; factorsCleared?: number },
  operatorDisplayName: string,
): string {
  const until = escape(claimed.expiresAt?.toUTCString() ?? 'the window closes');
  const factors = claimed.factorsCleared
    ? `The ${String(claimed.factorsCleared)} factor(s) on the account were removed, so set up a new one as soon as you are in.`
    : 'Set up a passkey or an authenticator app as soon as you are in.';

  const page = claimed.ok
    ? authPage({
        title: 'Recovery is ready',
        description: `Sign in as <strong>${escape(claimed.email ?? '')}</strong> with your password.`,
        body: card(`<div class="d3-stack d3-gap-16 d3-align-stretch"><p>You will not be asked for a passkey or a code until ${until}.</p><p>${factors}</p></div>`),
        footer: 'Go back to the app you were signing in to and sign in as usual.',
      })
    : authPage({
        title: 'This recovery link has expired',
        description: `Recovery links work once, and only for a few minutes. Ask ${escape(operatorDisplayName)} for another from the host.`,
      });

  return intoShell(consoleDist, page);
}

/**
 * Wraps server-rendered markup in the console's built shell, which carries the stylesheet.
 *
 * When there is no console build the markup is served on its own rather than failing. It matters
 * most for the page this was written for: break-glass is the path somebody reaches *because*
 * things are already wrong, and "the assets are missing" must not be one more thing in the way.
 * Unstyled and readable beats a 500.
 */
export function intoShell(consoleDist: string, markup: string): string {
  try {
    const shell = readFileSync(join(consoleDist, 'index.html'), 'utf8');
    return shell.replace('<div id="root"></div>', `<div id="root">${markup}</div>`);
  } catch {
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>D3 Auth</title></head><body><div id="root">${markup}</div></body></html>`;
  }
}

/** Injects the form into the console's built index.html, which carries the CSS and the app. */
export function renderLoginPage(consoleDist: string, view: FallbackView): string {
  return intoShell(consoleDist, fallbackForm(view));
}
