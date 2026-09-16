import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { LoginFlow } from './flow-store.js';

// A working sign-in form in the HTML itself, inside the console's shell.
//
// The console's React screens take over the moment they load, but the markup that arrives is a
// real form with a real action. That keeps sign-in working with JavaScript off or still loading,
// keeps it usable by very simple browsers (the OpenID conformance suite drives one), and means
// the slowest connection still gets a usable page.

export interface FallbackView {
  uid: string;
  flow: LoginFlow;
  clientName: string;
  operatorDisplayName: string;
}

const escape = (value: string): string => value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

export function fallbackForm(view: FallbackView): string {
  const action = `/api/interaction/${encodeURIComponent(view.uid)}`;
  const csrf = `<input type="hidden" name="csrf" value="${escape(view.flow.csrf)}">`;
  const state = view.flow.state;
  const email = view.flow.attemptedEmail ?? '';
  const signingInAs = `<p class="signin-identity">Signing in as <strong>${escape(email)}</strong></p>`;

  // Each step is its own small form, because each posts to its own endpoint. The passkey has no
  // no-JavaScript form at all: the ceremony *is* JavaScript, so that step offers the code instead.
  const form = (endpoint: string, inner: string): string =>
    `<form class="signin-form signin-form--fallback" method="post" action="${action}/${endpoint}">${csrf}${inner}</form>`;

  let body: string;
  switch (state.name) {
    case 'awaiting_identifier':
      body = form(
        'identify',
        `<label class="signin-label" for="email">Email</label>
      <input class="signin-input" id="email" name="email" type="email" autocomplete="username" inputmode="email" required autofocus>
      <p class="signin-footnote">The address you were invited with.</p>
      <button class="signin-button" type="submit">Continue</button>`,
      );
      break;
    case 'awaiting_factor':
      body = form(
        'totp',
        `${signingInAs}
      <label class="signin-label" for="code">Code from your authenticator app</label>
      <input class="signin-input" id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" required autofocus>
      <button class="signin-button" type="submit">Confirm</button>`,
      );
      break;
    case 'awaiting_trusted_device':
      body = form(
        'trust',
        `<p class="signin-identity">Skip this step on this browser for the next 30 days?</p>
      <button class="signin-button" type="submit" name="trust" value="true">Yes, remember this browser</button>
      <button class="signin-button signin-button--quiet" type="submit" name="trust" value="false">Not this time</button>`,
      );
      break;
    default:
      body = form(
        'password',
        `${signingInAs}
      <label class="signin-label" for="password">Password</label>
      <input class="signin-input" id="password" name="password" type="password" autocomplete="current-password" required autofocus>
      <button class="signin-button" type="submit">Sign in</button>`,
      );
  }

  return `<main class="shell shell--narrow">
    <h1 class="signin-title">Sign in to ${escape(view.clientName)}</h1>
    ${body}
    <p class="signin-footnote">Trouble signing in? Ask ${escape(view.operatorDisplayName)}.</p>
  </main>`;
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
  return intoShell(
    consoleDist,
    `<main class="shell shell--narrow">
      <h1 class="signin-title">Continue to ${escape(view.clientName)}</h1>
      <p class="signin-identity">You are signed in as <strong>${escape(who)}</strong>.</p>
      <form class="signin-form signin-form--fallback" method="post" action="${action}/continue">
        <input type="hidden" name="csrf" value="${escape(view.csrf)}">
        <button class="signin-button" type="submit">Continue as ${escape(who)}</button>
      </form>
      <form class="signin-form signin-form--fallback" method="post" action="${action}/switch">
        <input type="hidden" name="csrf" value="${escape(view.csrf)}">
        <button class="signin-button signin-button--quiet" type="submit">Not you? Sign in as someone else</button>
      </form>
      <p class="signin-footnote">Trouble signing in? Ask ${escape(view.operatorDisplayName)}.</p>
    </main>`,
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
  const body = claimed.ok
    ? `<h1 class="signin-title">Recovery is ready</h1>
      <p class="signin-identity">Sign in as <strong>${escape(claimed.email ?? '')}</strong> with your password.</p>
      <p class="signin-footnote">
        You will not be asked for a passkey or a code until ${escape(claimed.expiresAt?.toUTCString() ?? 'the window closes')}.
        ${claimed.factorsCleared ? `The ${String(claimed.factorsCleared)} factor(s) on the account were removed, so set up a new one as soon as you are in.` : 'Set up a passkey or an authenticator app as soon as you are in.'}
      </p>
      <p class="signin-footnote">Go back to the app you were signing in to and sign in as usual.</p>`
    : `<h1 class="signin-title">This recovery link has expired</h1>
      <p class="signin-footnote">
        Recovery links work once, and only for a few minutes. Ask ${escape(operatorDisplayName)} for another from the host.
      </p>`;

  return intoShell(consoleDist, `<main class="shell shell--narrow">${body}</main>`);
}

/**
 * Wraps server-rendered markup in the console's built shell, which carries the stylesheet.
 *
 * When there is no console build the markup is served on its own rather than failing. It matters
 * most for the page this was written for: break-glass is the path somebody reaches *because*
 * things are already wrong, and "the assets are missing" must not be one more thing in the way.
 * Unstyled and readable beats a 500.
 */
function intoShell(consoleDist: string, markup: string): string {
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
