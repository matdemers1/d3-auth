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

/** Injects the form into the console's built index.html, which carries the CSS and the app. */
export function renderLoginPage(consoleDist: string, view: FallbackView): string {
  const shell = readFileSync(join(consoleDist, 'index.html'), 'utf8');
  return shell.replace('<div id="root"></div>', `<div id="root">${fallbackForm(view)}</div>`);
}
