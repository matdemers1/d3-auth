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
  const onPassword = view.flow.state.name !== 'awaiting_identifier';
  const email = view.flow.attemptedEmail ?? '';

  const field = onPassword
    ? `<p class="signin-identity">Signing in as <strong>${escape(email)}</strong></p>
      <label class="signin-label" for="password">Password</label>
      <input class="signin-input" id="password" name="password" type="password" autocomplete="current-password" required autofocus>`
    : `<label class="signin-label" for="email">Email</label>
      <input class="signin-input" id="email" name="email" type="email" autocomplete="username" inputmode="email" required autofocus>
      <p class="signin-footnote">The address you were invited with.</p>`;

  return `<main class="shell shell--narrow">
    <h1 class="signin-title">Sign in to ${escape(view.clientName)}</h1>
    <form class="signin-form signin-form--fallback" method="post" action="${action}/${onPassword ? 'password' : 'identify'}">
      <input type="hidden" name="csrf" value="${escape(view.flow.csrf)}">
      ${field}
      <button class="signin-button" type="submit">${onPassword ? 'Sign in' : 'Continue'}</button>
    </form>
    <p class="signin-footnote">Trouble signing in? Ask ${escape(view.operatorDisplayName)}.</p>
  </main>`;
}

/** Injects the form into the console's built index.html, which carries the CSS and the app. */
export function renderLoginPage(consoleDist: string, view: FallbackView): string {
  const shell = readFileSync(join(consoleDist, 'index.html'), 'utf8');
  return shell.replace('<div id="root"></div>', `<div id="root">${fallbackForm(view)}</div>`);
}
