import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Like the sign-in screen, the setup form arrives as real HTML inside the console shell, so it
// works before the JavaScript does (and in a browser that never runs any).

const escape = (value: string): string => value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

const field = (id: string, label: string, type: string, hint?: string, extra = ''): string =>
  `<label class="signin-label" for="${id}">${escape(label)}</label>
   <input class="signin-input" id="${id}" name="${id}" type="${type}" required ${extra}>
   ${hint ? `<p class="signin-footnote">${escape(hint)}</p>` : ''}`;

export function setupForm(): string {
  return `<main class="shell shell--narrow">
    <h1 class="signin-title">Set up D3 Auth</h1>
    <p class="signin-identity">This instance has no accounts yet. Create the owner account to finish setting it up.</p>
    <form class="signin-form signin-form--fallback" method="post" action="/api/setup">
      ${field('code', 'Setup code', 'text', 'Printed in the server log when the service started: docker compose logs server.', 'autofocus autocomplete="off" spellcheck="false"')}
      ${field('email', 'Your email', 'email', undefined, 'autocomplete="email"')}
      ${field('username', 'Username', 'text', 'How you appear to apps. Letters, numbers, dot, dash or underscore.', 'autocomplete="username"')}
      ${field('displayName', 'Display name', 'text', undefined, 'autocomplete="name"')}
      ${field('password', 'Password', 'password', 'At least 12 characters. A few words you can remember beats a short scramble.', 'autocomplete="new-password"')}
      <button class="signin-button" type="submit">Create the owner account</button>
    </form>
  </main>`;
}

export function setupFinishedPage(): string {
  return `<main class="shell shell--narrow">
    <h1 class="signin-title">Setup is finished</h1>
    <p class="signin-identity">This instance already has an account. Sign in from the app you want to use.</p>
  </main>`;
}

export function renderSetupPage(consoleDist: string, options: { available: boolean }): string {
  const shell = readFileSync(join(consoleDist, 'index.html'), 'utf8');
  return shell.replace('<div id="root"></div>', `<div id="root">${options.available ? setupForm() : setupFinishedPage()}</div>`);
}
