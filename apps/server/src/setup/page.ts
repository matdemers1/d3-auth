import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { actions, authPage, button, card, field, form } from '../interaction/auth-markup.js';

// Like the sign-in screen, the setup form arrives as real HTML inside the console shell, so it
// works before the JavaScript does (and in a browser that never runs any).

export function setupForm(): string {
  return authPage({
    title: 'Set up D3 Auth',
    description: 'This instance has no accounts yet. Create the owner account to finish setting it up.',
    body: card(
      form(
        '/api/setup',
        field({
          id: 'code',
          label: 'Setup code',
          help: 'Printed in the server log when the service started: docker compose logs server.',
          attributes: 'autofocus autocomplete="off" spellcheck="false"',
        }) +
          field({ id: 'email', label: 'Your email', type: 'email', attributes: 'autocomplete="email"' }) +
          field({
            id: 'username',
            label: 'Username',
            help: 'How you appear to apps. Letters, numbers, dot, dash or underscore.',
            attributes: 'autocomplete="username"',
          }) +
          field({ id: 'displayName', label: 'Display name', attributes: 'autocomplete="name"' }) +
          field({
            id: 'password',
            label: 'Password',
            type: 'password',
            help: 'At least 12 characters. A few words you can remember beats a short scramble.',
            attributes: 'autocomplete="new-password"',
          }) +
          actions(button('Create the owner account', 'primary')),
        'Set up D3 Auth',
      ),
    ),
  });
}

export function setupFinishedPage(): string {
  return authPage({
    title: 'Setup is finished',
    description: 'This instance already has an account. Sign in from the app you want to use.',
  });
}

export function renderSetupPage(consoleDist: string, options: { available: boolean }): string {
  const shell = readFileSync(join(consoleDist, 'index.html'), 'utf8');
  return shell.replace('<div id="root"></div>', `<div id="root">${options.available ? setupForm() : setupFinishedPage()}</div>`);
}
