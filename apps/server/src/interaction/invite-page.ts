import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { actions, authPage, button, card, escape, field, form } from './auth-markup.js';

// The invite wizard's first paint, rendered server-side into the console shell (I-6).

export interface InvitePageView {
  valid: boolean;
  email?: string | undefined;
  token: string;
  operatorDisplayName: string;
}

export function inviteForm(view: InvitePageView): string {
  if (!view.valid) {
    return authPage({
      title: 'This invite has expired',
      description: `Invites last a few days and can be used once. Ask ${escape(view.operatorDisplayName)} for a new one.`,
    });
  }

  return authPage({
    title: 'Create your account',
    description: `Signing up as <strong>${escape(view.email ?? '')}</strong>`,
    body: card(
      form(
        `/api/invite/${encodeURIComponent(view.token)}/accept`,
        field({ id: 'displayName', label: 'Your name', attributes: 'autocomplete="name" autofocus' }) +
          field({
            id: 'username',
            label: 'Username',
            help: 'How you appear to apps. Letters, numbers, dot, dash or underscore.',
            attributes: 'autocomplete="username"',
          }) +
          field({
            id: 'password',
            label: 'Password',
            type: 'password',
            help: 'At least 12 characters. A few words you can remember beats a short scramble.',
            attributes: 'autocomplete="new-password"',
          }) +
          actions(button('Create my account', 'primary')),
        'Create your account',
      ),
    ),
  });
}

export function renderInvitePage(consoleDist: string, view: InvitePageView): string {
  const shell = readFileSync(join(consoleDist, 'index.html'), 'utf8');
  return shell.replace('<div id="root"></div>', `<div id="root">${inviteForm(view)}</div>`);
}
