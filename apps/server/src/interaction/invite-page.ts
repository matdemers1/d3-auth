import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// The invite wizard's first paint, rendered server-side into the console shell (I-6).

const escape = (value: string): string => value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

export interface InvitePageView {
  valid: boolean;
  email?: string | undefined;
  token: string;
  operatorDisplayName: string;
}

export function inviteForm(view: InvitePageView): string {
  if (!view.valid) {
    return `<main class="shell shell--narrow">
      <h1 class="signin-title">This invite has expired</h1>
      <p class="signin-identity">Invites last a few days and can be used once. Ask ${escape(view.operatorDisplayName)} for a new one.</p>
    </main>`;
  }

  return `<main class="shell shell--narrow">
    <h1 class="signin-title">Create your account</h1>
    <p class="signin-identity">Signing up as <strong>${escape(view.email ?? '')}</strong></p>
    <form class="signin-form signin-form--fallback" method="post" action="/api/invite/${encodeURIComponent(view.token)}/accept">
      <label class="signin-label" for="displayName">Your name</label>
      <input class="signin-input" id="displayName" name="displayName" type="text" autocomplete="name" required autofocus>
      <label class="signin-label" for="username">Username</label>
      <input class="signin-input" id="username" name="username" type="text" autocomplete="username" required>
      <p class="signin-footnote">How you appear to apps. Letters, numbers, dot, dash or underscore.</p>
      <label class="signin-label" for="password">Password</label>
      <input class="signin-input" id="password" name="password" type="password" autocomplete="new-password" required>
      <p class="signin-footnote">At least 12 characters. A few words you can remember beats a short scramble.</p>
      <button class="signin-button" type="submit">Create my account</button>
    </form>
  </main>`;
}

export function renderInvitePage(consoleDist: string, view: InvitePageView): string {
  const shell = readFileSync(join(consoleDist, 'index.html'), 'utf8');
  return shell.replace('<div id="root"></div>', `<div id="root">${inviteForm(view)}</div>`);
}
