// The server-rendered single-task pages — sign-in with JavaScript off, setup, an invite, the
// continue-as interstitial, sign-out, break-glass — in the entry shell (AUTH-T-8.2).
//
// The console's React screens (apps/console/src/login/LoginLayout.tsx) are EntryShell → the story
// panel and a form column. This emits the same elements with the same class names, so the page that
// arrives in the HTML is already styled by the stylesheet the console shell links, and nothing moves
// when React takes over. It carries no styles of its own and no style attributes (the CSP allows
// none). Two tests hold it to that: test/unit/fallback.test.ts checks every class used here exists
// in a stylesheet the console ships, and apps/console/test/entry-parity.test.tsx renders the React
// shell and compares it with this markup, character for character.

export const escape = (value: string): string => value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

// The story panel's words. The console's copy lives in apps/console/src/entry/story.ts; the parity
// test fails if these drift from it.
const PRODUCT = 'D3 Auth';
const HEADLINE = 'One account\u00a0—';
const HEADLINE_ACCENT = 'for every app that uses it.';
const PROMISE = 'Sign in here once, rather than in every app. Each app is told only the roles you were granted for it.';
const CLAIMS: readonly { title: string; detail: string }[] = [
  { title: 'Admins hold a second factor.', detail: 'Nobody is made an admin without a passkey or a code.' },
  { title: 'Apps are refused until granted.', detail: 'Access is per app, and denied by default.' },
  { title: 'Tested against the OpenID conformance suite.', detail: 'On every change, in CI.' },
];
const FOOT = 'self-hosted';

/**
 * The D3 Auth mark (AUTH-T-8.1): d3cloud.io's "Keyhole", the same drawing as
 * apps/console/src/brand/D3AuthMark.tsx, decorative. The lit star takes its colour from the
 * `auth-mark__star` class, never a style attribute.
 */
export function mark(size: number): string {
  const [line, joint, star] = size >= 72 ? [2.2, 2.6, 4.4] : [3.5, 3.4, 5.5];
  const ink = `stroke="currentColor" stroke-width="${String(line)}" stroke-linecap="round" stroke-linejoin="round"`;
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${String(size)}" height="${String(size)}" viewBox="0 0 64 64" fill="none" class="auth-mark" aria-hidden="true">` +
    `<circle cx="32" cy="32" r="26" ${ink}></circle>` +
    `<circle cx="32" cy="25" r="7.5" ${ink}></circle>` +
    `<path d="M28.5 31.5 L25 45 L39 45 L35.5 31.5" ${ink}></path>` +
    `<circle cx="25" cy="45" r="${String(joint)}" fill="currentColor"></circle>` +
    `<circle cx="39" cy="45" r="${String(joint)}" fill="currentColor"></circle>` +
    `<circle cx="32" cy="25" r="${String(star)}" fill="currentColor" class="auth-mark__star"></circle>` +
    `</svg>`
  );
}

const TICK =
  '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true" focusable="false" class="auth-entry__tick">' +
  '<path d="M3.5 8.5l3 3 6-7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"></path></svg>';

/** The story at the left of every entry screen, from 1024px: what D3 Auth is, and three claims. */
export function storyPanel(): string {
  const claims = CLAIMS.map(
    (claim) =>
      `<li class="auth-entry__claim">${TICK}<span><span class="auth-entry__claim-title">${escape(claim.title)}</span> ${escape(claim.detail)}</span></li>`,
  ).join('');
  return (
    `<aside aria-label="About ${PRODUCT}" class="auth-entry__story">` +
    `<div class="auth-entry__brand">${mark(28)} ${PRODUCT}</div>` +
    `<div class="auth-entry__pitch"><h2 class="auth-entry__headline">${escape(HEADLINE)} <span class="auth-entry__headline-accent">${escape(HEADLINE_ACCENT)}</span></h2>` +
    `<p class="auth-entry__promise">${escape(PROMISE)}</p><ul class="auth-entry__claims">${claims}</ul></div>` +
    `<footer class="auth-entry__foot"><span>${FOOT}</span></footer></aside>`
  );
}

export interface AuthPage {
  /** Plain text; escaped here. */
  title: string;
  /** Markup; the caller escapes what goes in it. */
  description?: string;
  /** Markup: usually one `form(...)`. */
  body?: string;
  /** Markup: a short line under the form, past a hairline. */
  footer?: string;
  /** A long form (setup, an invite): the wider column. */
  wide?: boolean;
}

/** `LoginLayout`: the story, then the form column — the mark, the page's one h1, the task, the note. */
export function authPage({ title, description, body, footer, wide = false }: AuthPage): string {
  return (
    `<div class="auth-entry">${storyPanel()}<main class="auth-entry__main">` +
    `<div class="${wide ? 'auth-entry__column auth-entry__column--wide' : 'auth-entry__column'}">` +
    `<div class="auth-entry__brand auth-entry__brand--compact">${mark(28)} ${PRODUCT}</div>` +
    `<header class="auth-entry__heading"><h1 tabindex="-1" class="auth-entry__title">${escape(title)}</h1>${
      description ? `<p class="auth-entry__lede">${description}</p>` : ''
    }</header>` +
    (body ? `<div class="auth-entry__body">${body}</div>` : '') +
    (footer ? `<div class="auth-entry__notes"><p>${footer}</p></div>` : '') +
    `</div></main></div>`
  );
}

/** `Stack as="form" gap="16"`, posting to its own endpoint. */
export const form = (action: string, inner: string, label: string): string =>
  `<form class="d3-stack d3-gap-16 d3-align-stretch" method="post" action="${escape(action)}" aria-label="${escape(label)}">${inner}</form>`;

export const hidden = (name: string, value: string): string => `<input type="hidden" name="${escape(name)}" value="${escape(value)}">`;

export interface FieldOptions {
  id: string;
  label: string;
  type?: string;
  help?: string;
  /** Extra attributes, written as-is: `autocomplete="username" autofocus`. Never from a request. */
  attributes?: string;
}

/** `FormField` around an `Input`: the label bound to the control, the help bound by aria-describedby. */
export function field({ id, label, type = 'text', help, attributes = '' }: FieldOptions): string {
  const helpId = `${id}-help`;
  return `<div class="d3-ff"><label class="d3-lb" for="${escape(id)}">${escape(label)}</label><div class="d3-inp d3-inp--md"><input class="d3-inp__control" id="${escape(
    id,
  )}" name="${escape(id)}" type="${escape(type)}" required${help ? ` aria-describedby="${helpId}"` : ''} ${attributes}></div>${
    help ? `<div class="d3-ff__help" id="${helpId}">${escape(help)}</div>` : ''
  }</div>`;
}

/** `Button`, large when it is the primary. `attributes` is written as-is and never comes from a request. */
export const button = (label: string, variant: 'primary' | 'ghost', attributes = 'type="submit"'): string =>
  `<button class="d3-btn d3-btn--${variant} ${buttonSize(variant)}" ${attributes}>${escape(label)}</button>`;

/** The entry screens' primary is `size="lg"`; the way round it stays the default. */
export const buttonSize = (variant: 'primary' | 'ghost'): string => (variant === 'primary' ? 'd3-btn--lg' : 'd3-btn--md');

/** `FormActions layout="stack"`: the primary full width on top, the way round it beneath. */
export const actions = (primary: string, leading?: string): string =>
  `<div class="d3-fa d3-fa--end d3-fa--stack">${leading ? `<div class="d3-fa__leading">${leading}</div>` : ''}<div class="d3-fa__main">${primary}</div></div>`;

/** `Section surface="plain"`: a titled question with its answer inside. */
export const section = (id: string, title: string, description: string, inner: string): string =>
  `<section class="d3-sec" aria-labelledby="${escape(id)}"><div class="d3-sec__head"><div class="d3-sec__lead"><h2 id="${escape(
    id,
  )}" class="d3-sec__title">${escape(title)}</h2><div class="d3-sec__desc">${escape(description)}</div></div></div><div class="d3-sec__body">${inner}</div></section>`;
