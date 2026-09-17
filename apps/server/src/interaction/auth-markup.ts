// The server-rendered single-task pages — sign-in with JavaScript off, setup, an invite, the
// continue-as interstitial, break-glass — written in the design system's own classes.
//
// The console's React screens (apps/console/src/login/LoginLayout.tsx) are AuthLayout → Card → a
// form → FormActions stacked. This emits the same elements with the same class names, so the page
// that arrives in the HTML is already styled by the stylesheet the console shell links, and nothing
// moves when React takes over. It carries no styles of its own. test/unit/fallback.test.ts checks
// every class used here exists in @d3cloud/ui's stylesheet, so a renamed class fails a test rather
// than quietly unstyling the path somebody reaches because their JavaScript did not load.

export const escape = (value: string): string => value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

/** Lucide's shield-half at 32px: the same mark LoginLayout renders, decorative. */
const MARK =
  '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>' +
  '<path d="M12 22V2"/></svg>';

export interface AuthPage {
  /** Plain text; escaped here. */
  title: string;
  /** Markup; the caller escapes what goes in it. */
  description?: string;
  /** Markup: usually one `card(...)`. */
  body?: string;
  /** Markup. */
  footer?: string;
}

/** `AuthLayout`: the mark, the page's one h1, the task, the footnote. */
export function authPage({ title, description, body, footer }: AuthPage): string {
  return `<main class="d3-auth">
  <div class="d3-auth__brand">${MARK}</div>
  <div class="d3-ph"><div class="d3-ph__lead"><h1 class="d3-ph__title" tabindex="-1">${escape(title)}</h1>${
    description ? `<div class="d3-ph__desc">${description}</div>` : ''
  }</div></div>
  ${body ? `<div class="d3-auth__body">${body}</div>` : ''}
  ${footer ? `<div class="d3-auth__footer">${footer}</div>` : ''}
</main>`;
}

/** `Card`. */
export const card = (inner: string): string => `<div class="d3-crd d3-crd--md">${inner}</div>`;

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

/** `Button`. `attributes` is written as-is and never comes from a request. */
export const button = (label: string, variant: 'primary' | 'ghost', attributes = 'type="submit"'): string =>
  `<button class="d3-btn d3-btn--${variant} d3-btn--md" ${attributes}>${escape(label)}</button>`;

/** `FormActions layout="stack"`: the primary full width on top, the way round it beneath. */
export const actions = (primary: string, leading?: string): string =>
  `<div class="d3-fa d3-fa--end d3-fa--stack">${leading ? `<div class="d3-fa__leading">${leading}</div>` : ''}<div class="d3-fa__main">${primary}</div></div>`;

/** `Section` on a card: a titled question with its answer inside. */
export const section = (id: string, title: string, description: string, inner: string): string =>
  `<section class="d3-crd d3-crd--md d3-sec d3-sec--card" aria-labelledby="${escape(id)}"><div class="d3-sec__head"><div class="d3-sec__lead"><h2 id="${escape(
    id,
  )}" class="d3-sec__title">${escape(title)}</h2><div class="d3-sec__desc">${escape(description)}</div></div></div><div class="d3-sec__body">${inner}</div></section>`;
