import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { authPage, mark, storyPanel } from '../../server/src/interaction/auth-markup';
import { D3AuthMark } from '../src/brand/D3AuthMark';
import { ENTRY_CLAIMS, ENTRY_HEADLINE, ENTRY_HEADLINE_ACCENT, ENTRY_PROMISE } from '../src/entry/story';
import { LoginLayout, troubleFooter } from '../src/login/LoginLayout';

// AUTH-T-8.1, AUTH-T-8.2: the sign-in page arrives as HTML the server wrote
// (apps/server/src/interaction/auth-markup.ts) and React replaces it when the login chunk loads. If
// the two frames differ by so much as an element, something on the page moves under somebody who
// is typing. So they are compared here character for character, not described twice and hoped equal.

const html = (node: React.ReactElement): string => renderToStaticMarkup(node);

describe('the entry shell, drawn by React and by the server', () => {
  it('is the same frame with a title, a lede and the trouble line', () => {
    const react = html(
      <LoginLayout title="Sign in to Web App" description="One more step: confirm it is you." footer={troubleFooter('Matthew')} focusOnMount={false} />,
    );
    const server = authPage({ title: 'Sign in to Web App', description: 'One more step: confirm it is you.', footer: 'Trouble signing in? Ask Matthew.' });
    expect(react).toBe(server);
  });

  it('is the same frame around a body, in the wide column', () => {
    const react = html(
      <LoginLayout title="Set up D3 Auth" wide focusOnMount={false}>
        <form aria-label="Set up D3 Auth" />
      </LoginLayout>,
    );
    const server = authPage({ title: 'Set up D3 Auth', wide: true, body: '<form aria-label="Set up D3 Auth"></form>' });
    expect(react).toBe(server);
  });

  it('is the same frame with nothing but a heading', () => {
    expect(html(<LoginLayout title="You are signed out" />)).toBe(authPage({ title: 'You are signed out' }));
  });

  it('tells the same story', () => {
    const react = html(<LoginLayout title="t" />);
    expect(react).toContain(storyPanel());
  });

  it('draws the same mark', () => {
    expect(html(<D3AuthMark size={28} decorative />)).toBe(mark(28));
    expect(html(<D3AuthMark size={96} decorative />)).toBe(mark(96));
  });
});

describe('the entry shell', () => {
  const page = html(
    <LoginLayout title="Sign in to Web App" footer={troubleFooter('Matthew')}>
      <form aria-label="Sign in" />
    </LoginLayout>,
  );

  it('has exactly one h1, and the story under an h2 in its own landmark', () => {
    expect(page.match(/<h1[\s>]/g)).toHaveLength(1);
    expect(page).toContain('>Sign in to Web App</h1>');
    expect(page).toContain('<aside aria-label="About D3 Auth" class="auth-entry__story">');
    expect(page.match(/<h2[\s>]/g)).toHaveLength(1);
    expect(page).toContain('<main class="auth-entry__main">');
  });

  it('says what it says, with the accent on the second line of the headline', () => {
    expect(page).toContain(`${ENTRY_HEADLINE} <span class="auth-entry__headline-accent">${ENTRY_HEADLINE_ACCENT}</span>`);
    expect(page).toContain(ENTRY_PROMISE);
    expect(ENTRY_CLAIMS).toHaveLength(3);
    for (const claim of ENTRY_CLAIMS) expect(page).toContain(`<span class="auth-entry__claim-title">${claim.title}</span> ${claim.detail}`);
    expect(page).toContain('<footer class="auth-entry__foot"><span>self-hosted</span></footer>');
  });

  it('keeps the trouble line, under the form', () => {
    expect(page.indexOf('<form')).toBeLessThan(page.indexOf('Trouble signing in? Ask Matthew.'));
    expect(page).toContain('<div class="auth-entry__notes"><p>Trouble signing in? Ask Matthew.</p></div>');
  });

  it('marks the form busy while the step loads', () => {
    expect(html(<LoginLayout title="Sign in" busy />)).toContain('<main class="auth-entry__main" aria-busy="true">');
  });
});

describe('the D3 Auth mark', () => {
  it('is announced as "D3 Auth" when it stands alone', () => {
    const alone = html(<D3AuthMark size={20} />);
    expect(alone).toContain('role="img"');
    expect(alone).toContain('aria-label="D3 Auth"');
    expect(alone).not.toContain('aria-hidden');
  });

  it('is hidden from a screen reader when the name is written beside it', () => {
    const beside = html(<D3AuthMark size={20} decorative />);
    expect(beside).toContain('aria-hidden="true"');
    expect(beside).not.toContain('role="img"');
  });

  it('draws the Keyhole in the ring, ink in currentColor, at d3cloud.io weights', () => {
    const icon = html(<D3AuthMark size={20} />);
    expect(icon).toContain('viewBox="0 0 64 64"');
    expect(icon).toContain('<circle cx="32" cy="32" r="26" stroke="currentColor" stroke-width="3.5"');
    expect(icon).toContain('d="M28.5 31.5 L25 45 L39 45 L35.5 31.5"');
    expect(icon).toContain('<circle cx="32" cy="25" r="5.5" fill="currentColor" class="auth-mark__star">');
    const display = html(<D3AuthMark size={72} />);
    expect(display).toContain('stroke-width="2.2"');
    expect(display).toContain('r="4.4" fill="currentColor" class="auth-mark__star"');
  });

  it('carries no style attribute and no colour of its own: the star is lit by class', () => {
    const icon = html(<D3AuthMark size={20} />);
    expect(icon).not.toContain('style=');
    expect(icon).not.toMatch(/#[0-9a-f]{3,8}\b/i);
  });
});
