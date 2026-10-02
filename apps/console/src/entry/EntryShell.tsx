import { useEffect, useRef, type ReactNode } from 'react';
import { D3AuthMark } from '../brand/D3AuthMark';
import { ENTRY_CLAIMS, ENTRY_FOOT, ENTRY_HEADLINE, ENTRY_HEADLINE_ACCENT, ENTRY_PRODUCT, ENTRY_PROMISE } from './story';

/**
 * AUTH-T-8.2: the frame of every screen somebody sees on their way in — sign in, setup, an invite,
 * continue-as, signed out, the error page. Split, after Bindery's and Postroom's front doors: from
 * 1024px the left half says what D3 Auth is and names three claims a person can check; the right
 * half is the form. Below that the story is dropped rather than squeezed, and the mark and name sit
 * above the form instead.
 *
 * The aside is a landmark with its own label and an h2, so each screen keeps exactly one h1 — the
 * form's — and the form is the page's <main>.
 *
 * The server writes the same elements with the same classes into the HTML for the no-JavaScript
 * path (apps/server/src/interaction/auth-markup.ts), so nothing moves when this mounts over it.
 * test/entry-parity.test.tsx compares the two. The styles (entry/entry.css) load with the console's
 * first stylesheet, which the server's pages link too.
 */
export function EntryShell({
  children,
  wide = false,
  busy = false,
}: {
  children: ReactNode;
  /** Setup and the invite: about 28rem rather than 24. */
  wide?: boolean;
  /** The step is still loading. */
  busy?: boolean;
}) {
  return (
    <div className="auth-entry">
      <StoryPanel />
      <main className="auth-entry__main" {...(busy ? { 'aria-busy': true } : {})}>
        <div className={wide ? 'auth-entry__column auth-entry__column--wide' : 'auth-entry__column'}>
          <div className="auth-entry__brand auth-entry__brand--compact">
            <D3AuthMark size={28} decorative />
            {` ${ENTRY_PRODUCT}`}
          </div>
          {children}
        </div>
      </main>
    </div>
  );
}

function StoryPanel() {
  return (
    <aside aria-label={`About ${ENTRY_PRODUCT}`} className="auth-entry__story">
      <div className="auth-entry__brand">
        <D3AuthMark size={28} decorative />
        {` ${ENTRY_PRODUCT}`}
      </div>
      <div className="auth-entry__pitch">
        <h2 className="auth-entry__headline">
          {`${ENTRY_HEADLINE} `}
          <span className="auth-entry__headline-accent">{ENTRY_HEADLINE_ACCENT}</span>
        </h2>
        <p className="auth-entry__promise">{ENTRY_PROMISE}</p>
        <ul className="auth-entry__claims">
          {ENTRY_CLAIMS.map((claim) => (
            <li key={claim.title} className="auth-entry__claim">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true" focusable="false" className="auth-entry__tick">
                <path d="M3.5 8.5l3 3 6-7" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              <span>
                <span className="auth-entry__claim-title">{claim.title}</span>
                {` ${claim.detail}`}
              </span>
            </li>
          ))}
        </ul>
      </div>
      {/* No build label: /health names the schema, not the revision, and an endpoint is not added
          just to print one here. */}
      <footer className="auth-entry__foot">
        <span>{ENTRY_FOOT}</span>
      </footer>
    </aside>
  );
}

/**
 * The heading every entry screen opens with: the page's one h1 and a muted line under it.
 * `focusOnMount` moves focus to the heading, as AuthLayout did, for a screen with no field to land in.
 */
export function EntryHeading({ title, children, focusOnMount = false }: { title: string; children?: ReactNode; focusOnMount?: boolean }) {
  const ref = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (focusOnMount) ref.current?.focus();
  }, [focusOnMount]);
  return (
    <header className="auth-entry__heading">
      <h1 ref={ref} tabIndex={-1} className="auth-entry__title">
        {title}
      </h1>
      {children === undefined ? null : <p className="auth-entry__lede">{children}</p>}
    </header>
  );
}

/** Under the form, past a hairline: where to go when this screen is not the answer. */
export function EntryNotes({ children }: { children: ReactNode }) {
  return (
    <div className="auth-entry__notes">
      <p>{children}</p>
    </div>
  );
}
