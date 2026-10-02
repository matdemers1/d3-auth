import { EntryHeading, EntryNotes, EntryShell } from '../entry/EntryShell';

// Every /login screen: one task, one primary, inside the entry shell (AUTH-T-8.2) — the story at
// the left from 1024px, the form at the right. No navigation: anything else on the page is something
// between a person and their account.
//
// The server renders the same frame from the same classes for the no-JavaScript path
// (apps/server/src/interaction/auth-markup.ts), mark and story included, so nothing moves when this
// mounts. test/entry-parity.test.tsx holds the two together.

interface Props {
  title: string;
  description?: React.ReactNode;
  children?: React.ReactNode;
  /** A short line under the form, past a hairline: who to ask, or the way back. */
  footer?: React.ReactNode;
  /** Off when a field on the screen takes focus itself — the email field, the code. */
  focusOnMount?: boolean;
  busy?: boolean;
  /** A long form (setup, an invite): a wider column. */
  wide?: boolean;
}

export function LoginLayout({ title, description, children, footer, focusOnMount = true, busy = false, wide = false }: Props) {
  return (
    <EntryShell wide={wide} busy={busy}>
      <EntryHeading title={title} focusOnMount={focusOnMount}>
        {description}
      </EntryHeading>
      {children === undefined ? null : <div className="auth-entry__body">{children}</div>}
      {footer === undefined ? null : <EntryNotes>{footer}</EntryNotes>}
    </EntryShell>
  );
}

export const troubleFooter = (operator: string) => <>Trouble signing in? Ask {operator}.</>;
