import { AuthLayout } from '@d3cloud/ui';
import { ShieldHalf } from 'lucide-react';
import { icon } from '../shared/icons';

// Every /login screen: one task, one Card, one primary (Auth page pattern). No navigation, and no
// second Card: anything else on the page is something between a person and their account.
//
// The server renders the same frame from the same classes for the no-JavaScript path
// (apps/server/src/interaction/auth-markup.ts), mark included, so nothing moves when this mounts.

interface Props {
  title: string;
  description?: React.ReactNode;
  children?: React.ReactNode;
  footer?: React.ReactNode;
  /** Off when a field on the screen takes focus itself — the email field, the code. */
  focusOnMount?: boolean;
  busy?: boolean;
}

export function LoginLayout({ title, description, children, footer, focusOnMount = true, busy = false }: Props) {
  return (
    <AuthLayout
      brand={icon(ShieldHalf, 32)}
      title={title}
      {...(description === undefined ? {} : { description })}
      {...(footer === undefined ? {} : { footer })}
      focusOnMount={focusOnMount}
      {...(busy ? { 'aria-busy': true } : {})}
    >
      {children}
    </AuthLayout>
  );
}

export const troubleFooter = (operator: string) => <>Trouble signing in? Ask {operator}.</>;
