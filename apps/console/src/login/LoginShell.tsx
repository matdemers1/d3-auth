import { InviteWizard } from './InviteWizard';
import { LoggedOut } from './LoggedOut';
import { LoginError } from './LoginError';
import { Setup } from './Setup';
import { SignIn } from './SignIn';
import { Welcome } from './Welcome';

// Routing inside /login/* without a router: the path is either an interaction uid or one of the
// two static screens.
export default function LoginShell() {
  const segments = window.location.pathname.replace(/^\/login\/?/, '').split('/');
  const rest = segments[0] ?? '';

  if (rest === 'setup') return <Setup />;
  if (rest === 'welcome') return <Welcome />;
  if (rest === 'invite') return <InviteWizard token={segments[1] ?? ''} />;
  if (rest === 'logged-out') return <LoggedOut />;
  if (rest === '' || rest === 'error') return <LoginError />;
  return <SignIn uid={rest} />;
}
