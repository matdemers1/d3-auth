import { LoggedOut } from './LoggedOut';
import { LoginError } from './LoginError';
import { Setup } from './Setup';
import { SignIn } from './SignIn';

// Routing inside /login/* without a router: the path is either an interaction uid or one of the
// two static screens.
export default function LoginShell() {
  const rest = window.location.pathname.replace(/^\/login\/?/, '').split('/')[0] ?? '';

  if (rest === 'setup') return <Setup />;
  if (rest === 'logged-out') return <LoggedOut />;
  if (rest === '' || rest === 'error') return <LoginError />;
  return <SignIn uid={rest} />;
}
