import { Link } from '@d3cloud/ui';
import { LoginLayout } from './LoginLayout';

// I-8: where a logout lands when the app did not register a post-logout URL.
export function LoggedOut() {
  return (
    <LoginLayout
      title="You are signed out"
      description="You can close this tab, or sign in again from the app you were using."
      footer={
        <Link variant="standalone" href="/signin">
          Sign in again
        </Link>
      }
    />
  );
}
