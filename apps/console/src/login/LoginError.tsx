import { Link } from '@d3cloud/ui';
import { LoginLayout } from './LoginLayout';

// I-9: the interaction error screen. It never redirects anywhere, by design.
export function LoginError({ operatorDisplayName = 'the person who runs D3 Auth' }: { operatorDisplayName?: string }) {
  return (
    <LoginLayout
      title="We could not continue this sign-in"
      description={`The link may have expired, or the app that sent you may be misconfigured. Go back to the app and start again, or ask ${operatorDisplayName}.`}
      footer={
        <Link variant="standalone" href="/signin">
          Sign in to your account
        </Link>
      }
    />
  );
}
