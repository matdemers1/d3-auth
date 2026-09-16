import { Alert } from '@d3cloud/ui';

// I-9: the interaction error screen. It never redirects anywhere, by design.
export function LoginError({ operatorDisplayName = 'the operator' }: { operatorDisplayName?: string }) {
  return (
    <main className="shell shell--narrow">
      <Alert tone="danger" title="We could not continue this sign-in">
        The link may have expired, or the app that sent you may be misconfigured. Go back to the app and start again, or
        ask {operatorDisplayName}.
      </Alert>
    </main>
  );
}
