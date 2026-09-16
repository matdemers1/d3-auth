import { EmptyState } from '@d3cloud/ui';

// Where the invite wizard lands. Phase 2's security screen adds "protect your account" here.
export function Welcome() {
  return (
    <main className="shell shell--narrow">
      <EmptyState kind="empty" size="page" headingLevel={2} heading="Your account is ready">
        Go back to the app you were invited to and sign in. Your username and password work everywhere that uses this
        sign-in.
      </EmptyState>
    </main>
  );
}
