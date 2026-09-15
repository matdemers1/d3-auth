import { Card, EmptyState, PageHeader } from '@d3cloud/ui';

// Phone-first sign-in surface. Phase 1 (T-1.6) replaces this placeholder with the real
// email → password → second-factor screens driven by the login state machine.
export default function LoginShell() {
  return (
    <main className="shell shell--narrow">
      <PageHeader title="Sign in" />
      <Card padding="lg">
        <EmptyState kind="empty" size="inline" headingLevel={2} heading="Sign-in screens arrive in Phase 1">
          Apps send people here to sign in once the login flow is built.
        </EmptyState>
      </Card>
    </main>
  );
}
