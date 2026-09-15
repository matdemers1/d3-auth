import { EmptyState, PageHeader } from '@d3cloud/ui';

// Self-service: my apps, profile, security, sessions and devices (Phase 2, T-2.7).
export default function AccountShell() {
  return (
    <main className="shell">
      <PageHeader title="Your account" description="Apps you can open, how you sign in, and where you are signed in." />
      <EmptyState kind="empty" size="page" headingLevel={2} heading="Account settings arrive in Phase 2">
        This is where you will manage your passkeys, sessions and devices.
      </EmptyState>
    </main>
  );
}
