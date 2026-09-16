import { EmptyState, Link, PageHeader } from '@d3cloud/ui';
import { Security } from './Security';

// Self-service. Security is here; profile, password and sessions follow in T-2.7.
export default function AccountShell() {
  const section = window.location.pathname.replace(/^\/account\/?/, '').split('/')[0] ?? '';

  if (section === 'security') return <Security />;

  return (
    <main className="shell">
      <PageHeader title="Your account" description="How you sign in, and where you are signed in." />
      <EmptyState kind="empty" size="page" headingLevel={2} heading="Your account">
        <Link href="/account/security">How you sign in</Link> — passkeys and authenticator apps. Profile, password and
        sessions arrive next.
      </EmptyState>
    </main>
  );
}
