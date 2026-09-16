import { EmptyState, PageHeader } from '@d3cloud/ui';
import { Password } from './Password';
import { Profile } from './Profile';
import { Security } from './Security';
import { Sessions } from './Sessions';

// The account area (A-1…A-5). Plain links, not a router: each section is its own page, which
// keeps the bundle small and the back button honest.

const SECTIONS = [
  { path: '', label: 'Your apps' },
  { path: 'profile', label: 'Profile' },
  { path: 'password', label: 'Password' },
  { path: 'security', label: 'How you sign in' },
  { path: 'sessions', label: 'Sessions and devices' },
] as const;

function Nav({ current }: { current: string }) {
  return (
    <nav className="account-nav" aria-label="Your account">
      {SECTIONS.map((section) => (
        <a
          key={section.path}
          className="account-nav-link"
          href={`/account/${section.path}`}
          aria-current={section.path === current ? 'page' : undefined}
        >
          {section.label}
        </a>
      ))}
    </nav>
  );
}

/** A-1. The launcher fills in when apps and grants land in Phase 3. */
function Apps() {
  return (
    <main className="shell">
      <PageHeader title="Your apps" description="Everything you can sign in to." />
      <EmptyState kind="empty" size="page" headingLevel={2} heading="No apps yet">
        When you are given access to an app, it appears here.
      </EmptyState>
    </main>
  );
}

export default function AccountShell() {
  const section = window.location.pathname.replace(/^\/account\/?/, '').split('/')[0] ?? '';

  return (
    <>
      <Nav current={section} />
      {section === 'profile' ? (
        <Profile />
      ) : section === 'password' ? (
        <Password />
      ) : section === 'security' ? (
        <Security />
      ) : section === 'sessions' ? (
        <Sessions />
      ) : (
        <Apps />
      )}
    </>
  );
}
