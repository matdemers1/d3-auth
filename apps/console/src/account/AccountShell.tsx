import { Card, EmptyState, PageHeader, Skeleton } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { api } from '../api';
import { Password } from './Password';
import { Profile } from './Profile';
import { Security } from './Security';
import { Sessions } from './Sessions';
import { SIGN_OUT_HREF } from '../signout';

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
      {/* Sign-out is on every signed-in page (ASVS 7.4.4). The provider asks before it acts, so a
          stray click costs a "No, stay signed in". */}
      <a className="account-nav-link" href={SIGN_OUT_HREF}>
        Sign out
      </a>
    </nav>
  );
}

/** A-1: the launcher (REQ-079). Access is deny-by-default, so this list is the whole answer. */
function Apps() {
  const [apps, setApps] = useState<{ clientId: string; name: string; roles: string[] }[] | undefined>();

  useEffect(() => {
    api
      .get<{ apps: { clientId: string; name: string; roles: string[] }[] }>('/api/account/apps')
      .then((answer) => {
        setApps(answer.apps);
      })
      .catch(() => {
        setApps([]);
      });
  }, []);

  return (
    <main className="shell">
      <PageHeader title="Your apps" description="Everything you can sign in to." />
      {!apps ? (
        <Skeleton height="8rem" />
      ) : apps.length === 0 ? (
        <EmptyState kind="empty" size="page" headingLevel={2} heading="No apps yet">
          When somebody gives you access to an app, it appears here.
        </EmptyState>
      ) : (
        <Card padding="lg">
          <ul className="rows">
            {apps.map((app) => (
              <li key={app.clientId} className="row">
                <div>
                  <strong>{app.name}</strong>
                  <div className="muted">{app.roles.length > 0 ? app.roles.join(', ') : 'no roles'}</div>
                </div>
              </li>
            ))}
          </ul>
          <p className="signin-footnote">Open one of these and choose &ldquo;Sign in with D3 Auth&rdquo;.</p>
        </Card>
      )}
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
