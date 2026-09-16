import { AppDetail } from './AppDetail';
import { Apps } from './Apps';
import { Audit } from './Audit';
import { GroupDetail } from './GroupDetail';
import { Groups } from './Groups';
import { Home } from './Home';
import { Keys } from './Keys';
import { People } from './People';
import { PersonDetail } from './PersonDetail';
import { RegisterApp } from './RegisterApp';
import { Settings } from './Settings';
import { Transfer } from './Transfer';

// The operator console: home, people, groups, apps, keys, audit, settings, export/import.
//
// Plain links again, not a router: each screen is its own page, so the back button does what a
// back button should and nothing has to remember where it came from.

const SECTIONS = [
  { path: '', label: 'Home' },
  { path: 'people', label: 'People' },
  { path: 'groups', label: 'Groups' },
  { path: 'apps', label: 'Apps' },
  { path: 'keys', label: 'Keys' },
  { path: 'audit', label: 'Audit' },
  { path: 'settings', label: 'Settings' },
  { path: 'transfer', label: 'Export & import' },
] as const;

function Nav({ current }: { current: string }) {
  return (
    <nav className="account-nav" aria-label="Console">
      {SECTIONS.map((section) => (
        <a
          key={section.path}
          className="account-nav-link"
          href={`/admin/${section.path}`}
          aria-current={section.path === current ? 'page' : undefined}
        >
          {section.label}
        </a>
      ))}
      {/* Sign-out is on every signed-in page (ASVS 7.4.4). The provider asks before it acts, so a
          stray click costs a "No, stay signed in". */}
      <a className="account-nav-link" href="/oidc/session/end">
        Sign out
      </a>
    </nav>
  );
}

export default function AdminShell() {
  const segments = window.location.pathname.replace(/^\/admin\/?/, '').split('/').filter(Boolean);
  const [section = '', id] = segments;

  return (
    <>
      <Nav current={['people', 'apps', 'groups', 'keys', 'audit', 'settings', 'transfer'].includes(section) ? section : ''} />
      {section === 'apps' ? (
        id === 'new' ? (
          <RegisterApp />
        ) : id ? (
          <AppDetail clientId={id} />
        ) : (
          <Apps />
        )
      ) : section === 'keys' ? (
        <Keys />
      ) : section === 'audit' ? (
        <Audit />
      ) : section === 'settings' ? (
        <Settings />
      ) : section === 'transfer' ? (
        <Transfer />
      ) : section === 'groups' ? (
        id ? (
          <GroupDetail id={id} />
        ) : (
          <Groups />
        )
      ) : section === 'people' ? (
        id ? (
          <PersonDetail id={id} />
        ) : (
          <People />
        )
      ) : (
        <Home />
      )}
    </>
  );
}
