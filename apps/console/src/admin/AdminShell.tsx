import { AppDetail } from './AppDetail';
import { Apps } from './Apps';
import { Audit } from './Audit';
import { GroupDetail } from './GroupDetail';
import { Groups } from './Groups';
import { Keys } from './Keys';
import { People } from './People';
import { PersonDetail } from './PersonDetail';
import { RegisterApp } from './RegisterApp';

// The operator console. Audit, keys and settings arrive with the rest of Phase 4.
//
// Plain links again, not a router: each screen is its own page, so the back button does what a
// back button should and nothing has to remember where it came from.

const SECTIONS = [
  { path: 'people', label: 'People' },
  { path: 'groups', label: 'Groups' },
  { path: 'apps', label: 'Apps' },
  { path: 'keys', label: 'Keys' },
  { path: 'audit', label: 'Audit' },
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
    </nav>
  );
}

export default function AdminShell() {
  const segments = window.location.pathname.replace(/^\/admin\/?/, '').split('/').filter(Boolean);
  const [section = 'people', id] = segments;

  return (
    <>
      <Nav current={['apps', 'groups', 'keys', 'audit'].includes(section) ? section : 'people'} />
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
      ) : section === 'groups' ? (
        id ? (
          <GroupDetail id={id} />
        ) : (
          <Groups />
        )
      ) : id ? (
        <PersonDetail id={id} />
      ) : (
        <People />
      )}
    </>
  );
}
