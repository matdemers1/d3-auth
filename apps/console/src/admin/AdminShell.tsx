import { AppDetail } from './AppDetail';
import { Apps } from './Apps';
import { People } from './People';
import { PersonDetail } from './PersonDetail';
import { RegisterApp } from './RegisterApp';

// The operator console. Groups, audit and keys arrive in Phase 4.
//
// Plain links again, not a router: each screen is its own page, so the back button does what a
// back button should and nothing has to remember where it came from.

const SECTIONS = [
  { path: 'people', label: 'People' },
  { path: 'apps', label: 'Apps' },
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
      <Nav current={section === 'apps' ? 'apps' : 'people'} />
      {section === 'apps' ? (
        id === 'new' ? (
          <RegisterApp />
        ) : id ? (
          <AppDetail clientId={id} />
        ) : (
          <Apps />
        )
      ) : id ? (
        <PersonDetail id={id} />
      ) : (
        <People />
      )}
    </>
  );
}
