import { AddApp } from './AddApp';
import { AppConnect } from './AppConnect';
import { AppDetail } from './AppDetail';
import { Apps } from './Apps';
import { Audit } from './Audit';
import { GroupDetail } from './GroupDetail';
import { Groups } from './Groups';
import { Home } from './Home';
import { Keys } from './Keys';
import { People } from './People';
import { PersonDetail } from './PersonDetail';
import { PresetForm } from './PresetForm';
import { RegisterApp } from './RegisterApp';
import { Settings } from './Settings';
import { Transfer } from './Transfer';
import { Frame, type AdminPlace } from '../shared/Frame';
import { useLoadMe } from '../shared/me';

// The operator console: home, people, groups, apps, keys, audit, settings, export and import.
// A detail or a new-thing page lights up the list it belongs to.

/** A malformed escape in somebody's pasted link is a page that does not exist, not a crash. */
const decodePart = (part: string): string => {
  try {
    return decodeURIComponent(part);
  } catch {
    return part;
  }
};

/** /admin/apps, /admin/apps/new, /admin/apps/new/manifest, /admin/apps/new/<preset>, /admin/apps/<id>, /admin/apps/<id>/connect */
function appsPage(id: string | undefined, sub: string | undefined): React.ReactNode {
  if (!id) return <Apps />;
  if (id === 'new') {
    if (!sub) return <AddApp />;
    return sub === 'manifest' ? <RegisterApp /> : <PresetForm presetKey={sub} />;
  }
  return sub === 'connect' ? <AppConnect clientId={id} /> : <AppDetail clientId={id} />;
}

function route(section: string, id: string | undefined, sub: string | undefined): { place: AdminPlace; page: React.ReactNode } {
  switch (section) {
    case 'people':
      return { place: 'people', page: id ? <PersonDetail id={id} /> : <People /> };
    case 'groups':
      return { place: 'groups', page: id ? <GroupDetail id={id} /> : <Groups /> };
    case 'apps':
      return { place: 'apps', page: appsPage(id, sub) };
    case 'keys':
      return { place: 'keys', page: <Keys /> };
    case 'audit':
      return { place: 'audit', page: <Audit /> };
    case 'settings':
      return { place: 'settings', page: <Settings /> };
    case 'transfer':
      return { place: 'transfer', page: <Transfer /> };
    default:
      return { place: 'home', page: <Home /> };
  }
}

export default function AdminShell() {
  const me = useLoadMe();
  const [section = '', id, sub] = window.location.pathname
    .replace(/^\/admin\/?/, '')
    .split('/')
    .filter(Boolean)
    .map(decodePart);
  const { place, page } = route(section, id, sub);

  return (
    <Frame area="admin" current={place} me={me}>
      {page}
    </Frame>
  );
}
