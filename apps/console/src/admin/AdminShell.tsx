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
import { Frame, type AdminPlace } from '../shared/Frame';
import { useLoadMe } from '../shared/me';

// The operator console: home, people, groups, apps, keys, audit, settings, export and import.
// A detail or a new-thing page lights up the list it belongs to.

function route(section: string, id: string | undefined): { place: AdminPlace; page: React.ReactNode } {
  switch (section) {
    case 'people':
      return { place: 'people', page: id ? <PersonDetail id={id} /> : <People /> };
    case 'groups':
      return { place: 'groups', page: id ? <GroupDetail id={id} /> : <Groups /> };
    case 'apps':
      return { place: 'apps', page: id === 'new' ? <RegisterApp /> : id ? <AppDetail clientId={id} /> : <Apps /> };
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
  const [section = '', id] = window.location.pathname.replace(/^\/admin\/?/, '').split('/').filter(Boolean);
  const { place, page } = route(section, id);

  return (
    <Frame area="admin" current={place} me={me}>
      {page}
    </Frame>
  );
}
