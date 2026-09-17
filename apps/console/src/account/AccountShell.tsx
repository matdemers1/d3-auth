import { Card, DataList, DataListRow, EmptyState, Page, PageHeader } from '@d3cloud/ui';
import { AppWindow, LayoutGrid } from 'lucide-react';
import { api } from '../api';
import { Frame, type AccountPlace } from '../shared/Frame';
import { icon } from '../shared/icons';
import { useLoad } from '../shared/load';
import { useLoadMe, useOperator } from '../shared/me';
import { LoadFailed, RowsSkeleton } from '../shared/states';
import { Password } from './Password';
import { Profile } from './Profile';
import { Security } from './Security';
import { Sessions } from './Sessions';

// The account area (A-1…A-5), in the same frame as the console, for anyone with an account.

const DESCRIPTION = 'Everything you can sign in to. Open one and choose “Sign in with D3 Auth”.';

/** A-1: the launcher (REQ-079). Access is deny-by-default, so this list is the whole answer. */
function YourApps() {
  const operator = useOperator();
  const { state, retry } = useLoad(() =>
    api.get<{ apps: { clientId: string; name: string; roles: string[] }[] }>('/api/account/apps').then((answer) => answer.apps),
  );

  if (state.status === 'loading') {
    return (
      <Page aria-busy="true">
        <PageHeader title="Your apps" description={DESCRIPTION} />
        <RowsSkeleton rows={2} leading />
      </Page>
    );
  }
  if (state.status !== 'ready') {
    return (
      <Page>
        <PageHeader title="Your apps" description={DESCRIPTION} />
        <LoadFailed what="Your apps" message={state.status === 'failed' ? state.message : 'The server refused.'} onRetry={retry} />
      </Page>
    );
  }

  const apps = state.data;
  return (
    <Page>
      <PageHeader title="Your apps" count={apps.length} description={DESCRIPTION} />
      <Card>
        <DataList
          aria-label="Your apps"
          empty={
            <EmptyState kind="empty" headingLevel={2} heading="No apps yet" icon={icon(LayoutGrid, 24)}>
              When somebody gives you access to an app, it appears here. Ask {operator} if you were expecting one.
            </EmptyState>
          }
        >
          {apps.map((app) => (
            <DataListRow
              key={app.clientId}
              leading={icon(AppWindow, 20)}
              title={app.name}
              description={app.roles.length > 0 ? `Roles: ${app.roles.join(', ')}` : 'No roles — you can sign in'}
            />
          ))}
        </DataList>
      </Card>
    </Page>
  );
}

function route(section: string): { place: AccountPlace; page: React.ReactNode } {
  switch (section) {
    case 'profile':
      return { place: 'profile', page: <Profile /> };
    case 'password':
      return { place: 'password', page: <Password /> };
    case 'security':
      return { place: 'security', page: <Security /> };
    case 'sessions':
      return { place: 'sessions', page: <Sessions /> };
    default:
      return { place: 'apps', page: <YourApps /> };
  }
}

export default function AccountShell() {
  const me = useLoadMe();
  const section = window.location.pathname.replace(/^\/account\/?/, '').split('/')[0] ?? '';
  const { place, page } = route(section);
  return (
    <Frame area="account" current={place} me={me}>
      {page}
    </Frame>
  );
}
